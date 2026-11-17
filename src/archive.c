/*
 * archive.c - The only module that talks to libarchive.
 */
#include "lpm_archive.h"
#include "filelist.h"
#include "safefs.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#define READ_BLOCK (64 * 1024)

struct lpm_archive {
    struct archive *ar;
    size_t entries;
};

static lpm_status archive_fail(lpm_archive *a, lpm_meta_error *err, const char *what)
{
    const char *why = a && a->ar ? archive_error_string(a->ar) : NULL;

    lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL, "%s: %s", what,
                       why ? why : "unknown libarchive error");
    return LPM_ERR_INVALID;
}

/*
 * Enable tar plus the gzip and xz filters. libarchive answers
 * ARCHIVE_WARN when it would run an external program (e.g. `xz -d`)
 * because it was built without the library; a package manager should
 * not spawn programs to read untrusted input, so that is refused.
 */
static lpm_status archive_new(lpm_archive **out, lpm_meta_error *err)
{
    lpm_archive *a = calloc(1, sizeof(*a));

    *out = NULL;
    if (a == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    a->ar = archive_read_new();
    if (a->ar == NULL) {
        free(a);
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    if (archive_read_support_format_tar(a->ar) != ARCHIVE_OK ||
        archive_read_support_filter_none(a->ar) != ARCHIVE_OK ||
        archive_read_support_filter_gzip(a->ar) != ARCHIVE_OK ||
        archive_read_support_filter_xz(a->ar) != ARCHIVE_OK) {
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                           "libarchive lacks built-in tar/gzip/xz support (it "
                           "must be built with zlib and liblzma)");
        archive_read_free(a->ar);
        free(a);
        return LPM_ERR_INVALID;
    }
    *out = a;
    return LPM_OK;
}

lpm_status lpm_archive_open(const char *path, lpm_archive **out, lpm_meta_error *err)
{
    lpm_archive *a;
    lpm_status rc = archive_new(&a, err);

    if (rc != LPM_OK)
        return rc;
    if (archive_read_open_filename(a->ar, path, READ_BLOCK) != ARCHIVE_OK) {
        rc = archive_fail(a, err, "cannot open archive");
        if (access(path, F_OK) != 0)
            rc = errno == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
        lpm_archive_close(a);
        return rc;
    }
    *out = a;
    return LPM_OK;
}

lpm_status lpm_archive_open_fd(int fd, lpm_archive **out, lpm_meta_error *err)
{
    lpm_archive *a;
    lpm_status rc = archive_new(&a, err);

    if (rc != LPM_OK)
        return rc;
    if (archive_read_open_fd(a->ar, fd, READ_BLOCK) != ARCHIVE_OK) {
        rc = archive_fail(a, err, "cannot open archive");
        lpm_archive_close(a);
        return rc;
    }
    *out = a;
    return LPM_OK;
}

void lpm_archive_close(lpm_archive *a)
{
    if (a == NULL)
        return;
    if (a->ar != NULL)
        archive_read_free(a->ar);   /* also closes what it opened */
    free(a);
}

lpm_status lpm_archive_next(lpm_archive *a, lpm_archive_entry *e, bool *end,
                            lpm_meta_error *err)
{
    struct archive_entry *ae;
    const char *path;
    int r;

    *end = false;
    r = archive_read_next_header(a->ar, &ae);
    if (r == ARCHIVE_EOF) {
        *end = true;
        return LPM_OK;
    }
    if (r != ARCHIVE_OK)   /* WARN included: never accept a doubtful header */
        return archive_fail(a, err, "corrupt or unsupported archive");
    if (++a->entries > LPM_ARCHIVE_MAX_ENTRIES) {
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                           "archive has more than %d entries", LPM_ARCHIVE_MAX_ENTRIES);
        return LPM_ERR_INVALID;
    }

    path = archive_entry_pathname(ae);
    if (path == NULL || path[0] == '\0' ||
        strnlen(path, LPM_ARCHIVE_MAX_PATH + 1) > LPM_ARCHIVE_MAX_PATH) {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "archive entry has a missing, unreadable or too long name");
        return LPM_ERR_INVALID;
    }
    e->path = path;
    e->link = NULL;
    e->size = 0;
    e->mode = (unsigned)archive_entry_perm(ae) & 07777u;

    if (archive_entry_hardlink(ae) != NULL) {
        e->type = LPM_AENTRY_HARDLINK;
        e->link = archive_entry_hardlink(ae);
        return LPM_OK;
    }
    switch (archive_entry_filetype(ae)) {
    case AE_IFREG:
        e->type = LPM_AENTRY_FILE;
        e->size = archive_entry_size_is_set(ae) ? (int64_t)archive_entry_size(ae) : 0;
        if (e->size < 0) {
            lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                               "archive entry has a negative size");
            return LPM_ERR_INVALID;
        }
        break;
    case AE_IFDIR:
        e->type = LPM_AENTRY_DIR;
        break;
    case AE_IFLNK:
        e->type = LPM_AENTRY_SYMLINK;
        e->link = archive_entry_symlink(ae);
        if (e->link == NULL) {
            lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                               "symbolic link '%.200s' has no readable target", path);
            return LPM_ERR_INVALID;
        }
        break;
    default:
        e->type = LPM_AENTRY_SPECIAL;
        break;
    }
    return LPM_OK;
}

lpm_status lpm_archive_read(lpm_archive *a, void *buf, size_t cap, size_t *got,
                            lpm_meta_error *err)
{
    la_ssize_t n = archive_read_data(a->ar, buf, cap);

    *got = 0;
    if (n < 0)   /* truncated data, CRC/decompression error, ... */
        return archive_fail(a, err, "cannot read archive data");
    *got = (size_t)n;
    return LPM_OK;
}

/* ---- Path rules -------------------------------------------------------- */

static bool has_dotdot(const char *p)
{
    size_t i = 0;

    while (p[i] != '\0') {
        size_t clen = strcspn(p + i, "/");
        if (clen == 2 && p[i] == '.' && p[i + 1] == '.')
            return true;
        i += clen;
        while (p[i] == '/')
            i++;
    }
    return false;
}

lpm_status lpm_archive_clean_path(const char *path, bool is_dir, char *buf,
                                  size_t size, const char **out, lpm_meta_error *err)
{
    size_t len;

    *out = NULL;
    if (path[0] == '/') {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "absolute path '%.200s' in archive: entries must be "
                           "relative to the installation root", path);
        return LPM_ERR_INVALID;
    }
    if (has_dotdot(path)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "path traversal ('..') in archive entry '%.200s'", path);
        return LPM_ERR_INVALID;
    }
    if (strncmp(path, "./", 2) == 0)
        path += 2;
    len = strlen(path);
    if (is_dir && len > 0 && path[len - 1] == '/')
        len--;
    if (len + 2 > size) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_LONG, 0, "path",
                           "archive entry name is too long");
        return LPM_ERR_INVALID;
    }
    if (len == 0 && is_dir) {   /* "./" or "." : the root itself */
        buf[0] = '\0';
        *out = buf;
        return LPM_OK;
    }
    /* Reuse the owned-path rules: "/" + path must be a valid path. */
    buf[0] = '/';
    memcpy(buf + 1, path, len);
    buf[len + 1] = '\0';
    if (!lpm_is_valid_owned_path(buf)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "unsafe or malformed archive entry name '%.200s'", path);
        return LPM_ERR_INVALID;
    }
    *out = buf + 1;
    return LPM_OK;
}

/* ---- Generic safe extraction ------------------------------------------ */

#define SAFE_MODE_MASK 0755u

typedef struct {
    lpm_archive *a;
    int root_fd;
    lpm_path_log log;
    uint64_t bytes;
    lpm_meta_error *err;
} extractor;

static lpm_status extract_file(extractor *x, int dirfd, const char *rel,
                               const char *base, unsigned mode)
{
    char buf[READ_BLOCK];
    lpm_status rc;
    int fd;

    /* O_EXCL + O_NOFOLLOW: never overwrite, never follow a planted link. */
    fd = openat(dirfd, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                             O_CLOEXEC | O_NOCTTY, 0600);
    if (fd < 0) {
        int e = errno;
        lpm_meta_error_set(x->err, e == EEXIST ? LPM_META_ERR_UNSAFE_ENTRY
                                               : LPM_META_ERR_IO, 0, "path",
                           "cannot create '%.200s': %s", rel, strerror(e));
        return e == EEXIST ? LPM_ERR_CONFLICT : LPM_ERR_IO;
    }
    rc = lpm_path_log_add(&x->log, rel, false, x->err);
    if (rc != LPM_OK) {
        close(fd);
        (void)unlinkat(dirfd, base, 0);
        return rc;
    }
    for (;;) {
        size_t got;
        rc = lpm_archive_read(x->a, buf, sizeof(buf), &got, x->err);
        if (rc != LPM_OK)
            break;
        if (got == 0)
            break;
        if (got > LPM_ARCHIVE_MAX_BYTES - x->bytes) {
            lpm_meta_error_set(x->err, LPM_META_ERR_ARCHIVE, 0, NULL,
                               "archive expands to more than the 8 GiB limit");
            rc = LPM_ERR_INVALID;
            break;
        }
        x->bytes += got;
        if (lpm_write_all(fd, buf, got) != 0) {
            lpm_meta_error_set(x->err, LPM_META_ERR_IO, 0, NULL, "cannot write "
                               "'%.200s': %s", rel, strerror(errno));
            rc = LPM_ERR_IO;
            break;
        }
    }
    if (rc == LPM_OK && fchmod(fd, mode & SAFE_MODE_MASK) != 0) {
        lpm_meta_error_set(x->err, LPM_META_ERR_IO, 0, NULL, "cannot set mode of "
                           "'%.200s': %s", rel, strerror(errno));
        rc = LPM_ERR_IO;
    }
    if (close(fd) != 0 && rc == LPM_OK) {
        lpm_meta_error_set(x->err, LPM_META_ERR_IO, 0, NULL, "cannot write "
                           "'%.200s': %s", rel, strerror(errno));
        rc = LPM_ERR_IO;
    }
    return rc;
}

static lpm_status extract_entry(extractor *x, const lpm_archive_entry *e)
{
    char clean[LPM_FILES_MAX_PATH + 2], parent[LPM_FILES_MAX_PATH + 1];
    const char *rel, *base;
    lpm_status rc;
    int dirfd;

    if (e->type == LPM_AENTRY_HARDLINK) {
        lpm_meta_error_set(x->err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "hard link '%.200s' rejected: hard links are not "
                           "supported", e->path);
        return LPM_ERR_INVALID;
    }
    if (e->type == LPM_AENTRY_SPECIAL) {
        lpm_meta_error_set(x->err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "'%.200s' rejected: devices, FIFOs and sockets are not "
                           "allowed in packages", e->path);
        return LPM_ERR_INVALID;
    }
    rc = lpm_archive_clean_path(e->path, e->type == LPM_AENTRY_DIR, clean,
                                sizeof(clean), &rel, x->err);
    if (rc != LPM_OK)
        return rc;
    if (rel[0] == '\0')
        return LPM_OK;   /* the root entry "./" */

    if (e->type == LPM_AENTRY_DIR) {
        rc = lpm_safe_open_dir(x->root_fd, rel, true, 0755, &x->log, &dirfd, x->err);
        if (rc == LPM_OK)
            close(dirfd);
        return rc;
    }

    if (e->type == LPM_AENTRY_SYMLINK && !lpm_is_safe_symlink_target(e->link)) {
        lpm_meta_error_set(x->err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "symbolic link '%.100s' -> '%.100s' rejected: targets "
                           "must be relative and must not contain '..'",
                           rel, e->link);
        return LPM_ERR_INVALID;
    }

    rc = lpm_safe_split(rel, parent, sizeof(parent), &base, x->err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_safe_open_dir(x->root_fd, parent, true, 0755, &x->log, &dirfd, x->err);
    if (rc != LPM_OK)
        return rc;

    if (e->type == LPM_AENTRY_SYMLINK) {
        if (symlinkat(e->link, dirfd, base) != 0) {
            int en = errno;
            lpm_meta_error_set(x->err, LPM_META_ERR_IO, 0, "path",
                               "cannot create symbolic link '%.200s': %s",
                               rel, strerror(en));
            rc = en == EEXIST ? LPM_ERR_CONFLICT : LPM_ERR_IO;
        } else {
            rc = lpm_path_log_add(&x->log, rel, false, x->err);
            if (rc != LPM_OK)
                (void)unlinkat(dirfd, base, 0);
        }
    } else {
        rc = extract_file(x, dirfd, rel, base, e->mode);
    }
    close(dirfd);
    return rc;
}

lpm_status lpm_archive_extract(const char *archive_path, const char *dest_dir,
                               lpm_meta_error *err)
{
    extractor x;
    lpm_status rc;

    x.a = NULL;
    x.bytes = 0;
    x.err = err;
    lpm_path_log_init(&x.log);

    /* The destination itself is the caller's choice (like --root). */
    x.root_fd = open(dest_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (x.root_fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot open destination '%.200s': %s", dest_dir,
                           strerror(errno));
        return errno == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
    }
    rc = lpm_archive_open(archive_path, &x.a, err);
    while (rc == LPM_OK) {
        lpm_archive_entry e;
        bool end;

        rc = lpm_archive_next(x.a, &e, &end, err);
        if (rc != LPM_OK || end)
            break;
        rc = extract_entry(&x, &e);
    }
    if (rc != LPM_OK)
        lpm_safe_rollback(x.root_fd, &x.log);   /* leave dest as it was */
    lpm_path_log_free(&x.log);
    lpm_archive_close(x.a);
    close(x.root_fd);
    return rc;
}
