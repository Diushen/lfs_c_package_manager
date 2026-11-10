/*
 * database.c - The installed-package database: listing (Milestone 1-2),
 * and locked, atomic registration, removal and checking (Milestone 3).
 *
 * The database is plain files so it can be inspected with ls/cat during
 * a demonstration, and needs no database library or server.
 */
#include "database.h"
#include "util.h"
#include "version.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

char *lpm_db_installed_dir(const lpm_config *cfg)
{
    char *db_dir = lpm_path_join(cfg->root, LPM_DB_SUBDIR);
    char *installed;

    if (db_dir == NULL)
        return NULL;
    installed = lpm_path_join(db_dir, LPM_DB_INSTALLED_DIR);
    free(db_dir);
    return installed;
}

lpm_status lpm_db_load_package(const lpm_config *cfg, const char *name,
                               lpm_package *out, lpm_meta_error *err)
{
    /* name is validated first, so this buffer always fits. */
    char fname[LPM_MAX_NAME_LEN + sizeof(LPM_META_SUFFIX)];
    char *installed_dir, *path;
    lpm_status rc;

    lpm_package_init(out);

    /* Defence in depth: a name like "../x" must never become a path. */
    if (!lpm_is_valid_package_name(name)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "invalid package name");
        return LPM_ERR_INVALID;
    }
    snprintf(fname, sizeof(fname), "%s%s", name, LPM_META_SUFFIX);

    installed_dir = lpm_db_installed_dir(cfg);
    if (installed_dir == NULL)
        return LPM_ERR_NOMEM;
    path = lpm_path_join(installed_dir, fname);
    free(installed_dir);
    if (path == NULL)
        return LPM_ERR_NOMEM;

    rc = lpm_metadata_parse_file(path, LPM_META_INSTALLED, out, err);
    free(path);
    if (rc != LPM_OK)
        return rc;

    /* hello.meta must describe "hello", or lookups by name would lie. */
    if (strcmp(out->name, name) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "record declares name '%s', which does not match "
                           "its database filename '%s'", out->name, fname);
        lpm_package_free(out);
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

/* Append an entry, doubling capacity as needed. Takes ownership of
 * name/version only on success. */
static lpm_status list_append(lpm_db_list *list, char *name, char *version)
{
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 8;
        lpm_db_entry *grown;

        if (new_cap > SIZE_MAX / sizeof(*grown))
            return LPM_ERR_NOMEM;
        grown = realloc(list->items, new_cap * sizeof(*grown));
        if (grown == NULL)
            return LPM_ERR_NOMEM;
        list->items = grown;
        list->capacity = new_cap;
    }
    list->items[list->count].name = name;
    list->items[list->count].version = version;
    list->count++;
    return LPM_OK;
}

static int compare_entries(const void *a, const void *b)
{
    const lpm_db_entry *ea = a;
    const lpm_db_entry *eb = b;
    return strcmp(ea->name, eb->name);
}

/*
 * Handle one directory entry: accept "<valid-name>.meta" regular files,
 * ignore anything else. Returns LPM_OK for both accepted and skipped
 * entries; only allocation failure is an error.
 *
 * Compatibility policy for damaged records (e.g. Milestone 1 data with
 * no version= line): the record is parsed strictly; if that fails, the
 * package is still listed, because its files may be installed, but with
 * version "?" plus a warning saying exactly what is wrong. No version
 * is ever invented, and the strict parser is not weakened.
 */
static lpm_status consider_entry(const lpm_config *cfg, const char *installed_dir,
                                 const char *fname, lpm_db_list *out)
{
    size_t name_len;
    char *name = NULL, *path = NULL, *version = NULL;
    struct stat st;
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc = LPM_OK;

    if (fname[0] == '.' || !lpm_has_suffix(fname, LPM_META_SUFFIX))
        return LPM_OK;   /* hidden files, temp files, *.list, ... */

    name_len = strlen(fname) - strlen(LPM_META_SUFFIX);
    name = malloc(name_len + 1);
    if (name == NULL)
        return LPM_ERR_NOMEM;
    memcpy(name, fname, name_len);
    name[name_len] = '\0';

    if (!lpm_is_valid_package_name(name)) {
        lpm_warn("ignoring database entry with invalid package name: %s", fname);
        goto out;
    }

    path = lpm_path_join(installed_dir, fname);
    if (path == NULL) {
        rc = LPM_ERR_NOMEM;
        goto out;
    }

    /* lstat: a symlink in the database is suspicious, not followed. */
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        lpm_warn("ignoring database entry that is not a regular file: %s", path);
        goto out;
    }

    rc = lpm_db_load_package(cfg, name, &pkg, &err);
    if (rc == LPM_OK) {
        version = pkg.version;   /* take ownership of the version string */
        pkg.version = NULL;
        lpm_package_free(&pkg);
    } else if (rc == LPM_ERR_NOMEM) {
        goto out;
    } else if (rc == LPM_ERR_NOT_FOUND) {
        rc = LPM_OK;             /* removed since readdir(): not installed */
        goto out;
    } else {
        char msg[512];
        lpm_meta_error_format(&err, path, msg, sizeof(msg));
        lpm_warn("damaged database record %s (listed with version '?')", msg);
        version = lpm_strdup("?");
        if (version == NULL) {
            rc = LPM_ERR_NOMEM;
            goto out;
        }
        rc = LPM_OK;
    }

    rc = list_append(out, name, version);
    if (rc == LPM_OK) {
        name = NULL;      /* ownership moved into the list */
        version = NULL;
    }

out:
    free(name);
    free(version);
    free(path);
    return rc;
}

lpm_status lpm_db_list_installed(const lpm_config *cfg, lpm_db_list *out,
                                 int *db_exists)
{
    char *installed_dir;
    DIR *dir;
    struct dirent *de;
    lpm_status rc = LPM_OK;

    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    *db_exists = 0;

    installed_dir = lpm_db_installed_dir(cfg);
    if (installed_dir == NULL)
        return LPM_ERR_NOMEM;

    dir = opendir(installed_dir);
    if (dir == NULL) {
        if (errno == ENOENT) {
            free(installed_dir);   /* no database yet: empty, not an error */
            return LPM_OK;
        }
        lpm_error("cannot open package database '%s': %s",
                  installed_dir, strerror(errno));
        free(installed_dir);
        return LPM_ERR_IO;
    }
    *db_exists = 1;

    errno = 0;
    while ((de = readdir(dir)) != NULL) {
        rc = consider_entry(cfg, installed_dir, de->d_name, out);
        if (rc != LPM_OK)
            break;
        errno = 0;
    }
    if (rc == LPM_OK && errno != 0) {
        lpm_error("error reading package database '%s': %s",
                  installed_dir, strerror(errno));
        rc = LPM_ERR_IO;
    }

    closedir(dir);
    free(installed_dir);

    if (rc != LPM_OK) {
        lpm_db_list_free(out);
        return rc;
    }

    /* readdir order is arbitrary; sort for stable, readable output. */
    if (out->count > 1)
        qsort(out->items, out->count, sizeof(out->items[0]), compare_entries);
    return LPM_OK;
}

void lpm_db_list_free(lpm_db_list *list)
{
    size_t i;

    if (list == NULL)
        return;
    for (i = 0; i < list->count; i++) {
        free(list->items[i].name);
        free(list->items[i].version);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* ==================================================================== */
/* Milestone 3: locked, atomic database operations                       */
/* ==================================================================== */
/*
 * Safety rules followed by everything below:
 *
 *  - No path to a database file is ever built as a string. The root is
 *    opened once, then each directory is opened relative to its parent
 *    with O_NOFOLLOW | O_DIRECTORY, and files are reached with *at()
 *    calls on those descriptors. A symlink anywhere in var/lib/lpm/...
 *    makes the open fail instead of redirecting it.
 *  - Database directories (and the lock file) must belong to us or
 *    root and must not be writable by group/others: anyone who can
 *    write there could swap records under a root-run LPM.
 *  - Writers hold an exclusive flock() for the whole logical operation.
 *  - A file is replaced by writing a temporary file in the same
 *    directory, fsync()ing it, rename()ing it over the final name and
 *    fsync()ing the directory. rename() within one directory is atomic,
 *    so readers see either the old file or the complete new one.
 */

#define LOCK_POLL_MS 50u

static void db_reset(lpm_db *db)
{
    db->root_fd = db->lpm_fd = db->installed_fd = db->files_fd = db->lock_fd = -1;
    db->mode = LPM_DB_READ;
}

static void err_clear(lpm_meta_error *err)
{
    if (err == NULL)
        return;
    err->code = LPM_META_ERR_NONE;
    err->line = 0;
    err->field[0] = '\0';
    err->message[0] = '\0';
}

static lpm_status nomem_err(lpm_meta_error *err)
{
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    return LPM_ERR_NOMEM;
}

void lpm_db_close(lpm_db *db)
{
    if (db == NULL)
        return;
    /* Closing the lock descriptor releases the flock(). */
    if (db->lock_fd >= 0)     close(db->lock_fd);
    if (db->files_fd >= 0)    close(db->files_fd);
    if (db->installed_fd >= 0) close(db->installed_fd);
    if (db->lpm_fd >= 0)      close(db->lpm_fd);
    if (db->root_fd >= 0)     close(db->root_fd);
    db_reset(db);
}

static const char *describe_type(mode_t m)
{
    if (S_ISLNK(m)) return "a symbolic link";
    if (S_ISDIR(m)) return "a directory";
    if (S_ISREG(m)) return "a regular file";
    return "a special file";
}

/* Ownership and permission rules for database directories/lock file. */
static lpm_status check_trusted(const struct stat *st, const char *what,
                                bool want_dir, lpm_meta_error *err)
{
    if (want_dir ? !S_ISDIR(st->st_mode) : !S_ISREG(st->st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "'%s' is %s, expected %s", what,
                           describe_type(st->st_mode),
                           want_dir ? "a directory" : "a regular file");
        return LPM_ERR_INVALID;
    }
    if (st->st_uid != geteuid() && st->st_uid != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "'%s' is owned by uid %ju, not by the current user "
                           "or root", what, (uintmax_t)st->st_uid);
        return LPM_ERR_INVALID;
    }
    if (st->st_mode & (S_IWGRP | S_IWOTH)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "'%s' is writable by group or others (fix with "
                           "'chmod go-w')", what);
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static int fsync_retry(int fd)
{
    /* Retry only EINTR. After a real fsync error the page cache state is
     * unknown, so retrying could falsely report success. */
    while (fsync(fd) != 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

/* fsync a directory; filesystems that cannot do this are not errors. */
static int fsync_dir(int dirfd)
{
    if (fsync_retry(dirfd) == 0)
        return 0;
    if (errno == EINVAL || errno == ENOTSUP)
        return 0;
    return -1;
}

/*
 * Open one directory component relative to parent, never following a
 * symlink, optionally creating it (mode 0755, before umask).
 */
static lpm_status open_dir_at(int parent, const char *name, const char *what,
                              bool create, int *out, lpm_meta_error *err)
{
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    struct stat st;
    int fd, e;
    lpm_status rc;

    *out = -1;
    fd = openat(parent, name, flags);
    if (fd < 0 && errno == ENOENT && create) {
        if (mkdirat(parent, name, 0755) != 0 && errno != EEXIST) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot create '%s': %s", what, strerror(errno));
            return LPM_ERR_IO;
        }
        if (fsync_dir(parent) != 0) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot flush parent of '%s': %s", what,
                               strerror(errno));
            return LPM_ERR_IO;
        }
        fd = openat(parent, name, flags);
    }
    if (fd < 0) {
        e = errno;
        if (e == ENOENT) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "'%s' does not exist", what);
            return LPM_ERR_NOT_FOUND;
        }
        if (e == ELOOP || e == ENOTDIR) {
            lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                               "'%s' is a symbolic link or not a directory; "
                               "refusing to use it", what);
            return LPM_ERR_INVALID;
        }
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open '%s': %s",
                           what, strerror(e));
        return LPM_ERR_IO;
    }
    if (fstat(fd, &st) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot stat '%s': %s",
                           what, strerror(errno));
        close(fd);
        return LPM_ERR_IO;
    }
    rc = check_trusted(&st, what, true, err);
    if (rc != LPM_OK) {
        close(fd);
        return rc;
    }
    *out = fd;
    return LPM_OK;
}

static void sleep_ms(unsigned ms)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    /* An interrupted sleep simply ends early; the caller loops anyway. */
    (void)nanosleep(&ts, NULL);
}

/*
 * flock() rather than a "create lock file if absent" scheme: the kernel
 * drops the lock when the holder exits or crashes, so a stale lock can
 * never block the database forever, and there is no check-then-create
 * race. LOCK_NB plus polling gives a bounded wait instead of a hang.
 */
static lpm_status acquire_lock(lpm_db *db, bool exclusive, unsigned wait_ms,
                               lpm_meta_error *err)
{
    const char *what = LPM_DB_SUBDIR "/" LPM_DB_LOCK_FILE;
    int flags = (exclusive ? O_RDWR | O_CREAT : O_RDONLY) |
                O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
    int op = (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB;
    unsigned waited = 0;
    struct stat st;
    lpm_status rc;
    int fd;

    fd = openat(db->lpm_fd, LPM_DB_LOCK_FILE, flags, 0644);
    if (fd < 0) {
        int e = errno;
        /* A reader of a database that no writer has ever touched (e.g.
         * Milestone 1 data) has nobody to exclude. */
        if (!exclusive && e == ENOENT)
            return LPM_OK;
        if (e == ELOOP) {
            lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                               "'%s' is a symbolic link; refusing to use it", what);
            return LPM_ERR_INVALID;
        }
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open '%s': %s",
                           what, strerror(e));
        return LPM_ERR_IO;
    }
    if (fstat(fd, &st) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot stat '%s': %s",
                           what, strerror(errno));
        close(fd);
        return LPM_ERR_IO;
    }
    rc = check_trusted(&st, what, false, err);
    if (rc != LPM_OK) {
        close(fd);
        return rc;
    }

    for (;;) {
        if (flock(fd, op) == 0)
            break;
        if (errno == EINTR)
            continue;
        if (errno != EWOULDBLOCK) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot lock '%s': %s",
                               what, strerror(errno));
            close(fd);
            return LPM_ERR_IO;
        }
        if (waited >= wait_ms) {
            lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL,
                               "the package database is locked by another LPM "
                               "process; try again when it has finished");
            close(fd);
            return LPM_ERR_BUSY;
        }
        sleep_ms(LOCK_POLL_MS);
        waited += LOCK_POLL_MS;
    }
    db->lock_fd = fd;
    return LPM_OK;
}

lpm_status lpm_db_open(const lpm_config *cfg, lpm_db_mode mode,
                       unsigned wait_ms, lpm_db *db, lpm_meta_error *err)
{
    static const char *const parents[] = { "var", "lib", "lpm" };
    static const char *const shown[] = { "var", "var/lib", LPM_DB_SUBDIR };
    bool create = mode == LPM_DB_CREATE;
    bool writer = mode != LPM_DB_READ;
    lpm_status rc;
    int fd;
    size_t i;

    db_reset(db);
    err_clear(err);
    if (cfg == NULL || cfg->root == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL, "no root directory");
        return LPM_ERR_USAGE;
    }
    db->mode = mode;

    /* The root itself is the user's choice (--root is a redirection, not
     * a sandbox), so it may be reached through symlinks. Below it, every
     * component is checked. */
    db->root_fd = openat(AT_FDCWD, cfg->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (db->root_fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot open root directory '%s': %s",
                           cfg->root, strerror(errno));
        return LPM_ERR_IO;
    }

    fd = db->root_fd;
    for (i = 0; i < 3; i++) {
        int next;

        rc = open_dir_at(fd, parents[i], shown[i], create, &next, err);
        if (fd != db->root_fd)
            close(fd);
        if (rc != LPM_OK) {
            if (rc == LPM_ERR_NOT_FOUND)
                lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                                   "no package database under '%s' (it has "
                                   "not been initialised)", cfg->root);
            goto fail;
        }
        fd = next;
    }
    db->lpm_fd = fd;

    /* Lock before looking at or creating anything inside var/lib/lpm. */
    rc = acquire_lock(db, writer, wait_ms, err);
    if (rc != LPM_OK)
        goto fail;

    rc = open_dir_at(db->lpm_fd, LPM_DB_INSTALLED_DIR,
                     LPM_DB_SUBDIR "/" LPM_DB_INSTALLED_DIR, writer,
                     &db->installed_fd, err);
    if (rc != LPM_OK) {
        if (rc == LPM_ERR_NOT_FOUND)
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "no package database under '%s' (it has not "
                               "been initialised)", cfg->root);
        goto fail;
    }
    rc = open_dir_at(db->lpm_fd, LPM_DB_FILES_DIR,
                     LPM_DB_SUBDIR "/" LPM_DB_FILES_DIR, writer,
                     &db->files_fd, err);
    if (rc == LPM_ERR_NOT_FOUND && !writer) {
        rc = LPM_OK;   /* pre-Milestone-3 database: no file lists yet */
        err_clear(err);
    }
    if (rc != LPM_OK)
        goto fail;
    return LPM_OK;

fail:
    lpm_db_close(db);
    return rc;
}

/* "<name><suffix>" for an already validated name. */
static void record_name(char *buf, size_t size, const char *name, const char *suffix)
{
    snprintf(buf, size, "%s%s", name, suffix);
}

#define RECORD_NAME_MAX (LPM_MAX_NAME_LEN + 8)

static lpm_status require_valid_name(const char *name, lpm_meta_error *err)
{
    if (!lpm_is_valid_package_name(name)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "invalid package name");
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static lpm_status require_writer(const lpm_db *db, lpm_meta_error *err)
{
    if (db == NULL || db->lock_fd < 0 || db->mode == LPM_DB_READ ||
        db->files_fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL,
                           "database is not open for writing");
        return LPM_ERR_USAGE;
    }
    return LPM_OK;
}

/*
 * lstat-like lookup of one entry. Sets *present; if present, *st is
 * filled. Only ENOENT counts as absent; other errors are reported.
 */
static lpm_status lookup_entry(int dirfd, const char *fname, const char *dir,
                               bool *present, struct stat *st,
                               lpm_meta_error *err)
{
    *present = false;
    if (fstatat(dirfd, fname, st, AT_SYMLINK_NOFOLLOW) == 0) {
        *present = true;
        return LPM_OK;
    }
    if (errno == ENOENT)
        return LPM_OK;
    lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot stat %s/%s: %s",
                       dir, fname, strerror(errno));
    return LPM_ERR_IO;
}

lpm_status lpm_db_package_exists(lpm_db *db, const char *name, bool *exists,
                                 lpm_meta_error *err)
{
    char meta[RECORD_NAME_MAX];
    struct stat st;
    bool present;
    lpm_status rc;

    err_clear(err);
    if (db == NULL || db->installed_fd < 0 || exists == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL, "database is not open");
        return LPM_ERR_USAGE;
    }
    rc = require_valid_name(name, err);
    if (rc != LPM_OK)
        return rc;
    record_name(meta, sizeof(meta), name, LPM_META_SUFFIX);
    rc = lookup_entry(db->installed_fd, meta, LPM_DB_INSTALLED_DIR, &present, &st, err);
    if (rc != LPM_OK)
        return rc;
    if (present && !S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL,
                           "installed/%s is %s, not a record", meta,
                           describe_type(st.st_mode));
        return LPM_ERR_INVALID;
    }
    *exists = present;
    return LPM_OK;
}

/* write() everything, coping with short writes and EINTR. */
static int write_all(int fd, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {          /* no progress: do not spin forever */
            errno = EIO;
            return -1;
        }
        data += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Atomically replace dir/<final> with data:
 *   temp file (O_CREAT|O_EXCL|O_NOFOLLOW, 0600) -> write -> fchmod 0644
 *   -> fsync -> close -> renameat -> fsync(dir)
 * Before the rename, any failure removes the temp file and leaves the
 * old <final> untouched. *renamed reports whether the rename happened,
 * because a failure after it (the directory fsync) leaves the new file
 * in place and the caller must know that.
 */
static lpm_status atomic_write(int dirfd, const char *dir, const char *final,
                               const char *data, size_t len, bool *renamed,
                               lpm_meta_error *err)
{
    static unsigned long counter;
    char tmp[RECORD_NAME_MAX + 64];
    const char *step;
    int fd = -1, attempt;

    *renamed = false;
    for (attempt = 0; attempt < 100; attempt++) {
        snprintf(tmp, sizeof(tmp), "%s%s.%ld.%lu", LPM_DB_TEMP_PREFIX, final,
                 (long)getpid(), counter++);
        fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                O_CLOEXEC | O_NOCTTY, 0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
    if (fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot create a temporary file in %s: %s", dir,
                           strerror(errno));
        return LPM_ERR_IO;
    }

    step = "write";
    if (write_all(fd, data, len) != 0)
        goto fail;
    step = "set permissions on";
    if (fchmod(fd, 0644) != 0)     /* readable by `lpm list` for any user */
        goto fail;
    step = "flush";
    if (fsync_retry(fd) != 0)
        goto fail;
    step = "close";
    if (close(fd) != 0) {
        fd = -1;
        goto fail;
    }
    fd = -1;
    step = "rename";
    if (renameat(dirfd, tmp, dirfd, final) != 0)
        goto fail;
    *renamed = true;
    if (fsync_dir(dirfd) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "%s/%s was written but the directory could not be "
                           "flushed (not flushed): %s", dir, final, strerror(errno));
        return LPM_ERR_IO;
    }
    return LPM_OK;

fail:
    lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot %s %s/%s: %s",
                       step, dir, final, strerror(errno));
    if (fd >= 0)
        close(fd);
    (void)unlinkat(dirfd, tmp, 0);
    return LPM_ERR_IO;
}

/* ---- Directory scanning --------------------------------------------- */

typedef lpm_status (*entry_fn)(void *ctx, const char *fname);

/* Call fn for every entry of dirfd except "." and "..". */
static lpm_status for_each_entry(int dirfd, const char *dir, entry_fn fn,
                                 void *ctx, lpm_meta_error *err)
{
    struct dirent *de;
    lpm_status rc = LPM_OK;
    DIR *d;
    int fd;

    /* fdopendir() takes over its descriptor, so give it a duplicate. */
    fd = fcntl(dirfd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0 || (d = fdopendir(fd)) == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot read %s: %s",
                           dir, strerror(errno));
        if (fd >= 0)
            close(fd);
        return LPM_ERR_IO;
    }
    rewinddir(d);   /* duplicates share the offset of an earlier scan */
    for (;;) {
        errno = 0;
        de = readdir(d);
        if (de == NULL) {
            if (errno != 0) {
                lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                                   "error reading %s: %s", dir, strerror(errno));
                rc = LPM_ERR_IO;
            }
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        rc = fn(ctx, de->d_name);
        if (rc != LPM_OK)
            break;
    }
    closedir(d);
    return rc;
}

/*
 * If fname is "<valid-name><suffix>", copy the name into out and return
 * true. out must hold LPM_MAX_NAME_LEN + 1 bytes.
 */
static bool split_record_name(const char *fname, const char *suffix, char *out)
{
    size_t len = strlen(fname), slen = strlen(suffix);

    if (len <= slen || len - slen > LPM_MAX_NAME_LEN ||
        strcmp(fname + len - slen, suffix) != 0)
        return false;
    memcpy(out, fname, len - slen);
    out[len - slen] = '\0';
    return lpm_is_valid_package_name(out);
}

lpm_status lpm_db_read_file_list(lpm_db *db, const char *name,
                                 lpm_file_list *out, lpm_meta_error *err)
{
    char fname[RECORD_NAME_MAX];
    char *data;
    size_t len;
    lpm_status rc;

    lpm_file_list_init(out);
    err_clear(err);
    rc = require_valid_name(name, err);
    if (rc != LPM_OK)
        return rc;
    if (db == NULL || db->files_fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "no file lists directory");
        return LPM_ERR_NOT_FOUND;
    }
    record_name(fname, sizeof(fname), name, LPM_LIST_SUFFIX);
    rc = lpm_read_bounded_fileat(db->files_fd, fname, LPM_FILES_MAX_SIZE,
                                 &data, &len, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_file_list_parse_buffer(data, len, out, err);
    free(data);
    return rc;
}

/* ---- Registration ----------------------------------------------------- */

/* The file lists of every registered package (one with a .meta). */
typedef struct {
    char name[LPM_MAX_NAME_LEN + 1];
    lpm_file_list files;
} owner_list;

typedef struct {
    lpm_db *db;
    owner_list *v;
    size_t n, cap;
    lpm_meta_error *err;
} owner_set;

static void owner_set_free(owner_set *s)
{
    size_t i;

    for (i = 0; i < s->n; i++)
        lpm_file_list_free(&s->v[i].files);
    free(s->v);
    s->v = NULL;
    s->n = s->cap = 0;
}

static lpm_status owner_set_add(owner_set *s, const char *name, lpm_file_list *files)
{
    if (s->n == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 16;
        owner_list *grown;

        if (new_cap > SIZE_MAX / sizeof(*grown))
            return LPM_ERR_NOMEM;
        grown = realloc(s->v, new_cap * sizeof(*grown));
        if (grown == NULL)
            return LPM_ERR_NOMEM;
        s->v = grown;
        s->cap = new_cap;
    }
    snprintf(s->v[s->n].name, sizeof(s->v[s->n].name), "%s", name);
    s->v[s->n].files = *files;   /* ownership moves into the set */
    lpm_file_list_init(files);
    s->n++;
    return LPM_OK;
}

static lpm_status collect_one_owner(void *ctx, const char *fname)
{
    owner_set *s = ctx;
    char name[LPM_MAX_NAME_LEN + 1];
    lpm_file_list files;
    lpm_meta_error lerr;
    struct stat st;
    lpm_status rc;

    if (!split_record_name(fname, LPM_META_SUFFIX, name))
        return LPM_OK;
    if (fstatat(s->db->installed_fd, fname, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode))
        return LPM_OK;   /* not a record; lpm check reports it */

    rc = lpm_db_read_file_list(s->db, name, &files, &lerr);
    if (rc == LPM_ERR_NOT_FOUND)
        return LPM_OK;   /* pre-Milestone-3 record: owns nothing known */
    if (rc != LPM_OK) {
        if (rc == LPM_ERR_NOMEM)
            return nomem_err(s->err);
        /* Fail closed: without every list, conflicts cannot be ruled out. */
        lpm_meta_error_set(s->err, rc == LPM_ERR_IO ? LPM_META_ERR_IO
                                                    : LPM_META_ERR_STATE, 0, NULL,
                           "cannot verify file ownership: files/%s%s %s "
                           "(%.160s); run 'lpm check'", name, LPM_LIST_SUFFIX,
                           rc == LPM_ERR_IO ? "cannot be read" : "is damaged",
                           lerr.message);
        return rc == LPM_ERR_IO ? LPM_ERR_IO : LPM_ERR_INVALID;
    }
    rc = owner_set_add(s, name, &files);
    if (rc != LPM_OK) {
        lpm_file_list_free(&files);
        lpm_meta_error_set(s->err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    }
    return rc;
}

typedef struct {
    const owner_set *set;
    size_t new_owner;
    lpm_meta_error *err;
    bool hit;
} register_conflict;

static bool on_register_conflict(void *ctx, const lpm_owned_path *a,
                                 const lpm_owned_path *b, bool same_path)
{
    register_conflict *c = ctx;

    if (a->owner != c->new_owner && b->owner != c->new_owner)
        return true;   /* old problem between other packages: not ours */
    c->hit = true;
    if (same_path) {
        const lpm_owned_path *other = a->owner == c->new_owner ? b : a;
        lpm_meta_error_set(c->err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                           "'%.200s' is already owned by package '%s'",
                           a->path, c->set->v[other->owner].name);
    } else if (a->owner == c->new_owner) {
        lpm_meta_error_set(c->err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                           "'%.100s' would be a file, but package '%s' owns "
                           "'%.100s' inside it", a->path,
                           c->set->v[b->owner].name, b->path);
    } else {
        lpm_meta_error_set(c->err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                           "'%.100s' is a file owned by package '%s', so "
                           "'%.100s' cannot be inside it", a->path,
                           c->set->v[a->owner].name, b->path);
    }
    return false;
}

/* Reject the registration if any new path collides with an owned one. */
static lpm_status check_ownership(lpm_db *db, const lpm_file_list *files,
                                  lpm_meta_error *err)
{
    owner_set set = { NULL, NULL, 0, 0, NULL };
    register_conflict ctx;
    lpm_owned_path *v = NULL;
    size_t i, j, total, k = 0;
    lpm_status rc;

    if (files == NULL || files->count == 0)
        return LPM_OK;
    set.db = db;
    set.err = err;
    rc = for_each_entry(db->installed_fd, LPM_DB_INSTALLED_DIR,
                        collect_one_owner, &set, err);
    if (rc != LPM_OK)
        goto out;

    total = files->count;
    for (i = 0; i < set.n; i++) {
        if (set.v[i].files.count > SIZE_MAX / sizeof(*v) - total) {
            rc = LPM_ERR_NOMEM;
            goto out;
        }
        total += set.v[i].files.count;
    }
    v = malloc(total * sizeof(*v));
    if (v == NULL) {
        rc = LPM_ERR_NOMEM;
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        goto out;
    }
    for (i = 0; i < set.n; i++)
        for (j = 0; j < set.v[i].files.count; j++) {
            v[k].path = set.v[i].files.paths[j];
            v[k++].owner = i;
        }
    for (j = 0; j < files->count; j++) {
        v[k].path = files->paths[j];
        v[k++].owner = set.n;   /* the package being registered */
    }

    lpm_owned_paths_sort(v, total);
    ctx.set = &set;
    ctx.new_owner = set.n;
    ctx.err = err;
    ctx.hit = false;
    lpm_owned_paths_conflicts(v, total, on_register_conflict, &ctx);
    rc = ctx.hit ? LPM_ERR_CONFLICT : LPM_OK;

out:
    free(v);
    owner_set_free(&set);
    return rc;
}

lpm_status lpm_db_register_package(lpm_db *db, const lpm_package *pkg,
                                   const lpm_file_list *files,
                                   lpm_meta_error *err)
{
    static const lpm_file_list empty = { NULL, 0, 0 };
    char meta[RECORD_NAME_MAX], list[RECORD_NAME_MAX];
    char *meta_buf = NULL, *list_buf = NULL;
    size_t meta_len, list_len;
    struct stat st;
    bool present, renamed;
    lpm_status rc;

    err_clear(err);
    rc = require_writer(db, err);
    if (rc != LPM_OK)
        return rc;
    if (pkg == NULL || !lpm_is_valid_package_name(pkg->name)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "missing or invalid package name");
        return LPM_ERR_INVALID;
    }
    if (files == NULL)
        files = &empty;

    /* 1. Validate and serialise everything before touching the disk. */
    rc = lpm_metadata_serialize(pkg, LPM_META_INSTALLED, &meta_buf, &meta_len, err);
    if (rc != LPM_OK)
        goto out;
    rc = lpm_file_list_serialize(files, &list_buf, &list_len, err);
    if (rc != LPM_OK)
        goto out;

    record_name(meta, sizeof(meta), pkg->name, LPM_META_SUFFIX);
    record_name(list, sizeof(list), pkg->name, LPM_LIST_SUFFIX);

    /* 2. Duplicate registration (we hold the lock, so this cannot race
     *    with another cooperating LPM process). */
    rc = lookup_entry(db->installed_fd, meta, LPM_DB_INSTALLED_DIR, &present, &st, err);
    if (rc != LPM_OK)
        goto out;
    if (present) {
        if (S_ISREG(st.st_mode)) {
            lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, "name",
                               "package '%s' is already registered", pkg->name);
            rc = LPM_ERR_EXISTS;
        } else {
            lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, "name",
                               "installed/%s is %s; refusing to touch it", meta,
                               describe_type(st.st_mode));
            rc = LPM_ERR_INVALID;
        }
        goto out;
    }
    /* An orphaned regular .list may be replaced; anything else is odd. */
    rc = lookup_entry(db->files_fd, list, LPM_DB_FILES_DIR, &present, &st, err);
    if (rc != LPM_OK)
        goto out;
    if (present && !S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "files/%s is %s; refusing to touch it", list,
                           describe_type(st.st_mode));
        rc = LPM_ERR_INVALID;
        goto out;
    }

    /* 3. No path may already belong to another registered package. */
    rc = check_ownership(db, files, err);
    if (rc != LPM_OK)
        goto out;

    /* 4. Write the file list, then the record (the commit point). */
    rc = atomic_write(db->files_fd, LPM_DB_FILES_DIR, list, list_buf, list_len,
                      &renamed, err);
    if (rc != LPM_OK) {
        if (renamed) {   /* list in place but not durable: undo it */
            (void)unlinkat(db->files_fd, list, 0);
            (void)fsync_dir(db->files_fd);
        }
        goto out;
    }
    rc = atomic_write(db->installed_fd, LPM_DB_INSTALLED_DIR, meta, meta_buf,
                      meta_len, &renamed, err);
    if (rc != LPM_OK && !renamed) {
        /* Not committed: take the file list back out. */
        (void)unlinkat(db->files_fd, list, 0);
        (void)fsync_dir(db->files_fd);
    }
    /* rc != OK && renamed: committed, but the flush failed (see header). */

out:
    free(meta_buf);
    free(list_buf);
    return rc;
}

lpm_status lpm_db_unregister_package(lpm_db *db, const char *name,
                                     lpm_meta_error *err)
{
    char meta[RECORD_NAME_MAX], list[RECORD_NAME_MAX];
    struct stat st;
    bool present;
    lpm_status rc;

    err_clear(err);
    rc = require_writer(db, err);
    if (rc != LPM_OK)
        return rc;
    rc = require_valid_name(name, err);
    if (rc != LPM_OK)
        return rc;
    record_name(meta, sizeof(meta), name, LPM_META_SUFFIX);
    record_name(list, sizeof(list), name, LPM_LIST_SUFFIX);

    rc = lookup_entry(db->installed_fd, meta, LPM_DB_INSTALLED_DIR, &present, &st, err);
    if (rc != LPM_OK)
        return rc;
    if (!present) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, "name",
                           "package '%s' is not registered", name);
        return LPM_ERR_NOT_FOUND;
    }
    if (!S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "installed/%s is %s; refusing to remove it "
                           "automatically", meta, describe_type(st.st_mode));
        return LPM_ERR_INVALID;
    }

    /* Commit point: once the .meta is gone, the package is unregistered. */
    if (unlinkat(db->installed_fd, meta, 0) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot remove "
                           "installed/%s: %s", meta, strerror(errno));
        return LPM_ERR_IO;
    }
    if (fsync_dir(db->installed_fd) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "installed/%s was removed but the directory could "
                           "not be flushed (not flushed): %s", meta, strerror(errno));
        rc = LPM_ERR_IO;
    }

    /* Then the (now orphaned) file list. */
    if (lookup_entry(db->files_fd, list, LPM_DB_FILES_DIR, &present, &st, err) != LPM_OK)
        return LPM_ERR_IO;
    if (!present)
        return rc;   /* pre-Milestone-3 record without a list */
    if (!S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                           "record removed, but files/%s is %s and was left "
                           "in place", list, describe_type(st.st_mode));
        return LPM_ERR_INVALID;
    }
    if (unlinkat(db->files_fd, list, 0) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "record removed, but files/%s could not be removed "
                           "(%s); 'lpm check' will report it as orphaned",
                           list, strerror(errno));
        return LPM_ERR_IO;
    }
    if (fsync_dir(db->files_fd) != 0 && rc == LPM_OK) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "files/%s was removed but the directory could not "
                           "be flushed (not flushed): %s", list, strerror(errno));
        rc = LPM_ERR_IO;
    }
    return rc;
}

/* ---- Consistency check ------------------------------------------------ */

const char *lpm_check_kind_str(lpm_check_kind kind)
{
    switch (kind) {
    case LPM_CHECK_BAD_RECORD:             return "damaged record";
    case LPM_CHECK_UNEXPECTED_ENTRY:       return "unexpected entry";
    case LPM_CHECK_STALE_TEMP:             return "abandoned temporary file";
    case LPM_CHECK_MISSING_FILE_LIST:      return "missing file list";
    case LPM_CHECK_BAD_FILE_LIST:          return "damaged file list";
    case LPM_CHECK_ORPHAN_FILE_LIST:       return "orphaned file list";
    case LPM_CHECK_FILE_CONFLICT:          return "file ownership conflict";
    case LPM_CHECK_UNSATISFIED_DEPENDENCY: return "unsatisfied dependency";
    }
    return "problem";
}

typedef struct {
    char name[LPM_MAX_NAME_LEN + 1];
    bool valid;            /* passed strict parsing and name check */
    lpm_package pkg;       /* only when valid                      */
    bool has_list;         /* files/<name>.list parsed             */
    bool list_seen;        /* a files/<name>.list entry exists     */
    lpm_file_list files;
} check_rec;

typedef struct {
    lpm_db *db;
    check_rec *recs;
    size_t n, cap;
    lpm_check_fn fn;
    void *ctx;
    lpm_check_summary *sum;
    lpm_meta_error *err;
} check_state;

static void report(check_state *cs, lpm_check_kind kind, const char *dir,
                   const char *fname, const char *fmt, ...) LPM_PRINTF(5, 6);

static void report(check_state *cs, lpm_check_kind kind, const char *dir,
                   const char *fname, const char *fmt, ...)
{
    char subject[320], detail[600];
    va_list ap;

    snprintf(subject, sizeof(subject), "%s/%s", dir, fname);
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    cs->sum->problems++;
    if (cs->fn != NULL)
        cs->fn(cs->ctx, kind, subject, detail);
}

static bool is_temp_name(const char *fname)
{
    return strncmp(fname, LPM_DB_TEMP_PREFIX, strlen(LPM_DB_TEMP_PREFIX)) == 0;
}

static lpm_status check_installed_entry(void *ctx, const char *fname)
{
    check_state *cs = ctx;
    char name[LPM_MAX_NAME_LEN + 1];
    lpm_meta_error perr;
    check_rec *r;
    struct stat st;
    char *data;
    size_t len;
    lpm_status rc;

    if (is_temp_name(fname)) {
        report(cs, LPM_CHECK_STALE_TEMP, LPM_DB_INSTALLED_DIR, fname,
               "left behind by an interrupted write; not a record (it can be "
               "deleted once no LPM process is running)");
        return LPM_OK;
    }
    if (fstatat(cs->db->installed_fd, fname, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return LPM_OK;   /* removed while we were scanning */
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_INSTALLED_DIR, fname,
               "cannot be examined: %s", strerror(errno));
        return LPM_OK;
    }
    if (!split_record_name(fname, LPM_META_SUFFIX, name)) {
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_INSTALLED_DIR, fname,
               "is %s that is not a package record (records are named "
               "<package>.meta)", describe_type(st.st_mode));
        return LPM_OK;
    }
    if (!S_ISREG(st.st_mode)) {
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_INSTALLED_DIR, fname,
               "is %s; records must be regular files", describe_type(st.st_mode));
        return LPM_OK;
    }

    if (cs->n == cs->cap) {
        size_t new_cap = cs->cap ? cs->cap * 2 : 16;
        check_rec *grown;

        if (new_cap > SIZE_MAX / sizeof(*grown))
            return nomem_err(cs->err);
        grown = realloc(cs->recs, new_cap * sizeof(*grown));
        if (grown == NULL)
            return nomem_err(cs->err);
        cs->recs = grown;
        cs->cap = new_cap;
    }
    r = &cs->recs[cs->n++];
    snprintf(r->name, sizeof(r->name), "%s", name);
    r->valid = r->has_list = r->list_seen = false;
    lpm_package_init(&r->pkg);
    lpm_file_list_init(&r->files);
    cs->sum->records++;

    rc = lpm_metadata_read_fileat(cs->db->installed_fd, fname, &data, &len, &perr);
    if (rc == LPM_OK) {
        rc = lpm_metadata_parse_buffer(data, len, LPM_META_INSTALLED, &r->pkg, &perr);
        free(data);
    }
    if (rc == LPM_ERR_NOMEM)
        return nomem_err(cs->err);
    if (rc == LPM_OK && strcmp(r->pkg.name, name) != 0) {
        lpm_meta_error_set(&perr, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "record declares name '%s', which does not match its "
                           "database filename", r->pkg.name);
        lpm_package_free(&r->pkg);
        rc = LPM_ERR_INVALID;
    }
    if (rc != LPM_OK) {
        char msg[400];
        lpm_meta_error_format(&perr, fname, msg, sizeof(msg));
        report(cs, LPM_CHECK_BAD_RECORD, LPM_DB_INSTALLED_DIR, fname, "%s", msg);
        return LPM_OK;
    }
    r->valid = true;
    cs->sum->packages++;
    return LPM_OK;
}

static int compare_recs(const void *a, const void *b)
{
    return strcmp(((const check_rec *)a)->name, ((const check_rec *)b)->name);
}

static check_rec *find_rec(check_state *cs, const char *name)
{
    check_rec key;

    if (cs->n == 0)
        return NULL;   /* bsearch() must not be given a NULL array */
    snprintf(key.name, sizeof(key.name), "%s", name);
    return bsearch(&key, cs->recs, cs->n, sizeof(*cs->recs), compare_recs);
}

static lpm_status check_files_entry(void *ctx, const char *fname)
{
    check_state *cs = ctx;
    char name[LPM_MAX_NAME_LEN + 1];
    lpm_meta_error perr;
    struct stat st;
    check_rec *r;
    lpm_status rc;

    if (is_temp_name(fname)) {
        report(cs, LPM_CHECK_STALE_TEMP, LPM_DB_FILES_DIR, fname,
               "left behind by an interrupted write; not a file list (it can "
               "be deleted once no LPM process is running)");
        return LPM_OK;
    }
    if (fstatat(cs->db->files_fd, fname, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return LPM_OK;
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_FILES_DIR, fname,
               "cannot be examined: %s", strerror(errno));
        return LPM_OK;
    }
    if (!split_record_name(fname, LPM_LIST_SUFFIX, name)) {
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_FILES_DIR, fname,
               "is %s that is not a file list (lists are named "
               "<package>.list)", describe_type(st.st_mode));
        return LPM_OK;
    }
    if (!S_ISREG(st.st_mode)) {
        report(cs, LPM_CHECK_UNEXPECTED_ENTRY, LPM_DB_FILES_DIR, fname,
               "is %s; file lists must be regular files", describe_type(st.st_mode));
        return LPM_OK;
    }
    r = find_rec(cs, name);
    if (r == NULL) {
        report(cs, LPM_CHECK_ORPHAN_FILE_LIST, LPM_DB_FILES_DIR, fname,
               "there is no installed/%s%s record (left over from an "
               "interrupted registration or removal); it owns nothing",
               name, LPM_META_SUFFIX);
        return LPM_OK;
    }
    r->list_seen = true;
    rc = lpm_db_read_file_list(cs->db, name, &r->files, &perr);
    if (rc == LPM_ERR_NOMEM)
        return nomem_err(cs->err);
    if (rc != LPM_OK) {
        char msg[400];
        lpm_meta_error_format(&perr, fname, msg, sizeof(msg));
        report(cs, LPM_CHECK_BAD_FILE_LIST, LPM_DB_FILES_DIR, fname, "%s", msg);
        return LPM_OK;
    }
    r->has_list = true;
    cs->sum->owned_files += r->files.count;
    return LPM_OK;
}

static bool on_check_conflict(void *ctx, const lpm_owned_path *a,
                              const lpm_owned_path *b, bool same_path)
{
    check_state *cs = ctx;
    const char *an = cs->recs[a->owner].name, *bn = cs->recs[b->owner].name;
    char fname[RECORD_NAME_MAX];

    record_name(fname, sizeof(fname), bn, LPM_LIST_SUFFIX);
    if (same_path)
        report(cs, LPM_CHECK_FILE_CONFLICT, LPM_DB_FILES_DIR, fname,
               "'%.200s' is also owned by package '%s'", a->path, an);
    else
        report(cs, LPM_CHECK_FILE_CONFLICT, LPM_DB_FILES_DIR, fname,
               "'%.200s' lies inside '%.200s', which package '%s' owns as a file",
               b->path, a->path, an);
    return true;   /* report them all */
}

static lpm_status check_conflicts(check_state *cs)
{
    lpm_owned_path *v;
    size_t i, j, k = 0, total = 0;

    for (i = 0; i < cs->n; i++)
        if (cs->recs[i].has_list) {
            if (cs->recs[i].files.count > SIZE_MAX / sizeof(*v) - total)
                return nomem_err(cs->err);
            total += cs->recs[i].files.count;
        }
    if (total == 0)
        return LPM_OK;
    v = malloc(total * sizeof(*v));
    if (v == NULL)
        return nomem_err(cs->err);
    for (i = 0; i < cs->n; i++)
        if (cs->recs[i].has_list)
            for (j = 0; j < cs->recs[i].files.count; j++) {
                v[k].path = cs->recs[i].files.paths[j];
                v[k++].owner = i;
            }
    lpm_owned_paths_sort(v, total);
    lpm_owned_paths_conflicts(v, total, on_check_conflict, cs);
    free(v);
    return LPM_OK;
}

static void check_dependencies(check_state *cs)
{
    size_t i, j;

    for (i = 0; i < cs->n; i++) {
        const check_rec *r = &cs->recs[i];
        char fname[RECORD_NAME_MAX];

        if (!r->valid)
            continue;
        record_name(fname, sizeof(fname), r->name, LPM_META_SUFFIX);
        for (j = 0; j < r->pkg.dependency_count; j++) {
            const lpm_dependency *d = &r->pkg.dependencies[j];
            const check_rec *t = find_rec(cs, d->name);
            bool ok = false;

            if (t == NULL) {
                report(cs, LPM_CHECK_UNSATISFIED_DEPENDENCY, LPM_DB_INSTALLED_DIR,
                       fname, "requires %s %s %s, which is not registered",
                       d->name, lpm_dep_operator_str(d->op), d->version);
            } else if (!t->valid) {
                report(cs, LPM_CHECK_UNSATISFIED_DEPENDENCY, LPM_DB_INSTALLED_DIR,
                       fname, "requires %s %s %s, whose record is damaged",
                       d->name, lpm_dep_operator_str(d->op), d->version);
            } else if (lpm_version_satisfies(t->pkg.version, d, &ok) != LPM_OK || !ok) {
                report(cs, LPM_CHECK_UNSATISFIED_DEPENDENCY, LPM_DB_INSTALLED_DIR,
                       fname, "requires %s %s %s, but version %s is registered",
                       d->name, lpm_dep_operator_str(d->op), d->version,
                       t->pkg.version);
            }
        }
    }
}

lpm_status lpm_db_check(lpm_db *db, lpm_check_fn fn, void *ctx,
                        lpm_check_summary *summary, lpm_meta_error *err)
{
    check_state cs;
    lpm_status rc;
    size_t i;

    err_clear(err);
    memset(summary, 0, sizeof(*summary));
    if (db == NULL || db->installed_fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL, "database is not open");
        return LPM_ERR_USAGE;
    }
    cs.db = db;
    cs.recs = NULL;
    cs.n = cs.cap = 0;
    cs.fn = fn;
    cs.ctx = ctx;
    cs.sum = summary;
    cs.err = err;

    rc = for_each_entry(db->installed_fd, LPM_DB_INSTALLED_DIR,
                        check_installed_entry, &cs, err);
    if (rc != LPM_OK)
        goto out;
    if (cs.n > 1)
        qsort(cs.recs, cs.n, sizeof(*cs.recs), compare_recs);

    if (db->files_fd >= 0) {
        rc = for_each_entry(db->files_fd, LPM_DB_FILES_DIR,
                            check_files_entry, &cs, err);
        if (rc != LPM_OK)
            goto out;
    }
    for (i = 0; i < cs.n; i++) {
        if (!cs.recs[i].list_seen) {
            char fname[RECORD_NAME_MAX];
            record_name(fname, sizeof(fname), cs.recs[i].name, LPM_META_SUFFIX);
            report(&cs, LPM_CHECK_MISSING_FILE_LIST, LPM_DB_INSTALLED_DIR, fname,
                   "has no files/%s%s, so the files it owns are unknown "
                   "(records created before Milestone 3 have none)",
                   cs.recs[i].name, LPM_LIST_SUFFIX);
        }
    }
    rc = check_conflicts(&cs);
    if (rc != LPM_OK)
        goto out;
    check_dependencies(&cs);

out:
    for (i = 0; i < cs.n; i++) {
        lpm_package_free(&cs.recs[i].pkg);
        lpm_file_list_free(&cs.recs[i].files);
    }
    free(cs.recs);
    return rc;
}
