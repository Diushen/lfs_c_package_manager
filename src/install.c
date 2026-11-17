/*
 * install.c - Package verification and installation (see install.h).
 */
#include "install.h"
#include "database.h"
#include "filelist.h"
#include "integrity.h"
#include "manifest.h"
#include "pkg.h"
#include "safefs.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool lpm_is_real_root(const char *root)
{
    struct stat a, b;

    if (root == NULL || stat(root, &a) != 0 || stat("/", &b) != 0)
        return false;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void summary_clear(lpm_pkg_summary *s)
{
    if (s != NULL)
        memset(s, 0, sizeof(*s));
}

static void summary_fill(lpm_pkg_summary *s, const lpm_pkg *p, const char *digest)
{
    if (s == NULL)
        return;
    snprintf(s->name, sizeof(s->name), "%s", p->meta.name);
    snprintf(s->version, sizeof(s->version), "%s", p->meta.version);
    snprintf(s->archive_sha256, sizeof(s->archive_sha256), "%s", digest);
    s->files = p->manifest.files;
    s->symlinks = p->manifest.symlinks;
    s->dirs = p->manifest.dirs;
    s->bytes = p->payload_bytes;
}

/*
 * Open the package file, hash all of it, compare with the optional
 * expected digest, and rewind: the same descriptor is then given to the
 * archive reader, so the bytes hashed are the bytes installed.
 */
static lpm_status open_package(const char *path, const char *expected, int *out_fd,
                               char digest[LPM_SHA256_HEX_LEN + 1], lpm_meta_error *err)
{
    char want[LPM_SHA256_HEX_LEN + 1];
    struct stat st;
    lpm_status rc;
    int fd;

    *out_fd = -1;
    if (expected != NULL) {   /* a malformed digest is a usage problem */
        rc = lpm_sha256_normalize(expected, want, err);
        if (rc != LPM_OK)
            return rc;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        int e = errno;
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot open package '%.200s': %s", path, strerror(e));
        return e == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL,
                           "package '%.200s' is not a regular file", path);
        close(fd);
        return LPM_ERR_INVALID;
    }
    rc = lpm_sha256_fd(fd, digest, NULL, err);
    if (rc == LPM_OK && expected != NULL && !lpm_sha256_equal(want, digest)) {
        lpm_meta_error_set(err, LPM_META_ERR_HASH_MISMATCH, 0, "sha256",
                           "package file SHA-256 mismatch: expected %s, got %s",
                           want, digest);
        rc = LPM_ERR_INTEGRITY;
    }
    if (rc == LPM_OK && lseek(fd, 0, SEEK_SET) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot rewind package: %s",
                           strerror(errno));
        rc = LPM_ERR_IO;
    }
    if (rc != LPM_OK) {
        close(fd);
        return rc;
    }
    *out_fd = fd;
    return LPM_OK;
}

lpm_status lpm_verify_package(const char *path, const char *expected_sha256,
                              lpm_pkg_summary *out, lpm_meta_error *err)
{
    char digest[LPM_SHA256_HEX_LEN + 1];
    lpm_pkg pkg;
    lpm_status rc;
    int fd;

    summary_clear(out);
    rc = open_package(path, expected_sha256, &fd, digest, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_pkg_read(fd, -1, &pkg, err);   /* -1: hash only, write nothing */
    close(fd);
    if (rc == LPM_OK) {
        summary_fill(out, &pkg, digest);
        lpm_pkg_free(&pkg);
    }
    return rc;
}

/* ---- Pre-flight and commit ---------------------------------------------- */

/*
 * Would placing every manifest entry succeed? Parents must be real
 * directories (or not exist yet); nothing may already exist where a file
 * or symlink goes; a directory entry may already exist as a directory.
 * Checking first means the common conflicts fail before any write.
 */
static lpm_status preflight(int root_fd, const lpm_manifest *m, lpm_meta_error *err)
{
    size_t i;

    for (i = 0; i < m->count; i++) {
        const lpm_manifest_entry *e = &m->entries[i];
        char parent[LPM_FILES_MAX_PATH + 1];
        const char *base;
        struct stat st;
        lpm_status rc;
        int dfd;

        rc = lpm_safe_split(e->path + 1, parent, sizeof(parent), &base, err);
        if (rc != LPM_OK)
            return rc;
        rc = lpm_safe_open_dir(root_fd, parent, false, 0, NULL, &dfd, err);
        if (rc == LPM_ERR_NOT_FOUND)
            continue;   /* parent missing: so is the entry; created later */
        if (rc != LPM_OK)
            return rc;
        if (fstatat(dfd, base, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (e->type == LPM_MAN_DIR && S_ISLNK(st.st_mode)) {
                /* e.g. a planted root/usr -> elsewhere */
                lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                                   "%.200s is a symbolic link or not a directory in "
                                   "the target root; refusing to write through it",
                                   e->path);
                close(dfd);
                return LPM_ERR_INVALID;
            }
            if (!(e->type == LPM_MAN_DIR && S_ISDIR(st.st_mode))) {
                lpm_meta_error_set(err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                                   "%.200s already exists in the target root and "
                                   "is not owned by any registered package; "
                                   "refusing to replace it", e->path);
                close(dfd);
                return LPM_ERR_CONFLICT;
            }
        } else if (errno != ENOENT) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot examine "
                               "%.200s: %s", e->path, strerror(errno));
            close(dfd);
            return LPM_ERR_IO;
        }
        close(dfd);
    }
    return LPM_OK;
}

/* Place one entry; append what was created to log. */
static lpm_status place(int root_fd, int stage_fd, const lpm_manifest *m, size_t i,
                        lpm_path_log *log, lpm_meta_error *err)
{
    const lpm_manifest_entry *e = &m->entries[i];
    const char *rel = e->path + 1, *base;
    char parent[LPM_FILES_MAX_PATH + 1], sname[16];
    lpm_status rc;
    int dfd, r, en;

    if (e->type == LPM_MAN_DIR) {
        rc = lpm_safe_open_dir(root_fd, rel, true, e->mode, log, &dfd, err);
        if (rc == LPM_OK)
            close(dfd);
        return rc;
    }
    rc = lpm_safe_split(rel, parent, sizeof(parent), &base, err);
    if (rc == LPM_OK)
        rc = lpm_safe_open_dir(root_fd, parent, true, 0755, log, &dfd, err);
    if (rc != LPM_OK)
        return rc;

    if (e->type == LPM_MAN_FILE) {
        /* linkat() fails with EEXIST instead of replacing anything, and
         * gives the destination the staged, already verified inode. */
        lpm_pkg_stage_name(i, sname);
        r = linkat(stage_fd, sname, dfd, base, 0);
    } else {
        r = symlinkat(e->target, dfd, base);
    }
    if (r != 0) {
        en = errno;
        if (en == EEXIST) {
            lpm_meta_error_set(err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                               "%.200s appeared while installing; refusing to "
                               "replace it", e->path);
            rc = LPM_ERR_CONFLICT;
        } else if (en == EXDEV) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot place %.200s: the target is on a different "
                               "filesystem from var/lib/lpm/staging", e->path);
            rc = LPM_ERR_IO;
        } else {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot create "
                               "%.200s: %s", e->path, strerror(en));
            rc = LPM_ERR_IO;
        }
        close(dfd);
        return rc;
    }
    rc = lpm_path_log_add(log, rel, false, err);
    if (rc != LPM_OK) {
        (void)unlinkat(dfd, base, 0);
        close(dfd);
        return rc;
    }
    if (lpm_fsync_retry(dfd) != 0 && errno != EINVAL) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot flush the "
                           "directory of %.200s: %s", e->path, strerror(errno));
        rc = LPM_ERR_IO;
    }
    close(dfd);
    return rc;
}

static lpm_status commit(int root_fd, int stage_fd, const lpm_manifest *m,
                         lpm_path_log *log, lpm_meta_error *err)
{
    size_t i;

    /* Sorted order puts every directory before what it contains. */
    for (i = 0; i < m->count; i++) {
        lpm_status rc = place(root_fd, stage_fd, m, i, log, err);
        if (rc != LPM_OK)
            return rc;
    }
    return LPM_OK;
}

lpm_status lpm_install_package(const lpm_config *cfg, const char *path,
                               const lpm_install_options *opt,
                               lpm_pkg_summary *out, lpm_meta_error *err)
{
    static const lpm_install_options defaults = { NULL, false, 0 };
    char digest[LPM_SHA256_HEX_LEN + 1], stage_name[LPM_DB_STAGE_NAME_MAX];
    lpm_file_list files;
    lpm_path_log log;
    lpm_pkg pkg;
    lpm_db db;
    lpm_status rc;
    int fd = -1, stage_fd = -1;
    bool db_open = false;

    summary_clear(out);
    if (opt == NULL)
        opt = &defaults;
    lpm_pkg_init(&pkg);
    lpm_file_list_init(&files);
    lpm_path_log_init(&log);
    stage_name[0] = '\0';

    /* 1. Only checksums are verified so far, not who made the package,
     *    so the live system is off limits. */
    if (!opt->allow_real_root && lpm_is_real_root(cfg->root)) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL,
                           "installing into the real root filesystem is disabled "
                           "until packages are authenticated with signatures; "
                           "use --root DIR");
        return LPM_ERR_INVALID;
    }

    /* 2. Package file and optional whole-file digest. */
    rc = open_package(path, opt->expected_sha256, &fd, digest, err);
    if (rc != LPM_OK)
        return rc;

    /* 3. Lock for the whole operation. */
    rc = lpm_db_open(cfg, LPM_DB_CREATE, opt->lock_wait_ms, &db, err);
    if (rc != LPM_OK)
        goto out;
    db_open = true;
    rc = lpm_db_open_staging(&db, &stage_fd, stage_name, err);
    if (rc != LPM_OK)
        goto out;

    /* 4. Verify everything; verified files land in staging only. */
    rc = lpm_pkg_read(fd, stage_fd, &pkg, err);
    if (rc != LPM_OK)
        goto out;

    /* 5. Pre-flight. */
    rc = lpm_manifest_owned(&pkg.manifest, &files, err);
    if (rc == LPM_OK)
        rc = lpm_db_check_register(&db, &pkg.meta, &files, err);
    if (rc == LPM_OK)
        rc = preflight(db.root_fd, &pkg.manifest, err);
    if (rc != LPM_OK)
        goto out;

    /* 6. Commit files, then 7. the record. */
    rc = commit(db.root_fd, stage_fd, &pkg.manifest, &log, err);
    if (rc == LPM_OK) {
        rc = lpm_db_register_package(&db, &pkg.meta, &files, err);
        if (rc != LPM_OK) {
            bool exists = false;
            lpm_meta_error ignore;
            /* "not flushed": recorded but maybe not durable -> keep files. */
            if (lpm_db_package_exists(&db, pkg.meta.name, &exists, &ignore) == LPM_OK &&
                exists)
                lpm_path_log_free(&log);
        }
    }
    if (rc != LPM_OK) {
        lpm_safe_rollback(db.root_fd, &log);
        goto out;
    }
    summary_fill(out, &pkg, digest);

out:
    lpm_path_log_free(&log);
    if (stage_fd >= 0) {
        lpm_meta_error cleanup_err;
        /* 8. Staged names go; installed files keep their own links. If
         *    this fails the package is still correctly installed and
         *    registered, so the result stands; the leftover directory is
         *    reported by lpm check. */
        (void)lpm_db_remove_staging(&db, stage_fd, stage_name, &cleanup_err);
    }
    if (db_open)
        lpm_db_close(&db);
    lpm_file_list_free(&files);
    lpm_pkg_free(&pkg);
    if (fd >= 0)
        close(fd);
    return rc;
}
