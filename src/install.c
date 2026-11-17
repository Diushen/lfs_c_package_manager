/*
 * install.c - Package verification and installation (see install.h).
 */
#include "install.h"
#include "database.h"
#include "filelist.h"
#include "integrity.h"
#include "manifest.h"
#include "pkg.h"
#include "plan.h"
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

/* ==================================================================== */
/* Milestone 5: plan-driven, all-or-nothing installation                 */
/* ==================================================================== */

/* One package of a plan, from verification to commit. */
typedef struct {
    const lpm_plan_node *node;     /* what the plan selected               */
    int fd;
    char digest[LPM_SHA256_HEX_LEN + 1];
    int stage_fd;
    char stage_name[LPM_DB_STAGE_NAME_MAX];
    lpm_pkg pkg;                   /* fully verified contents              */
    lpm_file_list files;           /* what it will own                     */
    lpm_path_log log;              /* what committing it created           */
    bool registered;
} prepared;

static void prepared_init(prepared *p, const lpm_plan_node *node)
{
    memset(p, 0, sizeof(*p));
    p->node = node;
    p->fd = -1;
    p->stage_fd = -1;
    lpm_pkg_init(&p->pkg);
    lpm_file_list_init(&p->files);
    lpm_path_log_init(&p->log);
}

static void prepared_free(lpm_db *db, prepared *p)
{
    if (p->stage_fd >= 0) {
        lpm_meta_error ignore;
        /* Staged names go; installed files keep their own links. A
         * failure leaves a directory that lpm check reports. */
        (void)lpm_db_remove_staging(db, p->stage_fd, p->stage_name, &ignore);
        p->stage_fd = -1;
    }
    if (p->fd >= 0)
        close(p->fd);
    p->fd = -1;
    lpm_path_log_free(&p->log);
    lpm_file_list_free(&p->files);
    lpm_pkg_free(&p->pkg);
}

/* Name the package an error belongs to. */
static void blame(lpm_meta_error *err, const lpm_plan_node *n)
{
    if (err != NULL) {
        lpm_meta_error orig = *err;
        lpm_meta_error_set(err, orig.code, orig.line, orig.field, "%s %s: %.200s",
                           n->pkg->name, n->pkg->version, orig.message);
    }
}

/*
 * Full Milestone 4 verification of one planned package: whole-file hash
 * (root package only, if --sha256 was given), metadata, manifest hash,
 * every payload hash, staging, database rules and filesystem pre-flight.
 * The verified metadata must be exactly what the plan was built from.
 */
static lpm_status prepare(lpm_db *db, prepared *p, const char *expected,
                          lpm_meta_error *err)
{
    lpm_status rc;

    rc = open_package(p->node->source, expected, &p->fd, p->digest, err);
    if (rc == LPM_OK)
        rc = lpm_db_open_staging(db, &p->stage_fd, p->stage_name, err);
    if (rc == LPM_OK)
        rc = lpm_pkg_read(p->fd, p->stage_fd, &p->pkg, err);
    if (rc == LPM_OK && !lpm_package_equal(&p->pkg.meta, p->node->pkg)) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL,
                           "package file changed after the dependency plan was made");
        rc = LPM_ERR_INVALID;
    }
    if (rc == LPM_OK)
        rc = lpm_manifest_owned(&p->pkg.manifest, &p->files, err);
    if (rc == LPM_OK)
        rc = lpm_db_check_register(db, &p->pkg.meta, &p->files, err);
    if (rc == LPM_OK)
        rc = preflight(db->root_fd, &p->pkg.manifest, err);
    return rc;
}

typedef struct {
    const prepared *pkgs;
    lpm_meta_error *err;
    bool hit;
} batch_conflict;

/* owner = package index * 4 + manifest entry type */
static bool on_batch_conflict(void *ctx, const lpm_owned_path *a,
                              const lpm_owned_path *b, bool same_path)
{
    batch_conflict *c = ctx;
    size_t pa = a->owner / 4, pb = b->owner / 4;
    bool a_dir = a->owner % 4 == LPM_MAN_DIR, b_dir = b->owner % 4 == LPM_MAN_DIR;

    if (same_path ? (a_dir && b_dir) : a_dir)
        return true;   /* a shared directory, or a directory with contents */
    if (pa == pb)
        return true;   /* impossible: each manifest was validated */
    c->hit = true;
    lpm_meta_error_set(c->err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                       "%s and %s both need %.200s", c->pkgs[pa].pkg.meta.name,
                       c->pkgs[pb].pkg.meta.name, same_path ? a->path : b->path);
    return false;
}

/* Packages of one plan must not collide with each other either (the
 * database only knows about packages that are already registered). */
static lpm_status check_batch(const prepared *p, size_t n, lpm_meta_error *err)
{
    lpm_owned_path *v;
    size_t total = 0, i, j, k = 0;
    batch_conflict ctx;

    if (n < 2)
        return LPM_OK;
    for (i = 0; i < n; i++)
        total += p[i].pkg.manifest.count;   /* <= 1024 * 131072: fits */
    v = malloc((total ? total : 1) * sizeof(*v));
    if (v == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    for (i = 0; i < n; i++)
        for (j = 0; j < p[i].pkg.manifest.count; j++) {
            v[k].path = p[i].pkg.manifest.entries[j].path;
            v[k++].owner = i * 4 + (size_t)p[i].pkg.manifest.entries[j].type;
        }
    lpm_owned_paths_sort(v, total);
    ctx.pkgs = p;
    ctx.err = err;
    ctx.hit = false;
    lpm_owned_paths_conflicts(v, total, on_batch_conflict, &ctx);
    free(v);
    return ctx.hit ? LPM_ERR_CONFLICT : LPM_OK;
}

/* Undo a committed (possibly registered) package of this run only: its
 * record, then exactly the files and directories this run created. */
static void undo_package(lpm_db *db, prepared *p)
{
    if (p->registered) {
        lpm_meta_error ignore;
        (void)lpm_db_unregister_package(db, p->pkg.meta.name, &ignore);
        p->registered = false;
    }
    lpm_safe_rollback(db->root_fd, &p->log);
}

void lpm_install_report_free(lpm_install_report *r)
{
    if (r == NULL)
        return;
    free(r->items);
    r->items = NULL;
    r->count = 0;
    r->satisfied = 0;
}

lpm_status lpm_install_packages(const lpm_config *cfg, const char *path,
                                const char *package_dir,
                                const lpm_install_options *opt,
                                lpm_install_report *report, lpm_meta_error *err)
{
    static const lpm_install_options defaults = { NULL, false, 0 };
    char digest[LPM_SHA256_HEX_LEN + 1];
    lpm_resolution res;
    prepared *pkgs = NULL;
    size_t n = 0, done = 0, i;
    lpm_status rc;
    lpm_db db;
    int fd;

    memset(report, 0, sizeof(*report));
    memset(&res, 0, sizeof(res));
    if (opt == NULL)
        opt = &defaults;

    /* 1. Only checksums are verified so far, not who made the package,
     *    so the live system is off limits. */
    if (!opt->allow_real_root && lpm_is_real_root(cfg->root)) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL,
                           "installing into the real root filesystem is disabled "
                           "until packages are authenticated with signatures; "
                           "use --root DIR");
        return LPM_ERR_INVALID;
    }
    /* 2. The requested file must exist and match --sha256 before anything
     *    is created (not even an empty database). */
    rc = open_package(path, opt->expected_sha256, &fd, digest, err);
    if (rc != LPM_OK)
        return rc;
    close(fd);

    /* 3. One exclusive lock for planning, verification and commit. */
    rc = lpm_db_open(cfg, LPM_DB_CREATE, opt->lock_wait_ms, &db, err);
    if (rc != LPM_OK)
        return rc;

    /* 4. Plan against the installed set seen under this lock. */
    rc = lpm_resolve_request(cfg, path, package_dir, true, &res, err);
    if (rc != LPM_OK)
        goto out;
    n = res.plan.order_count;
    pkgs = calloc(n ? n : 1, sizeof(*pkgs));
    report->items = calloc(n ? n : 1, sizeof(*report->items));
    if (pkgs == NULL || report->items == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        rc = LPM_ERR_NOMEM;
        goto out;
    }
    for (i = 0; i < n; i++)
        prepared_init(&pkgs[i], &res.plan.nodes[res.plan.order[i]]);

    /* 5. Verify and stage EVERY package before placing any file. */
    for (i = 0; i < n; i++) {
        const char *expect = res.plan.order[i] == 0 ? opt->expected_sha256 : NULL;
        rc = prepare(&db, &pkgs[i], expect, err);
        if (rc != LPM_OK) {
            blame(err, pkgs[i].node);
            goto out;
        }
    }
    rc = check_batch(pkgs, n, err);
    if (rc != LPM_OK)
        goto out;

    /* 6. Commit in dependency order: files, then the record. */
    for (done = 0; done < n; done++) {
        prepared *p = &pkgs[done];
        rc = commit(db.root_fd, p->stage_fd, &p->pkg.manifest, &p->log, err);
        if (rc == LPM_OK) {
            rc = lpm_db_register_package(&db, &p->pkg.meta, &p->files, err);
            if (rc != LPM_OK) {
                bool exists = false;
                lpm_meta_error ignore;
                /* "not flushed": the record exists but may not be durable;
                 * treat as a failure of the whole run and undo it too. */
                if (lpm_db_package_exists(&db, p->pkg.meta.name, &exists, &ignore) ==
                        LPM_OK && exists)
                    p->registered = true;
            } else {
                p->registered = true;
            }
        }
        if (rc != LPM_OK) {
            blame(err, p->node);
            break;
        }
    }
    if (rc != LPM_OK) {
        /* 7. All or nothing: undo this run, newest first. */
        size_t k = done < n ? done + 1 : n;
        while (k-- > 0)
            undo_package(&db, &pkgs[k]);
        goto out;
    }
    for (i = 0; i < n; i++)
        summary_fill(&report->items[i], &pkgs[i].pkg, pkgs[i].digest);
    report->count = n;
    report->satisfied = res.plan.satisfied;

out:
    if (pkgs != NULL)
        for (i = 0; i < n; i++)
            prepared_free(&db, &pkgs[i]);
    free(pkgs);
    if (rc != LPM_OK)
        lpm_install_report_free(report);
    lpm_resolution_free(&res);
    lpm_db_close(&db);
    return rc;
}

lpm_status lpm_install_package(const lpm_config *cfg, const char *path,
                               const lpm_install_options *opt,
                               lpm_pkg_summary *out, lpm_meta_error *err)
{
    lpm_install_report r;
    lpm_status rc = lpm_install_packages(cfg, path, NULL, opt, &r, err);

    summary_clear(out);
    if (rc == LPM_OK && out != NULL && r.count > 0)
        *out = r.items[r.count - 1];   /* the requested package comes last */
    lpm_install_report_free(&r);
    return rc;
}
