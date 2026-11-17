/*
 * test_deps.c - Dependency planning and multi-package installation
 * (Milestone 5), end to end with real .lpm files.
 *
 * Every test builds its packages in <tmp>/lpm-deptest-XXXXXX/pkgs and
 * installs into <tmp>/lpm-deptest-XXXXXX/root; outside/ must stay empty.
 * Fault injection and crash simulation work as in test_install.c.
 */
#include "database.h"
#include "install.h"
#include "integrity.h"
#include "metadata.h"
#include "plan.h"
#include "solver.h"
#include "util.h"

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
#include <sys/wait.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include "test_framework.h"

/* ==================================================================== */
/* Fault injection (as in test_install.c)                                */
/* ==================================================================== */

typedef enum {
    F_NONE, F_ALLOC, F_WRITE, F_FSYNC, F_RENAMEAT, F_OPENAT, F_UNLINKAT,
    F_MKDIRAT, F_FCHMOD, F_CLOSE, F_FLOCK, F_LINKAT, F_SYMLINKAT, F_KINDS
} fault_kind;

static fault_kind fault_target = F_NONE;
static long fault_at = -1, fault_seen;
static int fault_errno, fault_fired;
static long crash_at = -1, syscalls_seen;

static void fault_reset(void)
{
    fault_target = F_NONE;
    fault_at = -1;
    fault_seen = 0;
    crash_at = -1;
    syscalls_seen = 0;
}

static void fault_arm(fault_kind k, long n, int e)
{
    fault_reset();
    fault_fired = 0;
    fault_target = k;
    fault_at = n;
    fault_errno = e;
}

static int should_fail(fault_kind k)
{
    if (crash_at >= 0 && k != F_ALLOC && syscalls_seen++ == crash_at)
        _exit(77);
    if (fault_target != k)
        return 0;
    if (fault_seen++ == fault_at) {
        fault_fired = 1;
        errno = fault_errno;
        return 1;
    }
    return 0;
}

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);
ssize_t __real_write(int fd, const void *buf, size_t n);
ssize_t __wrap_write(int fd, const void *buf, size_t n);
int __real_fsync(int fd);
int __wrap_fsync(int fd);
int __real_renameat(int ofd, const char *o, int nfd, const char *n);
int __wrap_renameat(int ofd, const char *o, int nfd, const char *n);
int __real_openat(int dirfd, const char *path, int flags, ...);
int __wrap_openat(int dirfd, const char *path, int flags, ...);
int __real_unlinkat(int dirfd, const char *path, int flags);
int __wrap_unlinkat(int dirfd, const char *path, int flags);
int __real_mkdirat(int dirfd, const char *path, mode_t mode);
int __wrap_mkdirat(int dirfd, const char *path, mode_t mode);
int __real_fchmod(int fd, mode_t mode);
int __wrap_fchmod(int fd, mode_t mode);
int __real_close(int fd);
int __wrap_close(int fd);
int __real_flock(int fd, int op);
int __wrap_flock(int fd, int op);
int __real_linkat(int ofd, const char *o, int nfd, const char *n, int flags);
int __wrap_linkat(int ofd, const char *o, int nfd, const char *n, int flags);
int __real_symlinkat(const char *t, int dirfd, const char *p);
int __wrap_symlinkat(const char *t, int dirfd, const char *p);

/*
 * Swap a package file between planning and verification: the wrapper
 * runs just before the installer's full read of each package, and on
 * request overwrites one file in place (same inode, so the descriptor
 * the installer already holds sees the new bytes).
 */
#include "pkg.h"
lpm_status __real_lpm_pkg_read(int fd, int stage_fd, lpm_pkg *out, lpm_meta_error *err);
lpm_status __wrap_lpm_pkg_read(int fd, int stage_fd, lpm_pkg *out, lpm_meta_error *err);
static char swap_from[900], swap_to[900];

lpm_status __wrap_lpm_pkg_read(int fd, int stage_fd, lpm_pkg *out, lpm_meta_error *err)
{
    if (swap_from[0] != '\0') {
        char buf[65536];
        size_t n;
        FILE *in = fopen(swap_from, "rb"), *o = fopen(swap_to, "wb");
        while (in && o && (n = fread(buf, 1, sizeof(buf), in)) > 0)
            fwrite(buf, 1, n, o);
        if (in)
            fclose(in);
        if (o)
            fclose(o);
        swap_from[0] = '\0';
    }
    return __real_lpm_pkg_read(fd, stage_fd, out, err);
}

void *__wrap_malloc(size_t s) { return should_fail(F_ALLOC) ? NULL : __real_malloc(s); }
void *__wrap_calloc(size_t n, size_t s) { return should_fail(F_ALLOC) ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t s) { return should_fail(F_ALLOC) ? NULL : __real_realloc(p, s); }
ssize_t __wrap_write(int fd, const void *buf, size_t n)
{ return should_fail(F_WRITE) ? -1 : __real_write(fd, buf, n); }
int __wrap_fsync(int fd) { return should_fail(F_FSYNC) ? -1 : __real_fsync(fd); }
int __wrap_renameat(int ofd, const char *o, int nfd, const char *n)
{ return should_fail(F_RENAMEAT) ? -1 : __real_renameat(ofd, o, nfd, n); }
int __wrap_openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return should_fail(F_OPENAT) ? -1 : __real_openat(dirfd, path, flags, mode);
}
int __wrap_unlinkat(int dirfd, const char *path, int flags)
{ return should_fail(F_UNLINKAT) ? -1 : __real_unlinkat(dirfd, path, flags); }
int __wrap_mkdirat(int dirfd, const char *path, mode_t mode)
{ return should_fail(F_MKDIRAT) ? -1 : __real_mkdirat(dirfd, path, mode); }
int __wrap_fchmod(int fd, mode_t mode)
{ return should_fail(F_FCHMOD) ? -1 : __real_fchmod(fd, mode); }
int __wrap_close(int fd)
{
    if (should_fail(F_CLOSE)) {
        int e = errno;
        __real_close(fd);
        errno = e;
        return -1;
    }
    return __real_close(fd);
}
int __wrap_flock(int fd, int op) { return should_fail(F_FLOCK) ? -1 : __real_flock(fd, op); }
int __wrap_linkat(int ofd, const char *o, int nfd, const char *n, int flags)
{ return should_fail(F_LINKAT) ? -1 : __real_linkat(ofd, o, nfd, n, flags); }
int __wrap_symlinkat(const char *t, int dirfd, const char *p)
{ return should_fail(F_SYMLINKAT) ? -1 : __real_symlinkat(t, dirfd, p); }

/* ==================================================================== */
/* Package builder                                                       */
/* ==================================================================== */

static char base[512], root[600], pkgs[600], outside[600];
static lpm_config cfg;

static void add_raw(struct archive *a, const char *name, char type, const char *data)
{
    struct archive_entry *e = archive_entry_new();
    size_t len = (type == 'f' && data) ? strlen(data) : 0;

    archive_entry_set_pathname(e, name);
    archive_entry_set_perm(e, type == 'd' ? 0755 : 0644);
    archive_entry_set_size(e, (la_int64_t)len);
    archive_entry_set_filetype(e, type == 'd' ? AE_IFDIR : AE_IFREG);
    archive_write_header(a, e);
    if (len > 0)
        archive_write_data(a, data, len);
    archive_entry_free(e);
}

/*
 * Build pkgs/<file> for package name/version with the given depends
 * (space separated, e.g. "liba>=1 libb<2") and one payload file per
 * path in `files` (space separated; default /usr/share/<name>/README).
 * tamper: the payload bytes differ from the manifest.
 */
static void make_pkg_full(const char *file, const char *name, const char *version,
                          const char *deps, const char *files, int tamper,
                          const char *raw_metadata)
{
    char path[1400], manifest[8192], metadata[8192], hex[65];
    char flist[1024], *tok, *save = NULL;
    struct archive *a;
    lpm_meta_error err;
    size_t mpos = 0;
    int pos;

    snprintf(path, sizeof(path), "%s/%s", pkgs, file);
    if (files)
        snprintf(flist, sizeof(flist), "%s", files);
    else
        snprintf(flist, sizeof(flist), "/usr/share/%s/README", name);
    manifest[0] = '\0';
    for (tok = strtok_r(flist, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char content[256];
        snprintf(content, sizeof(content), "%s %s %s\n", name, version, tok);
        lpm_sha256_buffer(content, strlen(content), hex, &err);
        mpos += (size_t)snprintf(manifest + mpos, sizeof(manifest) - mpos,
                                 "file %s 0644 %s\n", hex, tok);
    }
    lpm_sha256_buffer(manifest, strlen(manifest), hex, &err);
    pos = snprintf(metadata, sizeof(metadata), "name=%s\nversion=%s\n", name, version);
    if (deps) {
        char dcopy[2048], *d, *s2 = NULL;
        snprintf(dcopy, sizeof(dcopy), "%s", deps);
        for (d = strtok_r(dcopy, " ", &s2); d; d = strtok_r(NULL, " ", &s2))
            pos += snprintf(metadata + pos, sizeof(metadata) - (size_t)pos,
                            "depends=%s\n", d);
    }
    snprintf(metadata + pos, sizeof(metadata) - (size_t)pos, "manifest_sha256=%s\n", hex);

    a = archive_write_new();
    archive_write_set_format_pax_restricted(a);
    archive_write_add_filter_gzip(a);
    archive_write_open_filename(a, path);
    add_raw(a, "metadata.txt", 'f', raw_metadata ? raw_metadata : metadata);
    add_raw(a, "manifest.txt", 'f', manifest);
    add_raw(a, "payload/", 'd', NULL);
    if (files)
        snprintf(flist, sizeof(flist), "%s", files);
    else
        snprintf(flist, sizeof(flist), "/usr/share/%s/README", name);
    save = NULL;
    for (tok = strtok_r(flist, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char content[256], ename[700];
        snprintf(content, sizeof(content), "%s %s %s\n", name, version, tok);
        if (tamper)
            snprintf(content, sizeof(content), "TAMPERED\n");
        snprintf(ename, sizeof(ename), "payload%s", tok);
        add_raw(a, ename, 'f', content);
    }
    archive_write_close(a);
    archive_write_free(a);
}

static void make_pkg(const char *name, const char *version, const char *deps)
{
    char file[200];
    snprintf(file, sizeof(file), "%s-%s.lpm", name, version);
    make_pkg_full(file, name, version, deps, NULL, 0, NULL);
}

static const char *pkg_path(const char *name, const char *version)
{
    static char p[2][800];
    static int k;
    k ^= 1;
    snprintf(p[k], sizeof(p[k]), "%s/%s-%s.lpm", pkgs, name, version);
    return p[k];
}

/* ==================================================================== */
/* Helpers                                                               */
/* ==================================================================== */

static void rm_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d;
        struct dirent *de;
        chmod(path, 0700);
        d = opendir(path);
        while (d && (de = readdir(d)) != NULL) {
            char sub[1400];
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            snprintf(sub, sizeof(sub), "%s/%s", path, de->d_name);
            rm_tree(sub);
        }
        if (d)
            closedir(d);
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void fresh(void)
{
    const char *t = getenv("TMPDIR");
    if (base[0])
        rm_tree(base);
    snprintf(base, sizeof(base), "%s/lpm-deptest-XXXXXX", (t && *t) ? t : "/tmp");
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(root, sizeof(root), "%s/root", base);
    snprintf(pkgs, sizeof(pkgs), "%s/pkgs", base);
    snprintf(outside, sizeof(outside), "%s/outside", base);
    mkdir(root, 0755);
    mkdir(pkgs, 0755);
    mkdir(outside, 0755);
    cfg.root = root;
}

static int count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int n = 0;
    while (d && (de = readdir(d)) != NULL)
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
            n++;
    if (d)
        closedir(d);
    return n;
}

static int registered(const char *name)
{
    lpm_package p;
    lpm_meta_error err;
    if (lpm_db_load_package(&cfg, name, &p, &err) != LPM_OK)
        return 0;
    lpm_package_free(&p);
    return 1;
}

static int registered_count(void)
{
    lpm_db_list list;
    int exists, n;
    if (lpm_db_list_installed(&cfg, &list, &exists) != LPM_OK)
        return -1;
    n = (int)list.count;
    lpm_db_list_free(&list);
    return n;
}

static int installed_file(const char *name)
{
    char p[1400];
    snprintf(p, sizeof(p), "%s/usr/share/%s/README", root, name);
    return access(p, F_OK) == 0;
}

static int staging_entries(void)
{
    char p[800];
    snprintf(p, sizeof(p), "%s/var/lib/lpm/staging", root);
    return count_entries(p);
}

/* Nothing but (possibly) an empty database. */
static int root_untouched(void)
{
    char usr[800];
    snprintf(usr, sizeof(usr), "%s/usr", root);
    return access(usr, F_OK) != 0 && registered_count() <= 0 &&
           count_entries(outside) == 0 && staging_entries() <= 0;
}

static const char *order_names(const lpm_plan *p)
{
    static char buf[2048];
    size_t i, pos = 0;
    buf[0] = '\0';
    for (i = 0; i < p->order_count; i++)
        pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, "%s%s",
                                i ? "," : "", p->nodes[p->order[i]].pkg->name);
    return buf;
}

static lpm_status install_with(const char *path, const char *dir, lpm_meta_error *err)
{
    lpm_install_options opt = { NULL, false, 0 };
    lpm_install_report rep;
    lpm_status rc = lpm_install_packages(&cfg, path, dir, &opt, &rep, err);
    if (tf_verbose)
        printf("      install: %s\n", rc == LPM_OK ? "ok" : err->message);
    lpm_install_report_free(&rep);
    return rc;
}

typedef struct { unsigned kinds; size_t n; } check_result;
static void collect(void *ctx, lpm_check_kind k, const char *s, const char *d)
{
    check_result *r = ctx;
    (void)s; (void)d;
    r->kinds |= 1u << k;
    r->n++;
}
static check_result run_check(void)
{
    check_result r = { 0, 0 };
    lpm_check_summary sum;
    lpm_meta_error err;
    lpm_db db;
    if (lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK) {
        lpm_db_check(&db, collect, &r, &sum, &err);
        lpm_db_close(&db);
    }
    return r;
}

/* app -> liba -> libc, app -> libb -> libc */
static void diamond(void)
{
    make_pkg("libc", "1.0", NULL);
    make_pkg("liba", "1.2", "libc>=1.0");
    make_pkg("libb", "1.0", "libc>=1.0");
    make_pkg("app", "1.0", "liba>=1.0 libb>=1.0");
}

/* ==================================================================== */
/* Scenarios A-G                                                         */
/* ==================================================================== */

static void test_scenario_a_dag(void)
{
    lpm_resolution r;
    lpm_meta_error err;
    size_t i;

    fresh();
    diamond();
    /* plan: read-only */
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) == LPM_OK);
    CHECK(strcmp(order_names(&r.plan), "libc,liba,libb,app") == 0);
    CHECK(r.plan.count == 4 && r.plan.satisfied == 0);
    for (i = 0; i < r.plan.order_count; i++)
        CHECK(strstr(r.plan.nodes[r.plan.order[i]].source, pkgs) != NULL);
    lpm_resolution_free(&r);
    CHECK(count_entries(root) == 0);              /* planning wrote nothing */

    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_OK);
    CHECK(registered("libc") && registered("liba") && registered("libb") && registered("app"));
    CHECK(registered_count() == 4);              /* libc exactly once */
    CHECK(installed_file("libc") && installed_file("app"));
    CHECK(staging_entries() == 0);
    CHECK(run_check().n == 0);                   /* dependencies satisfied */
}

static void test_scenario_b_missing(void)
{
    lpm_resolution r;
    lpm_meta_error err;

    fresh();
    make_pkg("app", "1.0", "missinglib>=1.0");
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) ==
          LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_MISSING);
    CHECK(strstr(err.message, "missinglib >= 1.0 (required by app 1.0)") != NULL);
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_DEPENDENCY);
    CHECK(root_untouched());
}

static void test_scenario_c_cycle(void)
{
    lpm_resolution r;
    lpm_meta_error err;

    fresh();
    make_pkg("a", "1", "b>=1");
    make_pkg("b", "1", "c>=1");
    make_pkg("c", "1", "a>=1");
    CHECK(lpm_resolve_request(&cfg, pkg_path("a", "1"), pkgs, false, &r, &err) ==
          LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_CYCLE);
    CHECK(strstr(err.message, "a -> b -> c -> a") != NULL);
    CHECK(install_with(pkg_path("a", "1"), pkgs, &err) == LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_CYCLE);
    CHECK(root_untouched());
}

static void test_scenario_d_version_conflict(void)
{
    lpm_resolution r;
    lpm_meta_error err;

    fresh();
    make_pkg("library", "1.0", NULL);
    make_pkg("library", "3.1", NULL);
    make_pkg("a", "1.0", "library>=3.0");
    make_pkg("b", "1.0", "library<2.0");
    make_pkg("app", "1.0", "a>=1.0 b>=1.0");
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) ==
          LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_CONFLICT);
    CHECK(strstr(err.message, "library < 2.0") != NULL &&
          strstr(err.message, "library >= 3.0") != NULL);
    CHECK(r.plan.nodes == NULL);                 /* no invalid plan */
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_DEPENDENCY);
    CHECK(root_untouched());
}

static void test_scenario_e_installed_dependency(void)
{
    lpm_resolution r;
    lpm_meta_error err;

    fresh();
    make_pkg("library", "2.0", NULL);
    CHECK(install_with(pkg_path("library", "2.0"), NULL, &err) == LPM_OK);
    make_pkg("library", "2.5", NULL);            /* newer, but no upgrades */
    make_pkg("app", "1.0", "library>=1.5");
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) == LPM_OK);
    CHECK(strcmp(order_names(&r.plan), "app") == 0);   /* only app needs installing */
    CHECK(r.plan.satisfied == 1);
    CHECK(r.plan.nodes[1].kind == LPM_NODE_INSTALLED &&
          strcmp(r.plan.nodes[1].pkg->version, "2.0") == 0);
    lpm_resolution_free(&r);
    /* Installing works even without a package directory. */
    CHECK(install_with(pkg_path("app", "1.0"), NULL, &err) == LPM_OK);
    CHECK(registered_count() == 2 && registered("app"));
}

static void test_scenario_f_corrupted_candidate(void)
{
    lpm_resolution r;
    lpm_meta_error err;

    fresh();
    diamond();
    /* libc's payload no longer matches its manifest; its metadata is
     * fine, so the plan is made, but installation verifies everything. */
    make_pkg_full("libc-1.0.lpm", "libc", "1.0", NULL, NULL, 1, NULL);
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) == LPM_OK);
    lpm_resolution_free(&r);
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_INTEGRITY);
    CHECK(strstr(err.message, "libc 1.0") != NULL);
    CHECK(root_untouched());                     /* not even liba, libb, app */

    /* A candidate whose metadata is unreadable stops planning, named. */
    fresh();
    diamond();
    make_pkg_full("libb-1.0.lpm", "libb", "1.0", NULL, NULL, 0, "name=libb\nversion=01\n");
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) ==
          LPM_ERR_INVALID);
    CHECK(strstr(err.message, "libb-1.0.lpm") != NULL);
    {   /* not an archive at all */
        FILE *f;
        char p[900];
        fresh();
        diamond();
        snprintf(p, sizeof(p), "%s/junk.lpm", pkgs);
        f = fopen(p, "w");
        fputs("not a package\n", f);
        fclose(f);
        CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) ==
              LPM_ERR_INVALID);
        CHECK(strstr(err.message, "junk.lpm") != NULL);
        CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_INVALID);
        CHECK(root_untouched());
    }
}

static void test_scenario_g_root_isolation(void)
{
    char host[300];
    lpm_meta_error err;

    fresh();
    snprintf(host, sizeof(host), "/usr/share/lpm-deptest-%ld/README", (long)getpid());
    make_pkg_full("iso-1.lpm", "iso", "1", NULL, host, 0, NULL);
    make_pkg("app", "1.0", "iso>=1");
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_OK);
    CHECK(access(host, F_OK) != 0);              /* not on the host */
    {
        char inroot[900];
        snprintf(inroot, sizeof(inroot), "%s%s", root, host);
        CHECK(access(inroot, F_OK) == 0);        /* but in the root */
    }
    CHECK(access("/var/lib/lpm/installed/iso.meta", F_OK) != 0);
    CHECK(count_entries(outside) == 0);
    CHECK(count_entries(base) == 3);             /* root, pkgs, outside */
}

/* ==================================================================== */
/* More planning and installation cases                                  */
/* ==================================================================== */

static void test_dependency_check_without_package_dir(void)
{
    lpm_meta_error err;

    fresh();
    diamond();
    CHECK(install_with(pkg_path("app", "1.0"), NULL, &err) == LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_MISSING);
    CHECK(strstr(err.message, "liba >= 1.0") != NULL);
    CHECK(root_untouched());
}

static void test_package_directory_handling(void)
{
    lpm_resolution r;
    lpm_meta_error err;
    char p[900];
    FILE *f;

    fresh();                                     /* empty directory */
    make_pkg_full("../app-1.0.lpm", "app", "1.0", NULL, NULL, 0, NULL);
    snprintf(p, sizeof(p), "%s/app-1.0.lpm", base);
    CHECK(lpm_resolve_request(&cfg, p, pkgs, false, &r, &err) == LPM_OK);   /* no deps */
    lpm_resolution_free(&r);
    make_pkg_full("../app2-1.lpm", "app2", "1", "liba>=1", NULL, 0, NULL);
    snprintf(p, sizeof(p), "%s/app2-1.lpm", base);
    CHECK(lpm_resolve_request(&cfg, p, pkgs, false, &r, &err) == LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_MISSING);

    fresh();                                     /* ignored entries */
    diamond();
    snprintf(p, sizeof(p), "%s/README.txt", pkgs);
    f = fopen(p, "w"); fputs("not a package\n", f); fclose(f);
    snprintf(p, sizeof(p), "%s/.hidden.lpm", pkgs);
    f = fopen(p, "w"); fputs("junk\n", f); fclose(f);
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) == LPM_OK);
    /* The requested file lives in the directory too: not a duplicate. */
    CHECK(r.plan.count == 4);
    lpm_resolution_free(&r);

    fresh();                                     /* ambiguous duplicate */
    diamond();
    make_pkg_full("libc-copy.lpm", "libc", "1.0", NULL, "/usr/share/libc/OTHER", 0, NULL);
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) ==
          LPM_ERR_DEPENDENCY);
    CHECK(err.code == LPM_META_ERR_DEP_DUPLICATE);

    fresh();                                     /* missing directory */
    diamond();
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), "/nonexistent/pkgs", false,
                              &r, &err) == LPM_ERR_NOT_FOUND);
    CHECK(lpm_resolve_request(&cfg, "/nonexistent/app.lpm", pkgs, false, &r, &err) ==
          LPM_ERR_NOT_FOUND);
}

static void test_highest_compatible_version_selected(void)
{
    lpm_resolution r;
    lpm_meta_error err;
    size_t i;

    fresh();
    make_pkg("lib", "1.0", NULL);
    make_pkg("lib", "2.0", NULL);
    make_pkg("lib", "3.0", NULL);
    make_pkg("app", "1.0", "lib<3.0");
    CHECK(lpm_resolve_request(&cfg, pkg_path("app", "1.0"), pkgs, false, &r, &err) == LPM_OK);
    for (i = 0; i < r.plan.count; i++)
        if (strcmp(r.plan.nodes[i].pkg->name, "lib") == 0)
            CHECK(strcmp(r.plan.nodes[i].pkg->version, "2.0") == 0 &&
                  strstr(r.plan.nodes[i].source, "lib-2.0.lpm") != NULL);
    lpm_resolution_free(&r);
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_OK);
    CHECK(registered_count() == 2);
}

static void test_conflict_between_new_packages(void)
{
    lpm_meta_error err;

    fresh();
    /* liba and libb both ship the same file. */
    make_pkg_full("liba-1.lpm", "liba", "1", NULL, "/usr/share/common/data", 0, NULL);
    make_pkg_full("libb-1.lpm", "libb", "1", NULL, "/usr/share/common/data", 0, NULL);
    make_pkg("app", "1", "liba>=1 libb>=1");
    CHECK(install_with(pkg_path("app", "1"), pkgs, &err) == LPM_ERR_CONFLICT);
    CHECK(strstr(err.message, "both need /usr/share/common/data") != NULL);
    CHECK(root_untouched());
}

static void test_expected_hash_applies_to_request(void)
{
    char digest[65];
    lpm_install_options opt = { NULL, false, 0 };
    lpm_install_report rep;
    lpm_meta_error err;

    fresh();
    diamond();
    CHECK(lpm_sha256_file(pkg_path("app", "1.0"), digest, &err) == LPM_OK);
    opt.expected_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    CHECK(lpm_install_packages(&cfg, pkg_path("app", "1.0"), pkgs, &opt, &rep, &err) ==
          LPM_ERR_INTEGRITY);
    CHECK(count_entries(root) == 0);              /* refused before anything */
    opt.expected_sha256 = digest;
    CHECK(lpm_install_packages(&cfg, pkg_path("app", "1.0"), pkgs, &opt, &rep, &err) ==
          LPM_OK);
    CHECK(rep.count == 4 && strcmp(rep.items[3].name, "app") == 0 &&
          strcmp(rep.items[0].name, "libc") == 0);
    lpm_install_report_free(&rep);
}

static void test_package_changed_after_plan(void)
{
    char file[200];
    lpm_meta_error err;

    fresh();
    diamond();
    /* A valid libc 1.0 (correct hashes) whose metadata differs only in
     * its description: integrity checks alone would accept it. */
    snprintf(file, sizeof(file), "../libc-swapped.lpm");
    {
        char meta[512], hex[65], manifest[512], content[256];
        snprintf(content, sizeof(content), "libc 1.0 /usr/share/libc/README\n");
        lpm_sha256_buffer(content, strlen(content), hex, &err);
        snprintf(manifest, sizeof(manifest), "file %s 0644 /usr/share/libc/README\n", hex);
        lpm_sha256_buffer(manifest, strlen(manifest), hex, &err);
        snprintf(meta, sizeof(meta), "name=libc\nversion=1.0\ndescription=swapped\n"
                 "manifest_sha256=%s\n", hex);
        make_pkg_full(file, "libc", "1.0", NULL, NULL, 0, meta);
    }
    snprintf(swap_from, sizeof(swap_from), "%s/libc-swapped.lpm", base);
    snprintf(swap_to, sizeof(swap_to), "%s", pkg_path("libc", "1.0"));
    CHECK(install_with(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_INVALID);
    CHECK(strstr(err.message, "changed after the dependency plan was made") != NULL);
    CHECK(root_untouched());
}

static void test_real_root_still_refused(void)
{
    lpm_config real = { "/" };
    lpm_install_options opt = { NULL, false, 0 };
    lpm_install_report rep;
    lpm_meta_error err;

    fresh();
    diamond();
    make_pkg_full("libc-1.0.lpm", "libc", "1.0", NULL, NULL, 1, NULL);   /* and corrupt */
    CHECK(lpm_install_packages(&real, pkg_path("app", "1.0"), pkgs, &opt, &rep, &err) ==
          LPM_ERR_INVALID);
    CHECK(strstr(err.message, "real root") != NULL);
}

/* ==================================================================== */
/* Failure safety of multi-package installation                          */
/* ==================================================================== */

static int fault_errno_for(fault_kind k)
{
    switch (k) {
    case F_WRITE:  return ENOSPC;
    case F_OPENAT: return EMFILE;
    case F_FCHMOD: return EPERM;
    case F_FLOCK:  return ENOLCK;
    case F_LINKAT: return EXDEV;
    default:       return EIO;
    }
}

/* All four packages, or none: every single failure of the whole run. */
static void test_fault_injection_all_or_nothing(void)
{
    int k, points = 0, partial = 0;

    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 3000; n++) {
            lpm_meta_error err;
            lpm_status rc;
            int count, all, none;

            fresh();
            diamond();
            fault_arm((fault_kind)k, n, fault_errno_for((fault_kind)k));
            rc = install_with(pkg_path("app", "1.0"), pkgs, &err);
            fault_reset();
            count = registered_count();
            all = count == 4 && installed_file("libc") && installed_file("liba") &&
                  installed_file("libb") && installed_file("app");
            none = root_untouched();
            if (!fault_fired) {
                CHECK(rc == LPM_OK && all && staging_entries() == 0);
                break;
            }
            points++;
            if (!all && !none) {
                partial++;
                fprintf(stderr, "    partial state after %d #%ld: %d records\n", k, n, count);
            }
            CHECK(all || none);
            if (none)
                CHECK(rc != LPM_OK);
            if (all && rc == LPM_OK && staging_entries() == 0)
                CHECK(run_check().n == 0);
        }
    }
    if (tf_verbose)
        printf("      %d injected failures, %d partial\n", points, partial);
    CHECK(points >= 150);
}

/* A crash can leave a partial state; it must always be reported. */
static void test_crash_during_multi_install(void)
{
    long n;
    int crashes = 0;

    for (n = 0; n < 3000; n++) {
        lpm_meta_error err;
        pid_t pid;
        int status, code, count;
        check_result r;

        fresh();
        diamond();
        fflush(NULL);
        pid = fork();
        if (pid == 0) {
            lpm_status rc;
            fault_reset();
            crash_at = n;
            rc = install_with(pkg_path("app", "1.0"), pkgs, &err);
            _exit(rc == LPM_OK ? 0 : 1);
        }
        waitpid(pid, &status, 0);
        code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        CHECK(code == 0 || code == 77);
        count = registered_count();
        r = run_check();
        if (code == 0) {
            CHECK(count == 4 && r.n == 0);
            break;
        }
        crashes++;
        /* Not complete and not clean: lpm check must say so. */
        if (count != 4 && !root_untouched())
            CHECK((r.kinds & (1u << LPM_CHECK_STALE_TEMP)) != 0);
    }
    CHECK(crashes >= 50);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    fault_reset();
    umask(022);

    printf("Running dependency planning and multi-install tests\n");
    RUN(test_scenario_a_dag);
    RUN(test_scenario_b_missing);
    RUN(test_scenario_c_cycle);
    RUN(test_scenario_d_version_conflict);
    RUN(test_scenario_e_installed_dependency);
    RUN(test_scenario_f_corrupted_candidate);
    RUN(test_scenario_g_root_isolation);
    RUN(test_dependency_check_without_package_dir);
    RUN(test_package_directory_handling);
    RUN(test_highest_compatible_version_selected);
    RUN(test_conflict_between_new_packages);
    RUN(test_expected_hash_applies_to_request);
    RUN(test_package_changed_after_plan);
    RUN(test_real_root_still_refused);
    RUN(test_fault_injection_all_or_nothing);
    RUN(test_crash_during_multi_install);
    if (base[0])
        rm_tree(base);
    return tf_summary();
}
