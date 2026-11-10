/*
 * test_database.c - Unit tests for the Milestone 3 database operations:
 * registration, removal, locking, atomic writes, crash consistency,
 * filesystem safety, file ownership, consistency checking and limits.
 *
 * Every test works in its own mkdtemp() directory under $TMPDIR (or
 * /tmp); nothing ever touches the real /var/lib/lpm.
 *
 * Fault injection: the binary is linked with GNU ld --wrap for
 * malloc/calloc/realloc and for the system calls the database uses
 * (write, fsync, renameat, openat, unlinkat, mkdirat, fchmod, close,
 * flock). A test can make the Nth call of one of them fail with a chosen
 * errno, make write() perform short writes, make calls return EINTR, or
 * make a forked child "crash" (_exit) at the Nth system call. After each
 * injected failure the tests inspect the database on disk: it must be
 * in the old state or the new state, never in between, and anything
 * left over must be reported by lpm_db_check().
 */
#include "database.h"
#include "filelist.h"
#include "metadata.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test_framework.h"

/* ==================================================================== */
/* Fault injection                                                       */
/* ==================================================================== */

typedef enum {
    F_NONE, F_ALLOC, F_WRITE, F_FSYNC, F_RENAMEAT, F_OPENAT, F_UNLINKAT,
    F_MKDIRAT, F_FCHMOD, F_CLOSE, F_FLOCK, F_KINDS
} fault_kind;

static const char *const fault_names[F_KINDS] = {
    "none", "malloc", "write", "fsync", "renameat", "openat", "unlinkat",
    "mkdirat", "fchmod", "close", "flock",
};

static fault_kind fault_target = F_NONE;
static long fault_at = -1, fault_seen;
static int fault_errno, fault_fired;
static int short_writes;          /* write() moves at most 1-3 bytes  */
static int eintr_mode;            /* every other call returns EINTR   */
static unsigned eintr_toggle;
static long crash_at = -1, syscalls_seen;  /* child _exit(77) at Nth call */

static void fault_reset(void)
{
    fault_target = F_NONE;
    fault_at = -1;
    fault_seen = 0;
    /* fault_fired is kept: the test reads it after disarming. */
    short_writes = 0;
    eintr_mode = 0;
    crash_at = -1;
    syscalls_seen = 0;
}

static void fault_arm(fault_kind k, long n, int e)
{
    fault_reset();
    fault_target = k;
    fault_fired = 0;
    fault_at = n;
    fault_errno = e;
}

static int should_fail(fault_kind k)
{
    if (crash_at >= 0 && k != F_ALLOC && syscalls_seen++ == crash_at)
        _exit(77);   /* simulated crash: no cleanup of any kind runs */
    if (fault_target != k)
        return 0;
    if (fault_seen++ == fault_at) {
        fault_fired = 1;
        errno = fault_errno;
        return 1;
    }
    return 0;
}

static int interrupted(void)
{
    if (eintr_mode && (eintr_toggle++ & 1u) == 0) {
        errno = EINTR;
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

void *__wrap_malloc(size_t s) { return should_fail(F_ALLOC) ? NULL : __real_malloc(s); }
void *__wrap_calloc(size_t n, size_t s) { return should_fail(F_ALLOC) ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t s) { return should_fail(F_ALLOC) ? NULL : __real_realloc(p, s); }

ssize_t __wrap_write(int fd, const void *buf, size_t n)
{
    if (should_fail(F_WRITE) || interrupted())
        return -1;
    if (short_writes && n > 1)
        n = 1 + tf_rand() % (n < 3 ? n : 3);
    return __real_write(fd, buf, n);
}

int __wrap_fsync(int fd)
{
    if (should_fail(F_FSYNC) || interrupted())
        return -1;
    return __real_fsync(fd);
}

int __wrap_renameat(int ofd, const char *o, int nfd, const char *n)
{
    return should_fail(F_RENAMEAT) ? -1 : __real_renameat(ofd, o, nfd, n);
}

int __wrap_openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (should_fail(F_OPENAT))
        return -1;
    return __real_openat(dirfd, path, flags, mode);
}

int __wrap_unlinkat(int dirfd, const char *path, int flags)
{
    return should_fail(F_UNLINKAT) ? -1 : __real_unlinkat(dirfd, path, flags);
}

int __wrap_mkdirat(int dirfd, const char *path, mode_t mode)
{
    return should_fail(F_MKDIRAT) ? -1 : __real_mkdirat(dirfd, path, mode);
}

int __wrap_fchmod(int fd, mode_t mode)
{
    return should_fail(F_FCHMOD) ? -1 : __real_fchmod(fd, mode);
}

int __wrap_close(int fd)
{
    if (should_fail(F_CLOSE)) {
        /* Linux semantics: the descriptor is gone even when close fails. */
        int e = errno;
        __real_close(fd);
        errno = e;
        return -1;
    }
    return __real_close(fd);
}

int __wrap_flock(int fd, int op)
{
    if (should_fail(F_FLOCK) || interrupted())
        return -1;
    return __real_flock(fd, op);
}

/* ==================================================================== */
/* Helpers                                                               */
/* ==================================================================== */

#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

/* The record most tests register: every scalar field, no dependencies
 * (so the consistency check has nothing to complain about). */
static const char HELLO_META[] =
    "name=hello\n"
    "version=1.2.0\n"
    "description=A simple hello world program\n"
    "manifest_sha256=" HEX64 "\n";
/* The same with dependencies, for round-trip and dependency checks. */
static const char HELLO_DEPS_META[] =
    "name=hello\n"
    "version=1.2.0\n"
    "description=A simple hello world program\n"
    "depends=libfoo>=1.0\n"
    "depends=libbar=2.1\n"
    "manifest_sha256=" HEX64 "\n";
static const char HELLO_LIST[] =
    "/usr/bin/hello\n"
    "/usr/share/doc/hello/README\n";

static char root[512];
static lpm_config cfg;

static void rm_tree(const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d;
        struct dirent *de;

        chmod(path, 0700);   /* permission tests may have locked us out */
        d = opendir(path);
        if (d != NULL) {
            while ((de = readdir(d)) != NULL) {
                char sub[1024];
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                    continue;
                snprintf(sub, sizeof(sub), "%s/%s", path, de->d_name);
                rm_tree(sub);
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static const char *tmp_base(void)
{
    const char *t = getenv("TMPDIR");
    return (t && *t) ? t : "/tmp";
}

/* Fresh, empty root for one test. */
static void new_root(void)
{
    if (root[0] != '\0')
        rm_tree(root);
    snprintf(root, sizeof(root), "%s/lpm-dbtest-XXXXXX", tmp_base());
    if (mkdtemp(root) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    cfg.root = root;
}

static void at(char *buf, size_t size, const char *rel)
{
    snprintf(buf, size, "%s/%s", root, rel);
}

static int exists_at(const char *rel)
{
    char p[1024];
    struct stat st;
    at(p, sizeof(p), rel);
    return lstat(p, &st) == 0;
}

static void write_at(const char *rel, const char *data, size_t len)
{
    char p[1024];
    FILE *f;
    at(p, sizeof(p), rel);
    f = fopen(p, "wb");
    if (f == NULL) {
        perror(p);
        return;
    }
    fwrite(data, 1, len, f);
    fclose(f);
}

static void write_text(const char *rel, const char *text)
{
    write_at(rel, text, strlen(text));
}

static void mkdir_at(const char *rel)
{
    char p[1024];
    at(p, sizeof(p), rel);
    mkdir(p, 0755);
}

/* Read a file under the root into a malloc'd NUL-terminated buffer. */
static char *read_at(const char *rel)
{
    char p[1024];
    FILE *f;
    char *buf;
    long n;

    at(p, sizeof(p), rel);
    f = fopen(p, "rb");
    if (f == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    rewind(f);
    buf = malloc((size_t)n + 1);
    if (buf != NULL) {
        buf[fread(buf, 1, (size_t)n, f)] = '\0';
    }
    fclose(f);
    return buf;
}

static int file_equals(const char *rel, const char *expect)
{
    char *got = read_at(rel);
    int eq = got != NULL && strcmp(got, expect) == 0;
    free(got);
    return eq;
}

static lpm_package make_pkg_at(const char *text, int line)
{
    lpm_package p;
    lpm_meta_error err;
    lpm_status rc = lpm_metadata_parse_buffer(text, strlen(text),
                                              LPM_META_INSTALLED, &p, &err);
    CHECK_AT(rc == LPM_OK, line);
    if (rc != LPM_OK)
        fprintf(stderr, "    bad test package: %s\n", err.message);
    return p;
}
#define make_pkg(text) make_pkg_at(text, __LINE__)

static lpm_status init_db(void)
{
    lpm_db db;
    lpm_meta_error err;
    lpm_status rc = lpm_db_open(&cfg, LPM_DB_CREATE, 0, &db, &err);
    lpm_db_close(&db);
    return rc;
}

/* Open, register, close: the unit of work a real caller performs. */
static lpm_status do_register(const char *meta, const char *list, lpm_meta_error *err)
{
    lpm_package pkg;
    lpm_file_list files;
    lpm_db db;
    lpm_status rc;

    lpm_package_init(&pkg);
    lpm_file_list_init(&files);
    rc = lpm_metadata_parse_buffer(meta, strlen(meta), LPM_META_INSTALLED, &pkg, err);
    if (rc == LPM_OK && list != NULL)
        rc = lpm_file_list_parse_buffer(list, strlen(list), &files, err);
    if (rc == LPM_OK)
        rc = lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, err);
    if (rc == LPM_OK) {
        rc = lpm_db_register_package(&db, &pkg, &files, err);
        lpm_db_close(&db);
    }
    lpm_package_free(&pkg);
    lpm_file_list_free(&files);
    return rc;
}

static lpm_status do_unregister(const char *name, lpm_meta_error *err)
{
    lpm_db db;
    lpm_status rc = lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, err);

    if (rc == LPM_OK) {
        rc = lpm_db_unregister_package(&db, name, err);
        lpm_db_close(&db);
    }
    return rc;
}

/* Run the consistency check; returns problems, fills a kind bitmask. */
typedef struct { unsigned kinds; size_t n; } check_result;

static void collect(void *ctx, lpm_check_kind kind, const char *subject,
                    const char *detail)
{
    check_result *r = ctx;
    r->kinds |= 1u << kind;
    r->n++;
    if (tf_verbose)
        printf("      check: [%s] %s: %s\n", lpm_check_kind_str(kind), subject, detail);
}

static check_result run_check(lpm_check_summary *sum_out)
{
    check_result r = { 0, 0 };
    lpm_check_summary sum;
    lpm_meta_error err;
    lpm_db db;

    if (lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) != LPM_OK) {
        r.n = (size_t)-1;
        return r;
    }
    if (lpm_db_check(&db, collect, &r, &sum, &err) != LPM_OK)
        r.n = (size_t)-1;
    lpm_db_close(&db);
    if (sum_out)
        *sum_out = sum;
    return r;
}
#define KIND(k) (1u << (k))

static int count_temp_files(void)
{
    static const char *const dirs[] = { "var/lib/lpm/installed", "var/lib/lpm/files" };
    int n = 0;
    size_t i;

    for (i = 0; i < 2; i++) {
        char p[1024];
        DIR *d;
        struct dirent *de;
        at(p, sizeof(p), dirs[i]);
        d = opendir(p);
        if (d == NULL)
            continue;
        while ((de = readdir(d)) != NULL)
            if (strncmp(de->d_name, LPM_DB_TEMP_PREFIX, strlen(LPM_DB_TEMP_PREFIX)) == 0)
                n++;
        closedir(d);
    }
    return n;
}

static void remove_temp_files(void)
{
    static const char *const dirs[] = { "var/lib/lpm/installed", "var/lib/lpm/files" };
    size_t i;

    for (i = 0; i < 2; i++) {
        char p[1024];
        DIR *d;
        struct dirent *de;
        at(p, sizeof(p), dirs[i]);
        d = opendir(p);
        if (d == NULL)
            continue;
        while ((de = readdir(d)) != NULL)
            if (strncmp(de->d_name, LPM_DB_TEMP_PREFIX, strlen(LPM_DB_TEMP_PREFIX)) == 0) {
                char f[1400];
                snprintf(f, sizeof(f), "%s/%s", p, de->d_name);
                unlink(f);
            }
        closedir(d);
    }
}

enum { ST_ABSENT, ST_REGISTERED, ST_ORPHAN, ST_BROKEN };
static const char *const state_names[] = { "absent", "registered", "orphan list", "BROKEN" };

/* Where is package `name`, given the exact bytes it should have? */
static int pkg_state(const char *name, const char *meta, const char *list)
{
    char m[256], l[256];
    int has_m, has_l;

    snprintf(m, sizeof(m), "var/lib/lpm/installed/%s.meta", name);
    snprintf(l, sizeof(l), "var/lib/lpm/files/%s.list", name);
    has_m = exists_at(m);
    has_l = exists_at(l);
    if (!has_m && !has_l)
        return ST_ABSENT;
    if (!has_m && has_l)
        return ST_ORPHAN;
    if (has_m && has_l && file_equals(m, meta) && file_equals(l, list))
        return ST_REGISTERED;
    return ST_BROKEN;   /* e.g. a .meta without its list, or partial bytes */
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static mode_t mode_at(const char *rel)
{
    char p[1024];
    struct stat st;
    at(p, sizeof(p), rel);
    return lstat(p, &st) == 0 ? st.st_mode : 0;
}

/* ==================================================================== */
/* Normal operations                                                     */
/* ==================================================================== */

static void test_init_creates_layout(void)
{
    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(S_ISDIR(mode_at("var/lib/lpm/installed")));
    CHECK(S_ISDIR(mode_at("var/lib/lpm/files")));
    CHECK(S_ISREG(mode_at("var/lib/lpm/lock")));
    CHECK((mode_at("var/lib/lpm") & 022) == 0);
    CHECK((mode_at("var/lib/lpm/lock") & 0777) == 0644 ||
          (mode_at("var/lib/lpm/lock") & 022) == 0);
    CHECK(init_db() == LPM_OK);                       /* idempotent */
    CHECK(run_check(NULL).n == 0);
}

static void test_open_uninitialised(void)
{
    lpm_db db;
    lpm_meta_error err;

    new_root();
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_NOT_FOUND);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_ERR_NOT_FOUND);
    CHECK(!exists_at("var"));                         /* nothing created */
    lpm_db_close(&db);                                /* safe after failure */
    lpm_db_close(&db);

    mkdir_at("var");                                  /* missing parents */
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_NOT_FOUND);
    CHECK(!exists_at("var/lib"));
    CHECK(init_db() == LPM_OK);
}

static void test_register_and_load(void)
{
    lpm_meta_error err;
    lpm_package got, expect;
    lpm_db_list list;
    lpm_db db;
    bool present = false;
    int db_exists;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_DEPS_META, HELLO_LIST, &err) == LPM_OK);

    /* Exact, deterministic bytes in both files. */
    CHECK(file_equals("var/lib/lpm/installed/hello.meta", HELLO_DEPS_META));
    CHECK(file_equals("var/lib/lpm/files/hello.list", HELLO_LIST));
    CHECK((mode_at("var/lib/lpm/installed/hello.meta") & 0777) == 0644);
    CHECK(count_temp_files() == 0);

    /* Readable through the Milestone 2 loader, field for field. */
    expect = make_pkg(HELLO_DEPS_META);
    CHECK(lpm_db_load_package(&cfg, "hello", &got, &err) == LPM_OK);
    CHECK(lpm_package_equal(&got, &expect));
    CHECK(got.dependency_count == 2 &&
          strcmp(got.dependencies[0].name, "libfoo") == 0);   /* order kept */
    lpm_package_free(&got);
    lpm_package_free(&expect);

    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_package_exists(&db, "hello", &present, &err) == LPM_OK && present);
    CHECK(lpm_db_package_exists(&db, "nothere", &present, &err) == LPM_OK && !present);
    lpm_db_close(&db);

    CHECK(lpm_db_list_installed(&cfg, &list, &db_exists) == LPM_OK);
    CHECK(list.count == 1 && strcmp(list.items[0].version, "1.2.0") == 0);
    lpm_db_list_free(&list);
}

static void test_register_without_file_list(void)
{
    lpm_meta_error err;
    lpm_db db;
    lpm_file_list files;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register("name=meta-only\nversion=1\n", NULL, &err) == LPM_OK);
    CHECK(file_equals("var/lib/lpm/files/meta-only.list", ""));   /* owns nothing */
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_read_file_list(&db, "meta-only", &files, &err) == LPM_OK);
    CHECK(files.count == 0);
    lpm_db_close(&db);
    CHECK(run_check(NULL).n == 0);
}

static void test_duplicate_registration(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    /* Even a different version or file list is a duplicate. */
    CHECK(do_register("name=hello\nversion=9.9\n", "/other\n", &err) == LPM_ERR_EXISTS);
    CHECK(strstr(err.message, "already registered") != NULL);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_REGISTERED);   /* untouched */
    CHECK(count_temp_files() == 0);
}

static void test_unregister(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    /* A "payload" file that the record claims. */
    mkdir_at("usr");
    mkdir_at("usr/bin");
    write_text("usr/bin/hello", "#!/bin/sh\necho hello\n");

    CHECK(do_unregister("hello", &err) == LPM_OK);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_ABSENT);
    CHECK(exists_at("usr/bin/hello"));            /* package files NOT deleted */
    CHECK(run_check(NULL).n == 0);

    CHECK(do_unregister("hello", &err) == LPM_ERR_NOT_FOUND);   /* twice */
    CHECK(do_unregister("never", &err) == LPM_ERR_NOT_FOUND);
    CHECK(strstr(err.message, "not registered") != NULL);
}

static void test_list_multiple_sorted(void)
{
    static const char *const names[] = { "zlib", "acl", "make", "bash", "coreutils" };
    lpm_meta_error err;
    lpm_db_list list;
    int db_exists;
    size_t i;

    new_root();
    CHECK(init_db() == LPM_OK);
    for (i = 0; i < 5; i++) {
        char meta[128];
        snprintf(meta, sizeof(meta), "name=%s\nversion=1.%zu\n", names[i], i);
        CHECK(do_register(meta, NULL, &err) == LPM_OK);
    }
    CHECK(lpm_db_list_installed(&cfg, &list, &db_exists) == LPM_OK);
    CHECK(list.count == 5);
    for (i = 1; i < list.count; i++)
        CHECK(strcmp(list.items[i - 1].name, list.items[i].name) < 0);
    lpm_db_list_free(&list);
}

static void test_roots_are_isolated(void)
{
    char first[512];
    lpm_meta_error err;
    lpm_package pkg;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    snprintf(first, sizeof(first), "%s", root);

    root[0] = '\0';   /* keep the first root alive */
    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(lpm_db_load_package(&cfg, "hello", &pkg, &err) == LPM_ERR_NOT_FOUND);
    rm_tree(first);
}

static void test_legacy_database_upgrade(void)
{
    lpm_meta_error err;
    check_result r;

    /* A Milestone 1/2 database: installed/ only, no files/, no lock. */
    new_root();
    mkdir_at("var");
    mkdir_at("var/lib");
    mkdir_at("var/lib/lpm");
    mkdir_at("var/lib/lpm/installed");
    write_text("var/lib/lpm/installed/old.meta", "name=old\nversion=1.0\n");

    r = run_check(NULL);                       /* readable without a lock file */
    CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_MISSING_FILE_LIST));
    CHECK(!exists_at("var/lib/lpm/lock"));     /* reading creates nothing */

    CHECK(do_register("name=new\nversion=2\n", "/usr/bin/new\n", &err) == LPM_OK);
    CHECK(exists_at("var/lib/lpm/lock") && exists_at("var/lib/lpm/files/new.list"));
    CHECK(file_equals("var/lib/lpm/installed/old.meta", "name=old\nversion=1.0\n"));
    r = run_check(NULL);
    CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_MISSING_FILE_LIST));
}

static void test_read_handle_cannot_write(void)
{
    lpm_meta_error err;
    lpm_package pkg;
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    pkg = make_pkg(HELLO_META);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_USAGE);
    CHECK(lpm_db_unregister_package(&db, "hello", &err) == LPM_ERR_USAGE);
    lpm_db_close(&db);
    CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_USAGE); /* closed */
    CHECK(lpm_db_register_package(NULL, &pkg, NULL, &err) == LPM_ERR_USAGE);
    lpm_package_free(&pkg);
    CHECK(!exists_at("var/lib/lpm/installed/hello.meta"));
}

/* ==================================================================== */
/* Invalid input and filesystem attacks                                  */
/* ==================================================================== */

static void test_invalid_names(void)
{
    static const char *const bad[] = { "../etc", "a/b", "", ".hidden", "Hello",
                                       "x..meta/../../y", "-dash" };
    lpm_meta_error err;
    lpm_package pkg;
    lpm_db db;
    bool present;
    size_t i;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(lpm_db_unregister_package(&db, bad[i], &err) == LPM_ERR_INVALID);
        CHECK(lpm_db_package_exists(&db, bad[i], &present, &err) == LPM_ERR_INVALID);
        /* A package struct built by hand, bypassing the parser. */
        pkg = make_pkg("name=placeholder\nversion=1\n");
        free(pkg.name);
        pkg.name = lpm_strdup(bad[i]);
        CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_INVALID);
        lpm_package_free(&pkg);
    }
    CHECK(lpm_db_unregister_package(&db, NULL, &err) == LPM_ERR_INVALID);
    lpm_db_close(&db);
    CHECK(!exists_at("var/lib/etc.meta") && !exists_at("etc"));
    CHECK(run_check(NULL).n == 0);
}

static void test_invalid_metadata_not_written(void)
{
    lpm_meta_error err;
    lpm_package pkg;
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);

    /* A newline in a value would inject a new field into the record. */
    pkg = make_pkg("name=evil\nversion=1\ndescription=x\n");
    free(pkg.description);
    pkg.description = lpm_strdup("ok\nmanifest_sha256=" HEX64);
    CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_CONTROL_CHAR);
    free(pkg.description);
    pkg.description = lpm_strdup(" padded ");     /* would be trimmed on read */
    CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_INVALID);
    free(pkg.description);
    pkg.description = NULL;
    free(pkg.version);
    pkg.version = lpm_strdup("01");
    CHECK(lpm_db_register_package(&db, &pkg, NULL, &err) == LPM_ERR_INVALID);
    lpm_package_free(&pkg);

    lpm_db_close(&db);
    CHECK(!exists_at("var/lib/lpm/installed/evil.meta"));
    CHECK(!exists_at("var/lib/lpm/files/evil.list"));
    CHECK(count_temp_files() == 0);
}

static void test_invalid_file_list_not_written(void)
{
    lpm_meta_error err;
    lpm_package pkg;
    lpm_file_list files;
    char *paths[2];
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    /* Traversal is rejected by the parser before the database is opened. */
    CHECK(do_register("name=x\nversion=1\n", "/../../etc/passwd\n", &err) == LPM_ERR_INVALID);
    CHECK(do_register("name=x\nversion=1\n", "/usr/bin/x\n/usr/bin/x\n", &err) == LPM_ERR_INVALID);

    /* A hand-built list that skipped validation is caught by the writer. */
    pkg = make_pkg("name=x\nversion=1\n");
    paths[0] = (char *)"/usr/bin/x";
    paths[1] = (char *)"/usr/../../etc/shadow";
    files.paths = paths;
    files.count = 2;
    files.capacity = 2;
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_register_package(&db, &pkg, &files, &err) == LPM_ERR_INVALID);
    lpm_db_close(&db);
    lpm_package_free(&pkg);
    CHECK(pkg_state("x", "", "") == ST_ABSENT);
    CHECK(count_temp_files() == 0);
}

static void test_unexpected_directory_entries(void)
{
    lpm_meta_error err;
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    mkdir_at("var/lib/lpm/installed/dir.meta");          /* a directory record */
    mkdir_at("var/lib/lpm/files/dir2.list");
    write_text("var/lib/lpm/installed/README", "notes\n");
    CHECK(do_register("name=dir\nversion=1\n", NULL, &err) == LPM_ERR_INVALID);
    CHECK(do_unregister("dir", &err) == LPM_ERR_INVALID);
    CHECK(S_ISDIR(mode_at("var/lib/lpm/installed/dir.meta")));   /* left alone */
    CHECK(do_register("name=dir2\nversion=1\n", NULL, &err) == LPM_ERR_INVALID);
    r = run_check(NULL);
    CHECK(r.n == 3 && r.kinds == KIND(LPM_CHECK_UNEXPECTED_ENTRY));
}

static void test_symlinked_database_directories(void)
{
    char outside[600], target[1024], link_path[1024];
    lpm_meta_error err;
    lpm_db db;
    int i;
    static const char *const victims[] = {
        "var/lib/lpm/installed", "var/lib/lpm/files", "var/lib/lpm", "var/lib", "var",
    };

    for (i = 0; i < 5; i++) {
        new_root();
        CHECK(init_db() == LPM_OK);
        /* Replace one database directory by a symlink to an outside dir. */
        snprintf(outside, sizeof(outside), "%s/outside", root);
        mkdir(outside, 0755);
        at(link_path, sizeof(link_path), victims[i]);
        rm_tree(link_path);
        snprintf(target, sizeof(target), "%s", outside);
        CHECK(symlink(target, link_path) == 0);

        CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_INVALID);
        CHECK(err.code == LPM_META_ERR_UNTRUSTED);
        CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_ERR_INVALID);
        CHECK(lpm_db_open(&cfg, LPM_DB_CREATE, 0, &db, &err) == LPM_ERR_INVALID);
        lpm_db_close(&db);
        {   /* the outside directory received nothing */
            DIR *d = opendir(outside);
            struct dirent *de;
            int n = 0;
            while (d && (de = readdir(d)) != NULL)
                if (de->d_name[0] != '.')
                    n++;
            if (d)
                closedir(d);
            CHECK(n == 0);
        }
    }
}

static void test_symlinked_records(void)
{
    char victim[700], lnk[1024];
    lpm_meta_error err;
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    snprintf(victim, sizeof(victim), "%s/victim", root);
    write_text("victim", "precious\n");

    /* installed/hello.meta -> victim */
    at(lnk, sizeof(lnk), "var/lib/lpm/installed/hello.meta");
    CHECK(symlink(victim, lnk) == 0);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_INVALID);
    CHECK(do_unregister("hello", &err) == LPM_ERR_INVALID);
    CHECK(file_equals("victim", "precious\n"));
    CHECK(S_ISLNK(mode_at("var/lib/lpm/installed/hello.meta")));   /* not deleted */
    unlink(lnk);

    /* files/hello.list -> victim */
    at(lnk, sizeof(lnk), "var/lib/lpm/files/hello.list");
    CHECK(symlink(victim, lnk) == 0);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_INVALID);
    CHECK(file_equals("victim", "precious\n"));
    CHECK(!exists_at("var/lib/lpm/installed/hello.meta"));

    /* the lock file -> victim */
    unlink(lnk);
    at(lnk, sizeof(lnk), "var/lib/lpm/lock");
    unlink(lnk);
    CHECK(symlink(victim, lnk) == 0);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_INVALID);
    CHECK(file_equals("victim", "precious\n"));
    unlink(lnk);

    /* check reports a symlinked record instead of following it */
    CHECK(init_db() == LPM_OK);
    at(lnk, sizeof(lnk), "var/lib/lpm/installed/evil.meta");
    CHECK(symlink(victim, lnk) == 0);
    r = run_check(NULL);
    CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_UNEXPECTED_ENTRY));
}

static void test_untrusted_permissions(void)
{
    char p[1024];
    lpm_meta_error err;
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    at(p, sizeof(p), "var/lib/lpm/installed");
    chmod(p, 0775);   /* group-writable: anyone in the group could swap records */
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_UNTRUSTED);
    CHECK(strstr(err.message, "writable by group or others") != NULL);
    chmod(p, 0757);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_ERR_INVALID);
    chmod(p, 0755);
    at(p, sizeof(p), "var/lib/lpm/lock");
    chmod(p, 0666);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_INVALID);
    chmod(p, 0644);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
    lpm_db_close(&db);
}

static void test_untrusted_owner(void)
{
    char p[1024];
    lpm_meta_error err;
    lpm_db db;

    if (geteuid() != 0)
        SKIP("needs root to chown a directory to another user");
    new_root();
    CHECK(init_db() == LPM_OK);
    at(p, sizeof(p), "var/lib/lpm/installed");
    CHECK(chown(p, 65534, 65534) == 0);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_UNTRUSTED);
    CHECK(strstr(err.message, "owned by uid 65534") != NULL);
}

static void test_inaccessible_database(void)
{
    char p[1024];
    lpm_meta_error err;
    lpm_db db;

    if (geteuid() == 0)
        SKIP("root ignores permission bits");
    new_root();
    CHECK(init_db() == LPM_OK);

    /* Read-only installed/: registration fails cleanly, nothing changes. */
    at(p, sizeof(p), "var/lib/lpm/installed");
    chmod(p, 0555);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_IO);
    CHECK(strstr(err.message, "Permission denied") != NULL);
    chmod(p, 0755);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_ABSENT);
    CHECK(count_temp_files() == 0);

    /* Unreadable var/lib/lpm: open fails with an I/O error. */
    at(p, sizeof(p), "var/lib/lpm");
    chmod(p, 0);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_ERR_IO);
    chmod(p, 0755);
    CHECK(run_check(NULL).n == 0);
}

/* ==================================================================== */
/* File ownership                                                        */
/* ==================================================================== */

static void test_ownership_conflicts_rejected(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);

    CHECK(do_register("name=impostor\nversion=1\n", "/usr/bin/hello\n", &err)
          == LPM_ERR_CONFLICT);
    CHECK(strstr(err.message, "already owned by package 'hello'") != NULL);
    /* A file where hello needs a directory, and vice versa. */
    CHECK(do_register("name=impostor\nversion=1\n", "/usr/share/doc/hello\n", &err)
          == LPM_ERR_CONFLICT);
    CHECK(do_register("name=impostor\nversion=1\n", "/usr/bin/hello/x\n", &err)
          == LPM_ERR_CONFLICT);
    CHECK(pkg_state("impostor", "", "") == ST_ABSENT);
    CHECK(count_temp_files() == 0);

    /* Neighbouring but distinct paths are fine. */
    CHECK(do_register("name=friend\nversion=1\n",
                      "/usr/bin/hello2\n/usr/share/doc/hello-extra\n", &err) == LPM_OK);
    CHECK(run_check(NULL).n == 0);
}

static void test_damaged_list_blocks_registration(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    write_text("var/lib/lpm/files/hello.list", "/usr/bin/hello\n../evil\n");
    /* Ownership cannot be verified, so the database refuses (fail closed). */
    CHECK(do_register("name=other\nversion=1\n", "/usr/bin/other\n", &err) == LPM_ERR_INVALID);
    CHECK(strstr(err.message, "cannot verify file ownership") != NULL);
    CHECK(pkg_state("other", "", "") == ST_ABSENT);
}

static void test_orphan_list_is_replaced(void)
{
    lpm_meta_error err;
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    /* As left by a crash between the two steps of a registration. */
    write_text("var/lib/lpm/files/hello.list", "/old/path\n");
    r = run_check(NULL);
    CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_ORPHAN_FILE_LIST));
    /* Orphans own nothing: another package may claim the same path. */
    CHECK(do_register("name=other\nversion=1\n", "/old/path\n", &err) == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_REGISTERED);
    CHECK(run_check(NULL).n == 0);
}

/* ==================================================================== */
/* Atomicity and failure handling                                        */
/* ==================================================================== */

static int fault_errno_for(fault_kind k)
{
    switch (k) {
    case F_WRITE:  return ENOSPC;
    case F_OPENAT: return EMFILE;
    case F_FCHMOD: return EPERM;
    case F_FLOCK:  return ENOLCK;
    default:       return EIO;
    }
}

/*
 * The core atomicity test: for every system call (and allocation) that a
 * registration performs, make exactly that one fail, then verify that
 * the package is either completely absent or completely registered,
 * that the error was reported, that no temporary file remains and that
 * the consistency check finds nothing wrong.
 */
static void test_fault_injection_register(void)
{
    int k, points = 0;

    new_root();
    CHECK(init_db() == LPM_OK);
    {
        lpm_meta_error err;
        /* An existing package, so ownership collection is exercised. */
        CHECK(do_register("name=libfoo\nversion=1.0\n", "/usr/lib/libfoo.so\n", &err) == LPM_OK);
    }

    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 500; n++) {
            lpm_meta_error err;
            lpm_status rc;
            int st;

            fault_arm((fault_kind)k, n, fault_errno_for((fault_kind)k));
            rc = do_register(HELLO_META, HELLO_LIST, &err);
            fault_reset();
            st = pkg_state("hello", HELLO_META, HELLO_LIST);

            if (!fault_fired) {          /* no Nth call: the operation is done */
                CHECK(rc == LPM_OK && st == ST_REGISTERED);
                CHECK(do_unregister("hello", &err) == LPM_OK);   /* next kind */
                break;
            }
            points++;
            if (tf_verbose)
                printf("      %s #%ld -> %s, %s\n", fault_names[k], n,
                       lpm_status_str(rc), state_names[st]);
            CHECK(st == ST_ABSENT || st == ST_REGISTERED);
            if (st == ST_ABSENT)
                CHECK(rc != LPM_OK && err.message[0] != '\0');
            if (st == ST_REGISTERED && rc != LPM_OK)   /* committed, flush failed */
                CHECK(strstr(err.message, "not flushed") != NULL);
            CHECK(count_temp_files() == 0);
            CHECK(run_check(NULL).n == 0);
            if (st == ST_REGISTERED)
                CHECK(do_unregister("hello", &err) == LPM_OK);
        }
    }
    if (tf_verbose)
        printf("      %d injected failures\n", points);
    CHECK(points >= 30);   /* the loop really explored the error paths */
}

/* Same for removal: registered, absent, or (only after an error) absent
 * with an orphaned file list that the check reports. */
static void test_fault_injection_unregister(void)
{
    int k, points = 0;
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 500; n++) {
            lpm_status rc;
            int st;

            CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
            fault_arm((fault_kind)k, n, fault_errno_for((fault_kind)k));
            rc = do_unregister("hello", &err);
            fault_reset();
            st = pkg_state("hello", HELLO_META, HELLO_LIST);

            if (!fault_fired) {
                CHECK(rc == LPM_OK && st == ST_ABSENT);
                break;
            }
            points++;
            CHECK(st == ST_ABSENT || st == ST_REGISTERED || st == ST_ORPHAN);
            if (st == ST_REGISTERED)
                CHECK(rc != LPM_OK);
            if (st == ST_ORPHAN) {
                check_result r = run_check(NULL);
                CHECK(rc == LPM_ERR_IO);
                CHECK(strstr(err.message, "orphaned") != NULL);
                CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_ORPHAN_FILE_LIST));
                unlink(strcat(strcpy((char[1024]){0}, root),
                              "/var/lib/lpm/files/hello.list"));
            } else {
                CHECK(run_check(NULL).n == 0);
            }
            if (pkg_state("hello", HELLO_META, HELLO_LIST) == ST_REGISTERED)
                CHECK(do_unregister("hello", &err) == LPM_OK);
        }
    }
    CHECK(points >= 15);
}

static void test_short_writes_and_eintr(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    fault_reset();
    short_writes = 1;    /* every write() moves only 1-3 bytes */
    eintr_mode = 1;      /* and every other write/fsync/flock is interrupted */
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    fault_reset();
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_REGISTERED);
    CHECK(count_temp_files() == 0);
}

static void test_failed_write_leaves_old_state(void)
{
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    /* Disk full while writing the record (2nd write = the .meta). */
    fault_arm(F_WRITE, 1, ENOSPC);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_IO);
    fault_reset();
    CHECK(strstr(err.message, "No space") != NULL);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_ABSENT);  /* list undone */

    /* rename of the record fails: the list written before it is undone. */
    fault_arm(F_RENAMEAT, 1, EIO);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_IO);
    fault_reset();
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_ABSENT);
    CHECK(count_temp_files() == 0);

    /* fsync of the new record fails: never renamed into place. */
    fault_arm(F_FSYNC, 2, EIO);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_ERR_IO);
    fault_reset();
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_ABSENT);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
}

/*
 * Crash consistency: a child process registers a package and is killed
 * (_exit, no cleanup at all) at its Nth system call, for every N. The
 * parent then inspects what is on disk. This simulates the process
 * dying (kill -9, OOM killer, segfault) at any point; it cannot simulate
 * a power cut, which also loses unflushed kernel buffers (that is what
 * the fsync calls are for).
 */
static int crash_child(long n, int unregister)
{
    pid_t pid;
    int status;

    fflush(NULL);
    pid = fork();
    if (pid == 0) {
        lpm_meta_error err;
        lpm_status rc;
        fault_reset();
        crash_at = n;
        rc = unregister ? do_unregister("hello", &err)
                        : do_register(HELLO_META, HELLO_LIST, &err);
        _exit(rc == LPM_OK ? 0 : 1);
    }
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static void test_crash_during_register(void)
{
    long n;
    int crashes = 0;
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    for (n = 0; n < 400; n++) {
        int code = crash_child(n, 0);
        int st = pkg_state("hello", HELLO_META, HELLO_LIST);
        check_result r = run_check(NULL);
        lpm_db db;

        CHECK(code == 0 || code == 77);
        CHECK(st == ST_ABSENT || st == ST_REGISTERED || st == ST_ORPHAN);
        /* Only harmless leftovers, and the check names every one. */
        CHECK((r.kinds & ~(KIND(LPM_CHECK_STALE_TEMP) |
                           KIND(LPM_CHECK_ORPHAN_FILE_LIST))) == 0);
        CHECK((st == ST_ORPHAN) == ((r.kinds & KIND(LPM_CHECK_ORPHAN_FILE_LIST)) != 0));
        CHECK((count_temp_files() > 0) == ((r.kinds & KIND(LPM_CHECK_STALE_TEMP)) != 0));
        /* The dead process's lock was released by the kernel. */
        CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
        lpm_db_close(&db);
        if (code == 0) {
            CHECK(st == ST_REGISTERED);
            break;
        }
        crashes++;
        /* Recovery: a new registration succeeds after any crash. */
        remove_temp_files();
        if (st != ST_REGISTERED)
            CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
        CHECK(run_check(NULL).n == 0);
        CHECK(do_unregister("hello", &err) == LPM_OK);
    }
    if (tf_verbose)
        printf("      %d crash points\n", crashes);
    CHECK(crashes >= 20);
}

static void test_crash_during_unregister(void)
{
    long n;
    int crashes = 0;
    lpm_meta_error err;

    new_root();
    CHECK(init_db() == LPM_OK);
    for (n = 0; n < 400; n++) {
        int code, st;
        check_result r;

        CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
        code = crash_child(n, 1);
        st = pkg_state("hello", HELLO_META, HELLO_LIST);
        r = run_check(NULL);
        CHECK(code == 0 || code == 77);
        CHECK(st == ST_ABSENT || st == ST_REGISTERED || st == ST_ORPHAN);
        CHECK((r.kinds & ~KIND(LPM_CHECK_ORPHAN_FILE_LIST)) == 0);
        if (code == 0) {
            CHECK(st == ST_ABSENT);
            break;
        }
        crashes++;
        if (st == ST_REGISTERED)
            CHECK(do_unregister("hello", &err) == LPM_OK);
        else if (st == ST_ORPHAN)
            unlink(strcat(strcpy((char[1024]){0}, root), "/var/lib/lpm/files/hello.list"));
    }
    CHECK(crashes >= 5);
}

static void test_stale_temp_files(void)
{
    lpm_meta_error err;
    lpm_db_list list;
    int db_exists;
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    /* Half-written temporaries, as left by a crash. */
    write_text("var/lib/lpm/installed/.lpm-tmp.hello.meta.4242.0", "name=hel");
    write_text("var/lib/lpm/files/.lpm-tmp.hello.list.4242.0", "/usr/b");

    CHECK(lpm_db_list_installed(&cfg, &list, &db_exists) == LPM_OK);
    CHECK(list.count == 0);                  /* never mistaken for a record */
    lpm_db_list_free(&list);
    r = run_check(NULL);
    CHECK(r.n == 2 && r.kinds == KIND(LPM_CHECK_STALE_TEMP));
    CHECK(count_temp_files() == 2);          /* the check deletes nothing */

    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    CHECK(pkg_state("hello", HELLO_META, HELLO_LIST) == ST_REGISTERED);
}

static void test_allocation_failures_in_check(void)
{
    lpm_meta_error err;
    long n;
    int done = 0;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register(HELLO_META, HELLO_LIST, &err) == LPM_OK);
    CHECK(do_register("name=libfoo\nversion=1\n", "/usr/lib/libfoo.so\n", &err) == LPM_OK);
    write_text("var/lib/lpm/installed/broken.meta", "name=broken\n");

    for (n = 0; n < 500 && !done; n++) {
        lpm_check_summary sum;
        lpm_db db;
        lpm_status rc;

        CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
        fault_arm(F_ALLOC, n, 0);
        rc = lpm_db_check(&db, NULL, NULL, &sum, &err);
        fault_reset();
        lpm_db_close(&db);
        if (!fault_fired) {
            CHECK(rc == LPM_OK);
            done = 1;
        } else {
            CHECK(rc == LPM_ERR_NOMEM);   /* never a false "consistent" */
        }
    }
    CHECK(done);
}

/* ==================================================================== */
/* Locking                                                               */
/* ==================================================================== */

static void test_lock_excludes_writers(void)
{
    lpm_meta_error err;
    lpm_db a, b;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &a, &err) == LPM_OK);
    /* flock() locks belong to the open file, so even this process's
     * second handle is excluded. */
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &b, &err) == LPM_ERR_BUSY);
    CHECK(strstr(err.message, "locked by another LPM process") != NULL);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &b, &err) == LPM_ERR_BUSY);
    lpm_db_close(&a);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &b, &err) == LPM_OK);
    lpm_db_close(&b);

    /* Readers share. */
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &a, &err) == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &b, &err) == LPM_OK);
    lpm_db_close(&b);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &b, &err) == LPM_ERR_BUSY);
    lpm_db_close(&a);
}

static void test_lock_wait_times_out(void)
{
    lpm_meta_error err;
    lpm_db a, b;
    double t0, elapsed;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &a, &err) == LPM_OK);
    t0 = now_ms();
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 300, &b, &err) == LPM_ERR_BUSY);
    elapsed = now_ms() - t0;
    CHECK(elapsed >= 250 && elapsed < 5000);   /* waited, but boundedly */
    lpm_db_close(&a);
}

static void test_lock_failure_is_an_error(void)
{
    lpm_meta_error err;
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    fault_arm(F_FLOCK, 0, ENOLCK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_IO);
    fault_reset();
    CHECK(db.lock_fd == -1 && db.installed_fd == -1);   /* never proceeds unlocked */
}

static void test_lock_released_when_holder_dies(void)
{
    lpm_meta_error err;
    int fds[2];
    char c;
    pid_t pid;
    lpm_db db;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(pipe(fds) == 0);
    fflush(NULL);
    pid = fork();
    if (pid == 0) {
        lpm_db held;
        close(fds[0]);
        if (lpm_db_open(&cfg, LPM_DB_WRITE, 0, &held, &err) == LPM_OK)
            (void)!write(fds[1], "L", 1);
        for (;;)
            pause();   /* hold the lock until killed */
    }
    close(fds[1]);
    CHECK(read(fds[0], &c, 1) == 1);
    close(fds[0]);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_ERR_BUSY);
    kill(pid, SIGKILL);              /* crash while holding the lock */
    waitpid(pid, NULL, 0);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
    lpm_db_close(&db);
}

/* Start `n` children at the same moment; each runs fn(i). Returns the
 * number of children whose exit status was `want`. */
static int race(int n, int (*fn)(int), int *codes)
{
    int go[2], i;
    pid_t pids[16];
    char c;

    if (pipe(go) != 0)
        return -1;
    fflush(NULL);
    for (i = 0; i < n; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            close(go[1]);
            (void)!read(go[0], &c, 1);   /* returns 0 when the parent closes */
            _exit(fn(i));
        }
    }
    close(go[0]);
    close(go[1]);                         /* release them all at once */
    for (i = 0; i < n; i++) {
        int status = 0;
        waitpid(pids[i], &status, 0);
        codes[i] = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    return 0;
}

static int register_distinct(int i)
{
    char meta[64], list[64];
    lpm_package pkg;
    lpm_file_list files;
    lpm_meta_error err;
    lpm_db db;
    lpm_status rc;

    snprintf(meta, sizeof(meta), "name=pkg%d\nversion=1.%d\n", i, i);
    snprintf(list, sizeof(list), "/usr/bin/pkg%d\n", i);
    lpm_metadata_parse_buffer(meta, strlen(meta), LPM_META_INSTALLED, &pkg, &err);
    lpm_file_list_parse_buffer(list, strlen(list), &files, &err);
    rc = lpm_db_open(&cfg, LPM_DB_WRITE, 20000, &db, &err);   /* wait our turn */
    if (rc == LPM_OK) {
        rc = lpm_db_register_package(&db, &pkg, &files, &err);
        lpm_db_close(&db);
    }
    return (int)rc;
}

static int register_same(int i)
{
    char meta[64];
    lpm_package pkg;
    lpm_meta_error err;
    lpm_db db;
    lpm_status rc;

    snprintf(meta, sizeof(meta), "name=same\nversion=%d\n", i + 1);
    lpm_metadata_parse_buffer(meta, strlen(meta), LPM_META_INSTALLED, &pkg, &err);
    rc = lpm_db_open(&cfg, LPM_DB_WRITE, 20000, &db, &err);
    if (rc == LPM_OK) {
        rc = lpm_db_register_package(&db, &pkg, NULL, &err);
        lpm_db_close(&db);
    }
    return (int)rc;
}

static int register_shared_file(int i)
{
    char meta[64];
    lpm_package pkg;
    lpm_file_list files;
    lpm_meta_error err;
    lpm_db db;
    lpm_status rc;

    snprintf(meta, sizeof(meta), "name=claim%d\nversion=1\n", i);
    lpm_metadata_parse_buffer(meta, strlen(meta), LPM_META_INSTALLED, &pkg, &err);
    lpm_file_list_parse_buffer("/usr/bin/shared\n", 16, &files, &err);
    rc = lpm_db_open(&cfg, LPM_DB_WRITE, 20000, &db, &err);
    if (rc == LPM_OK) {
        rc = lpm_db_register_package(&db, &pkg, &files, &err);
        lpm_db_close(&db);
    }
    return (int)rc;
}

static void test_concurrent_registration(void)
{
    enum { N = 8 };
    int codes[N], i, ok, exists, conflict;
    lpm_db_list list;
    int db_exists;
    lpm_check_summary sum;

    new_root();
    CHECK(init_db() == LPM_OK);

    /* 8 processes, 8 different packages: all must succeed, none lost. */
    CHECK(race(N, register_distinct, codes) == 0);
    for (i = 0; i < N; i++)
        CHECK(codes[i] == LPM_OK);
    CHECK(lpm_db_list_installed(&cfg, &list, &db_exists) == LPM_OK);
    CHECK(list.count == N);
    lpm_db_list_free(&list);

    /* 8 processes, the same name: exactly one wins. */
    CHECK(race(N, register_same, codes) == 0);
    ok = exists = 0;
    for (i = 0; i < N; i++) {
        ok += codes[i] == LPM_OK;
        exists += codes[i] == LPM_ERR_EXISTS;
    }
    CHECK(ok == 1 && exists == N - 1);

    /* 8 processes claiming the same file: exactly one owner. */
    CHECK(race(N, register_shared_file, codes) == 0);
    ok = conflict = 0;
    for (i = 0; i < N; i++) {
        ok += codes[i] == LPM_OK;
        conflict += codes[i] == LPM_ERR_CONFLICT;
    }
    CHECK(ok == 1 && conflict == N - 1);

    CHECK(run_check(&sum).n == 0);
    CHECK(sum.packages == N + 2 && count_temp_files() == 0);
}

/* ==================================================================== */
/* Consistency check                                                     */
/* ==================================================================== */

static void test_check_clean_database(void)
{
    lpm_meta_error err;
    lpm_check_summary sum;
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register("name=libfoo\nversion=1.10\n", "/usr/lib/libfoo.so\n", &err) == LPM_OK);
    CHECK(do_register("name=libbar\nversion=2.1.0\n", "/usr/lib/libbar.so\n", &err) == LPM_OK);
    CHECK(do_register(HELLO_DEPS_META, HELLO_LIST, &err) == LPM_OK); /* libfoo>=1.0, libbar=2.1 */
    r = run_check(&sum);
    CHECK(r.n == 0);
    CHECK(sum.records == 3 && sum.packages == 3 && sum.owned_files == 4 && sum.problems == 0);
}

/* Snapshot of every name and size in the database, to prove that the
 * check changes nothing. */
static void snapshot(char *buf, size_t size)
{
    static const char *const dirs[] = { "var/lib/lpm/installed", "var/lib/lpm/files" };
    size_t i, pos = 0;

    buf[0] = '\0';
    for (i = 0; i < 2; i++) {
        char p[1024];
        DIR *d;
        struct dirent *de;
        at(p, sizeof(p), dirs[i]);
        d = opendir(p);
        while (d && (de = readdir(d)) != NULL) {
            char f[1400];
            struct stat st;
            snprintf(f, sizeof(f), "%s/%s", p, de->d_name);
            lstat(f, &st);
            pos += (size_t)snprintf(buf + pos, size - pos, "%s:%ld;", de->d_name,
                                    (long)st.st_size);
            if (pos >= size)
                pos = size - 1;
        }
        if (d)
            closedir(d);
    }
}

static void test_check_detects_problems(void)
{
    char lnk[1024], before[4096], after[4096];
    lpm_meta_error err;
    lpm_check_summary sum;
    check_result r;
    unsigned want;

    new_root();
    CHECK(init_db() == LPM_OK);
    CHECK(do_register("name=libfoo\nversion=1.0\n", "/usr/lib/libfoo.so\n", &err) == LPM_OK);
    CHECK(do_register("name=good\nversion=1\ndepends=libfoo>=1.0\n", "/usr/bin/good\n", &err) == LPM_OK);

    write_text("var/lib/lpm/installed/broken.meta", "name=broken\nversion=1..2\n");   /* BAD_RECORD */
    write_text("var/lib/lpm/files/broken.list", "");
    write_text("var/lib/lpm/installed/liar.meta", "name=other\nversion=1\n");         /* BAD_RECORD */
    write_text("var/lib/lpm/files/liar.list", "");
    at(lnk, sizeof(lnk), "var/lib/lpm/installed/link.meta");
    CHECK(symlink("good.meta", lnk) == 0);                                          /* UNEXPECTED */
    write_text("var/lib/lpm/installed/notes.txt", "hi\n");                           /* UNEXPECTED */
    write_text("var/lib/lpm/installed/.lpm-tmp.x.meta.1.0", "na");                   /* STALE_TEMP */
    write_text("var/lib/lpm/files/ghost.list", "/usr/bin/ghost\n");                  /* ORPHAN */
    write_text("var/lib/lpm/installed/nolist.meta", "name=nolist\nversion=1\n");     /* MISSING_LIST */
    write_text("var/lib/lpm/installed/badlist.meta", "name=badlist\nversion=1\n");
    write_text("var/lib/lpm/files/badlist.list", "/usr/../etc/passwd\n");            /* BAD_FILE_LIST */
    /* Two lists claiming one file, written behind the database's back. */
    write_text("var/lib/lpm/installed/dup.meta", "name=dup\nversion=1\n");
    write_text("var/lib/lpm/files/dup.list", "/usr/bin/good\n");                     /* CONFLICT */
    /* Dependencies: one missing, one too old, one exact mismatch. */
    write_text("var/lib/lpm/installed/needy.meta",
               "name=needy\nversion=1\ndepends=missing>=1\ndepends=libfoo>=2.0\n"
               "depends=good=2\n");                                                 /* UNSATISFIED x3 */
    write_text("var/lib/lpm/files/needy.list", "");

    snapshot(before, sizeof(before));
    r = run_check(&sum);
    snapshot(after, sizeof(after));

    want = KIND(LPM_CHECK_BAD_RECORD) | KIND(LPM_CHECK_UNEXPECTED_ENTRY) |
           KIND(LPM_CHECK_STALE_TEMP) | KIND(LPM_CHECK_MISSING_FILE_LIST) |
           KIND(LPM_CHECK_BAD_FILE_LIST) | KIND(LPM_CHECK_ORPHAN_FILE_LIST) |
           KIND(LPM_CHECK_FILE_CONFLICT) | KIND(LPM_CHECK_UNSATISFIED_DEPENDENCY);
    CHECK(r.kinds == want);
    CHECK(r.n == 12);   /* 2+2+1+1+1+1+1+3, each problem exactly once */
    CHECK(sum.problems == r.n);
    CHECK(sum.records == 8);
    CHECK(strcmp(before, after) == 0);   /* nothing repaired or deleted */
}

/* ==================================================================== */
/* Resource bounds                                                       */
/* ==================================================================== */

static void test_register_maximum_file_count(void)
{
    lpm_meta_error err;
    lpm_package pkg;
    lpm_file_list files, back;
    lpm_db db;
    size_t i;

    new_root();
    CHECK(init_db() == LPM_OK);
    pkg = make_pkg("name=big\nversion=1\n");
    lpm_file_list_init(&files);
    for (i = 0; i < LPM_FILES_MAX_ENTRIES; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/usr/share/big/%05zu", i);
        if (lpm_file_list_add(&files, p, &err) != LPM_OK)
            break;
    }
    CHECK(files.count == LPM_FILES_MAX_ENTRIES);
    CHECK(lpm_file_list_finalize(&files, &err) == LPM_OK);
    CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_register_package(&db, &pkg, &files, &err) == LPM_OK);
    CHECK(lpm_db_read_file_list(&db, "big", &back, &err) == LPM_OK);
    CHECK(back.count == LPM_FILES_MAX_ENTRIES);
    lpm_file_list_free(&back);
    lpm_db_close(&db);
    lpm_file_list_free(&files);
    lpm_package_free(&pkg);
}

static void test_oversized_and_binary_records(void)
{
    lpm_meta_error err;
    lpm_file_list l;
    lpm_db db;
    check_result r;
    size_t len = (size_t)LPM_FILES_MAX_SIZE + 1, n = 0;
    char *big = malloc(len);

    new_root();
    CHECK(init_db() == LPM_OK);
    /* One byte over the file-list size limit. */
    while (n + 3 <= len) {
        memcpy(big + n, "/a\n", 3);
        n += 3;
    }
    memset(big + n, 'b', len - n);
    write_text("var/lib/lpm/installed/huge.meta", "name=huge\nversion=1\n");
    write_at("var/lib/lpm/files/huge.list", big, len);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_read_file_list(&db, "huge", &l, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_FILE_TOO_LARGE);
    lpm_db_close(&db);
    free(big);

    /* Binary garbage in a record and in a list. */
    write_at("var/lib/lpm/installed/bin.meta", "name=bin\n\x00\xff\x01version=1\n", 21);
    write_at("var/lib/lpm/files/bin.list", "/usr/\xff\x00\n", 8);
    r = run_check(NULL);
    CHECK(r.kinds == (KIND(LPM_CHECK_BAD_RECORD) | KIND(LPM_CHECK_BAD_FILE_LIST)));
    CHECK(r.n == 3);   /* huge.list, bin.meta and bin.list */
}

static void test_oversized_metadata_record(void)
{
    char *big = malloc(LPM_META_MAX_FILE_SIZE + 2);
    check_result r;

    new_root();
    CHECK(init_db() == LPM_OK);
    memset(big, '#', LPM_META_MAX_FILE_SIZE + 1);
    big[LPM_META_MAX_FILE_SIZE] = '\n';
    write_at("var/lib/lpm/installed/fat.meta", big, LPM_META_MAX_FILE_SIZE + 1);
    write_text("var/lib/lpm/files/fat.list", "");
    r = run_check(NULL);
    CHECK(r.n == 1 && r.kinds == KIND(LPM_CHECK_BAD_RECORD));
    free(big);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    fault_reset();
    umask(022);   /* the tests assert on the modes of files they create */

    printf("Running database unit tests\n");
    RUN(test_init_creates_layout);
    RUN(test_open_uninitialised);
    RUN(test_register_and_load);
    RUN(test_register_without_file_list);
    RUN(test_duplicate_registration);
    RUN(test_unregister);
    RUN(test_list_multiple_sorted);
    RUN(test_roots_are_isolated);
    RUN(test_legacy_database_upgrade);
    RUN(test_read_handle_cannot_write);
    RUN(test_invalid_names);
    RUN(test_invalid_metadata_not_written);
    RUN(test_invalid_file_list_not_written);
    RUN(test_unexpected_directory_entries);
    RUN(test_symlinked_database_directories);
    RUN(test_symlinked_records);
    RUN(test_untrusted_permissions);
    RUN(test_untrusted_owner);
    RUN(test_inaccessible_database);
    RUN(test_ownership_conflicts_rejected);
    RUN(test_damaged_list_blocks_registration);
    RUN(test_orphan_list_is_replaced);
    RUN(test_fault_injection_register);
    RUN(test_fault_injection_unregister);
    RUN(test_short_writes_and_eintr);
    RUN(test_failed_write_leaves_old_state);
    RUN(test_crash_during_register);
    RUN(test_crash_during_unregister);
    RUN(test_stale_temp_files);
    RUN(test_allocation_failures_in_check);
    RUN(test_lock_excludes_writers);
    RUN(test_lock_wait_times_out);
    RUN(test_lock_failure_is_an_error);
    RUN(test_lock_released_when_holder_dies);
    RUN(test_concurrent_registration);
    RUN(test_check_clean_database);
    RUN(test_check_detects_problems);
    RUN(test_register_maximum_file_count);
    RUN(test_oversized_and_binary_records);
    RUN(test_oversized_metadata_record);

    if (root[0] != '\0')
        rm_tree(root);
    return tf_summary();
}
