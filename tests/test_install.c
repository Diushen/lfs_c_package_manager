/*
 * test_install.c - Package verification and installation (Milestone 4).
 *
 * Builds real .lpm packages (tar + metadata.txt + manifest.txt +
 * payload/) with libarchive's write API, including tampered and
 * malicious ones, installs them into throw-away roots and inspects the
 * result on disk: the files, the database, the staging area and the
 * directory *next to* the root (which must never receive anything).
 *
 * Fault injection works as in test_database.c (GNU ld --wrap); linkat
 * and symlinkat are wrapped too, because the installer uses them to
 * place files. A forked child is also "crashed" at every system call.
 */
#include "database.h"
#include "filelist.h"
#include "install.h"
#include "integrity.h"
#include "metadata.h"
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
/* Fault injection (same model as test_database.c)                       */
/* ==================================================================== */

typedef enum {
    F_NONE, F_ALLOC, F_WRITE, F_FSYNC, F_RENAMEAT, F_OPENAT, F_UNLINKAT,
    F_MKDIRAT, F_FCHMOD, F_CLOSE, F_FLOCK, F_LINKAT, F_SYMLINKAT, F_KINDS
} fault_kind;

static const char *const fault_names[F_KINDS] = {
    "none", "malloc", "write", "fsync", "renameat", "openat", "unlinkat",
    "mkdirat", "fchmod", "close", "flock", "linkat", "symlinkat",
};

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
        __real_close(fd);   /* Linux: the descriptor is gone anyway */
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

/* Payload entry: path below the root ("/usr/bin/hello"). */
typedef struct {
    const char *path;
    char type;          /* f file, d dir, l symlink, h hardlink, p fifo */
    const char *data;   /* content or link target */
    unsigned mode;
} pentry;

/* Ways to damage a package, all default to "intact". */
typedef struct {
    const char *manifest;        /* use this manifest text instead     */
    const char *metadata;        /* use this exact metadata.txt        */
    const char *tamper_path;     /* this file's archive bytes differ   */
    const char *skip_path;       /* leave this entry out of the archive */
    const char *extra_name;      /* append a raw archive file entry    */
    const char *rename_from;     /* store this payload entry ...       */
    const char *rename_to;       /* ... under this raw archive name    */
    int duplicate_first;         /* store the first file entry twice   */
    int manifest_first;          /* swap metadata.txt / manifest.txt   */
    int filter;                  /* 0 none, 1 gzip, 2 xz               */
} damage;

static const damage INTACT = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 2 };

static char base[512], root[600], outside[600], pkgfile[600];
static lpm_config cfg;

static void add_raw(struct archive *a, const char *name, char type, const char *data,
                    unsigned mode)
{
    struct archive_entry *e = archive_entry_new();
    size_t len = (type == 'f' && data) ? strlen(data) : 0;

    archive_entry_set_pathname(e, name);
    archive_entry_set_perm(e, mode ? mode : 0644);
    archive_entry_set_size(e, (la_int64_t)len);
    switch (type) {
    case 'd': archive_entry_set_filetype(e, AE_IFDIR); break;
    case 'l': archive_entry_set_filetype(e, AE_IFLNK); archive_entry_set_symlink(e, data); break;
    case 'h': archive_entry_set_filetype(e, AE_IFREG); archive_entry_set_hardlink(e, data); break;
    case 'p': archive_entry_set_filetype(e, AE_IFIFO); break;
    default:  archive_entry_set_filetype(e, AE_IFREG); break;
    }
    archive_write_header(a, e);
    if (len > 0)
        archive_write_data(a, data, len);
    archive_entry_free(e);
}

static char *manifest_for(const pentry *p, size_t n)
{
    size_t cap = 4096 + n * 1200, pos = 0, i;
    char *m = malloc(cap);
    lpm_meta_error err;

    m[0] = '\0';
    for (i = 0; i < n; i++) {
        char hex[65];
        switch (p[i].type) {
        case 'f':
            lpm_sha256_buffer(p[i].data, strlen(p[i].data), hex, &err);
            pos += (size_t)snprintf(m + pos, cap - pos, "file %s %04o %s\n", hex,
                                    p[i].mode ? p[i].mode : 0644, p[i].path);
            break;
        case 'd':
            pos += (size_t)snprintf(m + pos, cap - pos, "dir %04o %s\n",
                                    p[i].mode ? p[i].mode : 0755, p[i].path);
            break;
        case 'l':
            pos += (size_t)snprintf(m + pos, cap - pos, "symlink %s %s\n", p[i].data,
                                    p[i].path);
            break;
        default:   /* hard links / fifos: listed as files, never valid */
            pos += (size_t)snprintf(m + pos, cap - pos, "file %064d 0644 %s\n", 0,
                                    p[i].path);
            break;
        }
    }
    return m;
}

/* Build pkgfile from metadata (without manifest_sha256) + payload. */
static void build_pkg(const char *meta, const pentry *p, size_t n, const damage *d)
{
    struct archive *a = archive_write_new();
    char *manifest = d->manifest ? NULL : manifest_for(p, n);
    const char *mtext = d->manifest ? d->manifest : manifest;
    char hex[65], metadata[4096];
    lpm_meta_error err;
    size_t i;
    int first_file_done = 0;

    lpm_sha256_buffer(mtext, strlen(mtext), hex, &err);
    if (d->metadata)
        snprintf(metadata, sizeof(metadata), "%s", d->metadata);
    else
        snprintf(metadata, sizeof(metadata), "%smanifest_sha256=%s\n", meta, hex);

    archive_write_set_format_pax_restricted(a);
    if (d->filter == 1)
        archive_write_add_filter_gzip(a);
    else if (d->filter == 2)
        archive_write_add_filter_xz(a);
    archive_write_open_filename(a, pkgfile);
    if (d->manifest_first) {
        add_raw(a, "manifest.txt", 'f', mtext, 0644);
        add_raw(a, "metadata.txt", 'f', metadata, 0644);
    } else {
        add_raw(a, "metadata.txt", 'f', metadata, 0644);
        add_raw(a, "manifest.txt", 'f', mtext, 0644);
    }
    add_raw(a, "payload/", 'd', NULL, 0755);
    for (i = 0; i < n; i++) {
        char name[1200];
        const char *data = p[i].data;

        if (d->skip_path && strcmp(d->skip_path, p[i].path) == 0)
            continue;
        if (d->rename_from && strcmp(d->rename_from, p[i].path) == 0)
            snprintf(name, sizeof(name), "%s", d->rename_to);
        else
            snprintf(name, sizeof(name), "payload%s%s", p[i].path,
                     p[i].type == 'd' ? "/" : "");
        if (d->tamper_path && strcmp(d->tamper_path, p[i].path) == 0)
            data = "TAMPERED CONTENT\n";
        add_raw(a, name, p[i].type, data, p[i].mode);
        if (d->duplicate_first && p[i].type == 'f' && !first_file_done) {
            add_raw(a, name, p[i].type, data, p[i].mode);
            first_file_done = 1;
        }
    }
    if (d->extra_name)
        add_raw(a, d->extra_name, 'f', "extra\n", 0644);
    archive_write_close(a);
    archive_write_free(a);
    free(manifest);
}

static const char HELLO_META[] =
    "name=hello\nversion=1.2.0\ndescription=Hello demo package\n";
static const pentry HELLO[] = {
    { "/usr/bin/hello", 'f', "#!/bin/sh\necho hello\n", 0755 },
    { "/usr/bin/hi", 'l', "hello", 0 },
    { "/etc/hello.conf", 'f', "greeting=hello\n", 0644 },
    { "/usr/share/doc/hello/README", 'f', "Hello, world.\n", 0644 },
    { "/usr/share/hello/empty", 'd', NULL, 0755 },
};
#define NHELLO (sizeof(HELLO) / sizeof(HELLO[0]))

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
    snprintf(base, sizeof(base), "%s/lpm-insttest-XXXXXX", (t && *t) ? t : "/tmp");
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(root, sizeof(root), "%s/root", base);
    snprintf(outside, sizeof(outside), "%s/outside", base);
    snprintf(pkgfile, sizeof(pkgfile), "%s/hello.lpm", base);
    mkdir(root, 0755);
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

static int open_fds(void) { return count_entries("/proc/self/fd"); }

static int exists_in(const char *dir, const char *rel)
{
    char p[1400];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, rel);
    return lstat(p, &st) == 0;
}

static int file_is(const char *rel, const char *content)
{
    char p[1400], buf[512];
    FILE *f;
    size_t n;
    snprintf(p, sizeof(p), "%s%s", root, rel);
    f = fopen(p, "rb");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strcmp(buf, content) == 0;
}

static mode_t mode_of(const char *rel)
{
    char p[1400];
    struct stat st;
    snprintf(p, sizeof(p), "%s%s", root, rel);
    return lstat(p, &st) == 0 ? st.st_mode : 0;
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

static int staging_entries(void)
{
    char p[700];
    snprintf(p, sizeof(p), "%s/var/lib/lpm/staging", root);
    return count_entries(p);
}

/* The root holds nothing but the (possibly created) database. */
static int root_untouched(void)
{
    int n = count_entries(root);
    return n == 0 || (n == 1 && exists_in(root, "var") && count_entries(outside) == 0 &&
                      !exists_in(root, "usr") && !exists_in(root, "etc"));
}

/* Fully installed: record plus every payload object, exact content. */
static int fully_installed(void)
{
    return registered("hello") &&
           file_is("/usr/bin/hello", "#!/bin/sh\necho hello\n") &&
           file_is("/etc/hello.conf", "greeting=hello\n") &&
           file_is("/usr/share/doc/hello/README", "Hello, world.\n") &&
           S_ISLNK(mode_of("/usr/bin/hi")) &&
           S_ISDIR(mode_of("/usr/share/hello/empty"));
}

static lpm_status install(const char *expected, lpm_meta_error *err)
{
    lpm_install_options opt = { expected, false, 0 };
    lpm_pkg_summary s;
    lpm_status rc = lpm_install_package(&cfg, pkgfile, &opt, &s, err);
    if (tf_verbose && rc != LPM_OK)
        printf("      rejected (%s): %s\n", lpm_status_str(rc), err->message);
    return rc;
}

typedef struct { unsigned kinds; size_t n; } check_result;

static void collect(void *ctx, lpm_check_kind kind, const char *s, const char *d)
{
    check_result *r = ctx;
    (void)s; (void)d;
    r->kinds |= 1u << kind;
    r->n++;
}

static check_result run_check(void)
{
    check_result r = { 0, 0 };
    lpm_check_summary sum;
    lpm_meta_error err;
    lpm_db db;
    if (lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK) {
        if (lpm_db_check(&db, collect, &r, &sum, &err) != LPM_OK)
            r.n = (size_t)-1;
        lpm_db_close(&db);
    }
    return r;
}

/* A rejected install: right status and code, nothing changed anywhere. */
#define REJECTED(rc, status, code_)                                        \
    do {                                                                   \
        lpm_status rc_ = (rc);                                             \
        CHECK(rc_ == (status));                                            \
        CHECK(err.code == (code_));                                        \
        CHECK(root_untouched());                                           \
        CHECK(!registered("hello"));                                       \
        CHECK(staging_entries() == 0);                                     \
        CHECK(count_entries(outside) == 0);                                \
    } while (0)

/* ==================================================================== */
/* Verification and successful installation                              */
/* ==================================================================== */

static void test_verify_good_package(void)
{
    lpm_pkg_summary s;
    lpm_meta_error err;
    int fds;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    fds = open_fds();
    CHECK(lpm_verify_package(pkgfile, NULL, &s, &err) == LPM_OK);
    CHECK(open_fds() == fds);
    CHECK(strcmp(s.name, "hello") == 0 && strcmp(s.version, "1.2.0") == 0);
    CHECK(s.files == 3 && s.symlinks == 1 && s.dirs == 1);
    CHECK(s.bytes == strlen(HELLO[0].data) + strlen(HELLO[2].data) + strlen(HELLO[3].data));
    CHECK(strlen(s.archive_sha256) == 64);
    CHECK(count_entries(root) == 0);              /* verify writes nothing */
    CHECK(count_entries(base) == 3);
}

static void test_install_success(void)
{
    lpm_meta_error err;
    lpm_package rec;
    lpm_db db;
    lpm_file_list owned;
    int fds;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    fds = open_fds();
    CHECK(install(NULL, &err) == LPM_OK);
    CHECK(open_fds() == fds);
    CHECK(fully_installed());
    CHECK((mode_of("/usr/bin/hello") & 07777) == 0755);
    CHECK((mode_of("/etc/hello.conf") & 07777) == 0644);
    CHECK(staging_entries() == 0);
    CHECK(run_check().n == 0);

    /* The record keeps the manifest digest; the owned files are exactly
     * the files and symlinks (directories are shared, never owned). */
    CHECK(lpm_db_load_package(&cfg, "hello", &rec, &err) == LPM_OK);
    CHECK(rec.has_manifest_sha256);
    lpm_package_free(&rec);
    CHECK(lpm_db_open(&cfg, LPM_DB_READ, 0, &db, &err) == LPM_OK);
    CHECK(lpm_db_read_file_list(&db, "hello", &owned, &err) == LPM_OK);
    CHECK(owned.count == 4);
    CHECK(lpm_file_list_contains(&owned, "/usr/bin/hi"));
    CHECK(!lpm_file_list_contains(&owned, "/usr/share/hello/empty"));
    lpm_file_list_free(&owned);
    lpm_db_close(&db);
}

static void test_all_compressions(void)
{
    lpm_meta_error err;
    int f;

    for (f = 0; f < 3; f++) {
        damage d = INTACT;
        d.filter = f;
        fresh();
        build_pkg(HELLO_META, HELLO, NHELLO, &d);
        CHECK(install(NULL, &err) == LPM_OK);
        CHECK(fully_installed());
    }
}

static void test_root_isolation(void)
{
    char host[256];
    lpm_meta_error err;
    pentry p[2];

    fresh();
    /* Unique names, so their absence on the host proves something. */
    snprintf(host, sizeof(host), "/usr/bin/lpm-isolation-%ld", (long)getpid());
    p[0].path = host; p[0].type = 'f'; p[0].data = "isolated\n"; p[0].mode = 0755;
    p[1].path = "/etc/lpm-isolation.conf"; p[1].type = 'f'; p[1].data = "x\n"; p[1].mode = 0644;
    build_pkg("name=iso\nversion=1\n", p, 2, &INTACT);
    CHECK(install(NULL, &err) == LPM_OK);
    CHECK(file_is(host, "isolated\n"));            /* inside the root ... */
    CHECK(access(host, F_OK) != 0);                /* ... and not on the host */
    CHECK(access("/etc/lpm-isolation.conf", F_OK) != 0);
    CHECK(access("/var/lib/lpm/installed/iso.meta", F_OK) != 0);
    CHECK(count_entries(outside) == 0);
    CHECK(count_entries(base) == 3);               /* root, outside, package */
    CHECK(count_entries(root) == 3);               /* usr, etc, var */
}

static void test_large_streamed_payload(void)
{
    const size_t size = 24 * 1024 * 1024;
    char *big = malloc(size + 1);
    lpm_meta_error err;
    pentry p[1];
    size_t i;
    struct stat st;
    char path[700];

    for (i = 0; i < size; i++)
        big[i] = (char)('a' + i % 26);
    big[size] = '\0';
    fresh();
    p[0].path = "/usr/share/big/data.bin"; p[0].type = 'f'; p[0].data = big; p[0].mode = 0644;
    build_pkg("name=big\nversion=1\n", p, 1, &INTACT);
    CHECK(install(NULL, &err) == LPM_OK);
    snprintf(path, sizeof(path), "%s/usr/share/big/data.bin", root);
    CHECK(stat(path, &st) == 0 && (size_t)st.st_size == size);
    {
        char want[65];
        lpm_sha256_buffer(big, size, want, &err);
        CHECK(lpm_sha256_verify_file(path, want, &err) == LPM_OK);
    }
    free(big);
}

/* ==================================================================== */
/* Integrity failures                                                    */
/* ==================================================================== */

static void test_expected_package_hash(void)
{
    char digest[65], upper[65];
    lpm_meta_error err;
    size_t i;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    CHECK(lpm_sha256_file(pkgfile, digest, &err) == LPM_OK);

    /* Wrong digest: rejected before the archive is even opened. */
    REJECTED(install("0000000000000000000000000000000000000000000000000000000000000000", &err),
             LPM_ERR_INTEGRITY, LPM_META_ERR_HASH_MISMATCH);
    CHECK(count_entries(root) == 0);               /* not even a database */
    /* Malformed digest: a usage error, not a mismatch. */
    REJECTED(install("abc", &err), LPM_ERR_INVALID, LPM_META_ERR_INVALID_VALUE);
    /* Upper case is accepted for typed digests. */
    for (i = 0; i < 64; i++)
        upper[i] = (char)(digest[i] >= 'a' ? digest[i] - 'a' + 'A' : digest[i]);
    upper[64] = '\0';
    CHECK(install(upper, &err) == LPM_OK);
    CHECK(fully_installed());
}

static void test_tampered_payload_rejected(void)
{
    lpm_meta_error err;
    damage d = INTACT;
    char p[700];

    fresh();
    d.tamper_path = "/usr/share/doc/hello/README";   /* not the first file */
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INTEGRITY, LPM_META_ERR_HASH_MISMATCH);
    CHECK(strstr(err.message, "/usr/share/doc/hello/README") != NULL);
    /* Files that were verified before the bad one were staged, never
     * placed: the root has no usr/ at all. */
    snprintf(p, sizeof(p), "%s/usr", root);
    CHECK(access(p, F_OK) != 0);
    CHECK(lpm_verify_package(pkgfile, NULL, NULL, &err) == LPM_ERR_INTEGRITY);
}

static void test_tampered_manifest_rejected(void)
{
    lpm_meta_error err;
    damage d = INTACT;
    char metadata[512], hex[65];
    char *real = manifest_for(HELLO, NHELLO);

    fresh();
    /* metadata commits to the real manifest, the archive carries another */
    lpm_sha256_buffer(real, strlen(real), hex, &err);
    snprintf(metadata, sizeof(metadata), "%smanifest_sha256=%s\n", HELLO_META, hex);
    d.metadata = metadata;
    d.manifest = "file 0000000000000000000000000000000000000000000000000000000000000000 0644 /x\n";
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INTEGRITY, LPM_META_ERR_HASH_MISMATCH);
    CHECK(strstr(err.message, "manifest.txt does not match") != NULL);
    free(real);
}

static void test_symlink_target_tampered(void)
{
    lpm_meta_error err;
    damage d = INTACT;
    pentry p[2];
    char *m;

    fresh();
    p[0] = HELLO[0];
    p[1].path = "/usr/bin/hi"; p[1].type = 'l'; p[1].data = "hello"; p[1].mode = 0;
    m = manifest_for(p, 2);
    p[1].data = "other";   /* archive says "other", manifest says "hello" */
    d.manifest = m;
    build_pkg(HELLO_META, p, 2, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INTEGRITY, LPM_META_ERR_HASH_MISMATCH);
    free(m);
}

static void test_invalid_metadata_rejected(void)
{
    lpm_meta_error err;
    damage d = INTACT;

    fresh();
    d.metadata = "name=hello\nversion=1.2.0\n";   /* no manifest_sha256 */
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_MISSING_FIELD);
    CHECK(strstr(err.message, "metadata.txt") != NULL);

    fresh();
    d.metadata = "name=hello\nversion=01\nmanifest_sha256="
                 "0000000000000000000000000000000000000000000000000000000000000000\n";
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_INVALID_VALUE);
}

/* ==================================================================== */
/* Structural problems                                                   */
/* ==================================================================== */

static void test_structure_rejected(void)
{
    lpm_meta_error err;
    damage d;

    fresh();                                        /* wrong order */
    d = INTACT;
    d.manifest_first = 1;
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);

    fresh();                                        /* unlisted extra file */
    d = INTACT;
    d.extra_name = "payload/usr/bin/backdoor";
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);
    CHECK(strstr(err.message, "not listed") != NULL);

    fresh();                                        /* outside payload/ */
    d = INTACT;
    d.extra_name = "scripts/postinstall.sh";
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);

    fresh();                                        /* listed but missing */
    d = INTACT;
    d.skip_path = "/etc/hello.conf";
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);
    CHECK(strstr(err.message, "missing") != NULL);

    fresh();                                        /* same entry twice */
    d = INTACT;
    d.duplicate_first = 1;
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);

    fresh();                                        /* not an archive */
    {
        FILE *f = fopen(pkgfile, "wb");
        fputs("this is not a tar archive at all\n", f);
        fclose(f);
    }
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);
}

static void test_truncated_package(void)
{
    static char big[300000];
    lpm_meta_error err;
    damage d = INTACT;
    pentry p[2];
    struct stat st;

    memset(big, 'q', sizeof(big) - 1);
    p[0].path = "/usr/share/a.txt"; p[0].type = 'f'; p[0].data = "a\n"; p[0].mode = 0644;
    p[1].path = "/usr/share/z.bin"; p[1].type = 'f'; p[1].data = big;   p[1].mode = 0644;
    fresh();
    d.filter = 0;
    build_pkg("name=hello\nversion=1\n", p, 2, &d);
    stat(pkgfile, &st);
    CHECK(truncate(pkgfile, st.st_size - 150000) == 0);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_ARCHIVE);
}

/* ==================================================================== */
/* Attacks                                                               */
/* ==================================================================== */

static void test_traversal_entry_rejected(void)
{
    /* The manifest lists a harmless path with the correct hash; the
     * archive stores that same content under a climbing name. */
    static const char *const names[] = {
        "payload/../../escape.txt", "payload/usr/../../../escape.txt",
        "payload/../outside/escape.txt", "../escape.txt",
    };
    char probe1[700], probe2[700];
    lpm_meta_error err;
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        damage d = INTACT;
        fresh();
        d.rename_from = "/etc/hello.conf";
        d.rename_to = names[i];
        build_pkg(HELLO_META, HELLO, NHELLO, &d);
        REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_UNSAFE_ENTRY);
        CHECK(strstr(err.message, "traversal") != NULL);
        snprintf(probe1, sizeof(probe1), "%s/escape.txt", base);
        snprintf(probe2, sizeof(probe2), "%s/../escape.txt", base);
        CHECK(access(probe1, F_OK) != 0 && access(probe2, F_OK) != 0);
    }
}

static void test_absolute_entry_rejected(void)
{
    char target[700];
    lpm_meta_error err;
    damage d = INTACT;

    fresh();
    snprintf(target, sizeof(target), "%s/abs.txt", outside);
    d.rename_from = "/etc/hello.conf";
    d.rename_to = target;   /* an absolute name pointing at a real place */
    build_pkg(HELLO_META, HELLO, NHELLO, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(strstr(err.message, "absolute path") != NULL);
    CHECK(access(target, F_OK) != 0);
}

static void test_unsafe_manifest_rejected(void)
{
    static const char *const bad[] = {
        "file 0000000000000000000000000000000000000000000000000000000000000000 0644 /../../escape\n",
        "file 0000000000000000000000000000000000000000000000000000000000000000 0644 relative/path\n",
        "symlink /etc /usr/lib/link\n",
        "symlink ../../../outside /usr/lib/link\n",
        "symlink real /usr/lib/link\nfile 0000000000000000000000000000000000000000000000000000000000000000 0644 /usr/lib/link/passwd\n",
        "file 0000000000000000000000000000000000000000000000000000000000000000 4755 /usr/bin/suid\n",
        "file 0000000000000000000000000000000000000000000000000000000000000000 0777 /usr/bin/w\n",
        "dir 1777 /tmp\n",
        "file 0000000000000000000000000000000000000000000000000000000000000000 0644 /a\nfile 0000000000000000000000000000000000000000000000000000000000000000 0644 /a\n",
        "fifo 0644 /dev/x\n",
        "file 0000000000000000000000000000000000000000000000000000000000000000 0644 /no-newline",
    };
    lpm_meta_error err;
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        damage d = INTACT;
        fresh();
        d.manifest = bad[i];   /* manifest_sha256 matches it: integrity is fine */
        build_pkg(HELLO_META, NULL, 0, &d);
        CHECK(install(NULL, &err) == LPM_ERR_INVALID);
        CHECK(root_untouched() && !registered("hello") && count_entries(outside) == 0);
    }
}

static void test_symlink_escape_via_archive(void)
{
    /* A symlink to a "safe" target, then a file through it. */
    pentry p[3];
    lpm_meta_error err;

    fresh();
    p[0].path = "/usr/lib/real"; p[0].type = 'd'; p[0].data = NULL; p[0].mode = 0755;
    p[1].path = "/usr/lib/link"; p[1].type = 'l'; p[1].data = "real"; p[1].mode = 0;
    p[2].path = "/usr/lib/link/passwd"; p[2].type = 'f'; p[2].data = "pwned\n"; p[2].mode = 0644;
    build_pkg(HELLO_META, p, 3, &INTACT);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_PATH_CONFLICT);
}

static void test_preexisting_symlink_in_root(void)
{
    char lnk[700];
    lpm_meta_error err;

    fresh();
    snprintf(lnk, sizeof(lnk), "%s/usr", root);
    CHECK(symlink(outside, lnk) == 0);        /* root/usr -> outside */
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    CHECK(install(NULL, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(count_entries(outside) == 0);       /* nothing went through it */
    CHECK(!registered("hello") && staging_entries() == 0);
    CHECK(!exists_in(root, "etc"));           /* nothing partial either */

    /* Same attack when the package lists /usr itself as a directory. */
    {
        pentry p[2];
        p[0].path = "/usr"; p[0].type = 'd'; p[0].data = NULL; p[0].mode = 0755;
        p[1].path = "/usr/bin/tool"; p[1].type = 'f'; p[1].data = "x\n"; p[1].mode = 0755;
        build_pkg(HELLO_META, p, 2, &INTACT);
        CHECK(install(NULL, &err) == LPM_ERR_INVALID);
        CHECK(err.code == LPM_META_ERR_UNSAFE_ENTRY);
        CHECK(strstr(err.message, "symbolic link") != NULL);
        CHECK(count_entries(outside) == 0);
    }
}

static void test_hardlink_and_special_rejected(void)
{
    pentry p[1];
    lpm_meta_error err;
    damage d = INTACT;

    fresh();
    p[0].path = "/etc/shadow-copy"; p[0].type = 'h'; p[0].data = "/etc/shadow"; p[0].mode = 0644;
    build_pkg(HELLO_META, p, 1, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(strstr(err.message, "hard links") != NULL);

    fresh();
    p[0].path = "/dev/fifo"; p[0].type = 'p'; p[0].data = NULL;
    build_pkg(HELLO_META, p, 1, &d);
    REJECTED(install(NULL, &err), LPM_ERR_INVALID, LPM_META_ERR_UNSAFE_ENTRY);
}

/* ==================================================================== */
/* Conflicts and policy                                                  */
/* ==================================================================== */

static void test_existing_unowned_file_kept(void)
{
    char p[700];
    lpm_meta_error err;
    FILE *f;

    fresh();
    snprintf(p, sizeof(p), "%s/etc", root);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/etc/hello.conf", root);
    f = fopen(p, "w");
    fputs("hand-made LFS config\n", f);
    fclose(f);
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    CHECK(install(NULL, &err) == LPM_ERR_CONFLICT);
    CHECK(strstr(err.message, "already exists") != NULL);
    CHECK(file_is("/etc/hello.conf", "hand-made LFS config\n"));
    CHECK(!exists_in(root, "usr"));          /* nothing else placed */
    CHECK(!registered("hello") && staging_entries() == 0);
}

static void test_conflicts_with_installed_package(void)
{
    lpm_meta_error err;
    pentry p[1];

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    CHECK(install(NULL, &err) == LPM_OK);
    /* Same package again. */
    CHECK(install(NULL, &err) == LPM_ERR_EXISTS);
    /* Another package claiming hello's file. */
    p[0].path = "/usr/bin/hello"; p[0].type = 'f'; p[0].data = "impostor\n"; p[0].mode = 0755;
    build_pkg("name=impostor\nversion=1\n", p, 1, &INTACT);
    CHECK(install(NULL, &err) == LPM_ERR_CONFLICT);
    CHECK(strstr(err.message, "owned by package 'hello'") != NULL);
    CHECK(fully_installed() && !registered("impostor"));
    CHECK(file_is("/usr/bin/hello", "#!/bin/sh\necho hello\n"));
    CHECK(run_check().n == 0);
}

static void test_real_root_refused(void)
{
    lpm_config real = { "/" };
    lpm_install_options opt = { NULL, false, 0 };
    lpm_meta_error err;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    CHECK(lpm_install_package(&real, pkgfile, &opt, NULL, &err) == LPM_ERR_INVALID);
    CHECK(strstr(err.message, "real root") != NULL);
    real.root = "//";
    CHECK(lpm_install_package(&real, pkgfile, &opt, NULL, &err) == LPM_ERR_INVALID);
    CHECK(lpm_is_real_root("/usr/.."));
    CHECK(!lpm_is_real_root(root));
}

static void test_missing_package_file(void)
{
    lpm_meta_error err;
    lpm_install_options opt = { NULL, false, 0 };

    fresh();
    CHECK(lpm_install_package(&cfg, "/nonexistent/pkg.lpm", &opt, NULL, &err) ==
          LPM_ERR_NOT_FOUND);
    CHECK(lpm_verify_package("/nonexistent/pkg.lpm", NULL, NULL, &err) == LPM_ERR_NOT_FOUND);
    CHECK(lpm_verify_package(root, NULL, NULL, &err) == LPM_ERR_INVALID);   /* a dir */
    CHECK(count_entries(root) == 0);
}

/* ==================================================================== */
/* Failure safety                                                        */
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

/*
 * Fail every system call (and allocation) of a whole installation, one
 * at a time. Afterwards the root must be fully installed or completely
 * untouched; leftovers in staging are allowed only when the package is
 * fully installed (cleanup is the last step) and are then reported by
 * lpm check.
 */
static void test_fault_injection_install(void)
{
    int k, points = 0;

    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 1000; n++) {
            lpm_meta_error err;
            lpm_status rc;
            int installed, untouched, stage;

            fresh();
            build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
            fault_arm((fault_kind)k, n, fault_errno_for((fault_kind)k));
            rc = install(NULL, &err);
            fault_reset();
            installed = fully_installed();
            untouched = root_untouched() && !registered("hello");
            stage = staging_entries();

            if (!fault_fired) {
                CHECK(rc == LPM_OK && installed && stage == 0);
                break;
            }
            points++;
            if (tf_verbose)
                printf("      %s #%ld -> %s, %s\n", fault_names[k], n,
                       lpm_status_str(rc), installed ? "installed" :
                       untouched ? "untouched" : "PARTIAL");
            CHECK(installed || untouched);
            if (untouched) {
                CHECK(rc != LPM_OK && err.message[0] != '\0');
                CHECK(stage == 0);
            }
            if (installed && stage > 0)
                CHECK(run_check().kinds == (1u << LPM_CHECK_STALE_TEMP));
            if (installed && stage == 0)
                CHECK(run_check().n == 0);
        }
    }
    if (tf_verbose)
        printf("      %d injected failures\n", points);
    CHECK(points >= 60);
}

/*
 * Kill a child installer at its 1st, 2nd, ... system call. This is the
 * documented limit of the design: a crash after files were placed but
 * before the record was written can leave files without a record. The
 * test proves such a state is never silent: the staging directory is
 * still there, and lpm check reports it.
 */
static void test_crash_during_install(void)
{
    long n;
    int crashes = 0, partial = 0;

    for (n = 0; n < 1000; n++) {
        lpm_meta_error err;
        pid_t pid;
        int status, code, installed, untouched;
        check_result r;
        lpm_db db;

        fresh();
        build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
        fflush(NULL);
        pid = fork();
        if (pid == 0) {
            lpm_status rc;
            fault_reset();
            crash_at = n;
            rc = install(NULL, &err);
            _exit(rc == LPM_OK ? 0 : 1);
        }
        waitpid(pid, &status, 0);
        code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        CHECK(code == 0 || code == 77);

        installed = fully_installed();
        untouched = root_untouched() && !registered("hello");
        r = run_check();
        /* A record always means every file is there. */
        if (registered("hello"))
            CHECK(installed);
        /* Anything else than "clean" or "complete" is reported. */
        if (!installed && !untouched) {
            partial++;
            CHECK(r.kinds & (1u << LPM_CHECK_STALE_TEMP));
        }
        /* The dead installer's lock is free. */
        if (exists_in(root, "var/lib/lpm/lock")) {
            CHECK(lpm_db_open(&cfg, LPM_DB_WRITE, 0, &db, &err) == LPM_OK);
            lpm_db_close(&db);
        }
        if (code == 0) {
            CHECK(installed && r.n == 0);
            break;
        }
        crashes++;
    }
    if (tf_verbose)
        printf("      %d crash points, %d left files without a record (reported)\n",
               crashes, partial);
    CHECK(crashes >= 40);
}

static void test_disk_full_while_staging(void)
{
    lpm_meta_error err;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    fault_arm(F_WRITE, 0, ENOSPC);   /* first staged write */
    REJECTED(install(NULL, &err), LPM_ERR_IO, LPM_META_ERR_IO);
    fault_reset();
    CHECK(strstr(err.message, "No space") != NULL);
    CHECK(install(NULL, &err) == LPM_OK);     /* and it works afterwards */
}

static void test_cross_filesystem_failure_rolls_back(void)
{
    lpm_meta_error err;

    fresh();
    build_pkg(HELLO_META, HELLO, NHELLO, &INTACT);
    fault_arm(F_LINKAT, 2, EXDEV);   /* third file cannot be placed */
    CHECK(install(NULL, &err) == LPM_ERR_IO);
    fault_reset();
    CHECK(strstr(err.message, "different filesystem") != NULL);
    CHECK(root_untouched() && !registered("hello") && staging_entries() == 0);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    fault_reset();
    umask(022);

    printf("Running package install unit tests\n");
    RUN(test_verify_good_package);
    RUN(test_install_success);
    RUN(test_all_compressions);
    RUN(test_root_isolation);
    RUN(test_large_streamed_payload);
    RUN(test_expected_package_hash);
    RUN(test_tampered_payload_rejected);
    RUN(test_tampered_manifest_rejected);
    RUN(test_symlink_target_tampered);
    RUN(test_invalid_metadata_rejected);
    RUN(test_structure_rejected);
    RUN(test_truncated_package);
    RUN(test_traversal_entry_rejected);
    RUN(test_absolute_entry_rejected);
    RUN(test_unsafe_manifest_rejected);
    RUN(test_symlink_escape_via_archive);
    RUN(test_preexisting_symlink_in_root);
    RUN(test_hardlink_and_special_rejected);
    RUN(test_existing_unowned_file_kept);
    RUN(test_conflicts_with_installed_package);
    RUN(test_real_root_refused);
    RUN(test_missing_package_file);
    RUN(test_fault_injection_install);
    RUN(test_crash_during_install);
    RUN(test_disk_full_while_staging);
    RUN(test_cross_filesystem_failure_rolls_back);
    if (base[0])
        rm_tree(base);
    return tf_summary();
}
