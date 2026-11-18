/*
 * test_auth.c - Trusted keys, package authentication and authenticated
 * (multi-package) installation (Milestone 6).
 *
 * Packages are built and signed in the test with ephemeral keys
 * (test_signing.h): tk_key is trusted in every fresh root, tk_other
 * never is (unless a test adds it). Every test uses
 * <tmp>/lpm-authtest-XXXXXX/{root,pkgs,outside}; outside must stay empty.
 */
#include "database.h"
#include "install.h"
#include "integrity.h"
#include "metadata.h"
#include "pkg.h"
#include "plan.h"
#include "signature.h"
#include "trust.h"
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
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include "test_framework.h"
#include "test_signing.h"

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

static void fault_reset(void)
{
    fault_target = F_NONE;
    fault_at = -1;
    fault_seen = 0;
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

/* Swap a package file just before the installer reads it (TOCTOU test). */
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

/* ==================================================================== */
/* Package builder                                                       */
/* ==================================================================== */

static char base[512], root[600], pkgs[600], outside[600];
static lpm_config cfg;

/* How to build one package; zero means "normal". */
typedef struct {
    const lpm_privkey *key;        /* NULL: unsigned                       */
    const char *files;             /* space separated; default README      */
    const char *signature;         /* raw signature.txt instead of signing */
    int tamper_metadata;           /* store metadata differing from signed */
    int tamper_manifest;           /* store a manifest metadata did not hash */
    int tamper_payload;            /* payload bytes differ from manifest   */
    int signature_twice;           /* a second signature.txt (duplicate)   */
    int signature_last;            /* signature.txt after the payload      */
} spec;

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

static const char *pkg_path(const char *name, const char *version)
{
    static char p[3][800];
    static int k;
    k = (k + 1) % 3;
    snprintf(p[k], sizeof(p[k]), "%s/%s-%s.lpm", pkgs, name, version);
    return p[k];
}

static void build(const char *path, const char *name, const char *version,
                  const char *deps, const spec *s)
{
    char manifest[8192], metadata[8192], hex[65], sig[LPM_SIG_RECORD_MAX + 1];
    char flist[1024], *tok, *save = NULL;
    struct archive *a;
    lpm_meta_error err;
    size_t mpos = 0;
    int pos;

    if (s->files)
        snprintf(flist, sizeof(flist), "%s", s->files);
    else
        snprintf(flist, sizeof(flist), "/usr/share/%s/README", name);
    manifest[0] = '\0';
    for (tok = strtok_r(flist, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char content[300];
        snprintf(content, sizeof(content), "%s %s %s\n", name, version, tok);
        lpm_sha256_buffer(content, strlen(content), hex, &err);
        mpos += (size_t)snprintf(manifest + mpos, sizeof(manifest) - mpos,
                                 "file %s 0644 %s\n", hex, tok);
    }
    lpm_sha256_buffer(manifest, strlen(manifest), hex, &err);
    pos = snprintf(metadata, sizeof(metadata), "name=%s\nversion=%s\n", name, version);
    if (deps) {
        char dc[1024], *d, *s2 = NULL;
        snprintf(dc, sizeof(dc), "%s", deps);
        for (d = strtok_r(dc, " ", &s2); d; d = strtok_r(NULL, " ", &s2))
            pos += snprintf(metadata + pos, sizeof(metadata) - (size_t)pos, "depends=%s\n", d);
    }
    snprintf(metadata + pos, sizeof(metadata) - (size_t)pos, "manifest_sha256=%s\n", hex);

    sig[0] = '\0';
    if (s->signature)
        snprintf(sig, sizeof(sig), "%s", s->signature);
    else if (s->key) {
        size_t n = tk_sign(s->key, metadata, strlen(metadata), sig);
        sig[n] = '\0';
    }

    a = archive_write_new();
    archive_write_set_format_pax_restricted(a);
    archive_write_add_filter_gzip(a);
    archive_write_open_filename(a, path);
    if (s->tamper_metadata) {
        /* Same fields, one byte changed after signing: "1.0" -> "9.0". */
        char *v = strstr(metadata, "version=");
        v[8] = '9';
    }
    add_raw(a, "metadata.txt", 'f', metadata);
    add_raw(a, "manifest.txt", 'f', s->tamper_manifest ? "file 0000000000000000000000000000000000000000000000000000000000000000 0644 /x\n" : manifest);
    if (sig[0] && !s->signature_last) {
        add_raw(a, "signature.txt", 'f', sig);
        if (s->signature_twice)
            add_raw(a, "signature.txt", 'f', sig);
    }
    add_raw(a, "payload/", 'd', NULL);
    if (s->files)
        snprintf(flist, sizeof(flist), "%s", s->files);
    else
        snprintf(flist, sizeof(flist), "/usr/share/%s/README", name);
    save = NULL;
    for (tok = strtok_r(flist, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char content[300], ename[700];
        snprintf(content, sizeof(content), "%s %s %s\n", name, version, tok);
        if (s->tamper_payload)
            snprintf(content, sizeof(content), "TAMPERED\n");
        snprintf(ename, sizeof(ename), "payload%s", tok);
        add_raw(a, ename, 'f', content);
    }
    if (sig[0] && s->signature_last)
        add_raw(a, "signature.txt", 'f', sig);
    archive_write_close(a);
    archive_write_free(a);
}

/* A normal package signed by key. */
static void make(const char *name, const char *version, const char *deps,
                 const lpm_privkey *key)
{
    spec s;
    memset(&s, 0, sizeof(s));
    s.key = key;
    build(pkg_path(name, version), name, version, deps, &s);
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

/* trust: whether the fresh root trusts tk_key. */
static void fresh_with(int trust)
{
    const char *t = getenv("TMPDIR");
    if (base[0])
        rm_tree(base);
    snprintf(base, sizeof(base), "%s/lpm-authtest-XXXXXX", (t && *t) ? t : "/tmp");
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
    if (trust && tk_trust(root, &tk_pub) != 0) {
        fprintf(stderr, "cannot trust the test key\n");
        exit(1);
    }
}

static void fresh(void) { fresh_with(1); }

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

/* Entries whose names do not start with '.' (temporaries excluded). */
static int count_visible(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    int n = 0;
    while (d && (de = readdir(d)) != NULL)
        if (de->d_name[0] != '.')
            n++;
    if (d)
        closedir(d);
    return n;
}

static int exists_in_root(const char *rel)
{
    char p[1400];
    snprintf(p, sizeof(p), "%s/%s", root, rel);
    return access(p, F_OK) == 0;
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

static const char *store_dir(void)
{
    static char p[900];
    snprintf(p, sizeof(p), "%s/etc/lpm/trusted-keys", root);
    return p;
}

/* No package file, record or staging left; trust store as it was. */
static int nothing_installed(int keys_expected)
{
    char staging[900];
    snprintf(staging, sizeof(staging), "%s/var/lib/lpm/staging", root);
    return !exists_in_root("usr") && registered_count() <= 0 &&
           count_entries(staging) == 0 && count_entries(outside) == 0 &&
           count_entries(store_dir()) == keys_expected;
}

static int root_fd(void)
{
    return open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static lpm_status verify(const char *path, lpm_auth_result *a, bool *intact,
                         lpm_meta_error *err)
{
    lpm_pkg_summary s;
    lpm_status rc = lpm_verify_authenticated(&cfg, path, NULL, &s, a, intact, err);
    if (tf_verbose)
        printf("      verify: %s (%s)\n", lpm_status_str(rc),
               rc == LPM_OK ? "ok" : err->message);
    return rc;
}

static lpm_status install(const char *path, const char *dir, lpm_meta_error *err)
{
    lpm_install_options opt = { NULL, false, 0 };
    lpm_install_report rep;
    lpm_status rc = lpm_install_packages(&cfg, path, dir, &opt, &rep, err);
    if (tf_verbose)
        printf("      install: %s\n", rc == LPM_OK ? "ok" : err->message);
    lpm_install_report_free(&rep);
    return rc;
}

/* ==================================================================== */
/* Trusted-key management                                                */
/* ==================================================================== */

static void test_import_and_fingerprint(void)
{
    char name[1000], *pem;
    size_t len;
    lpm_pubkey back;
    lpm_meta_error err;
    struct stat st;
    int fd;

    fresh_with(0);
    fd = root_fd();
    CHECK(lpm_trust_add(fd, &tk_pub, &err) == LPM_OK);
    snprintf(name, sizeof(name), "%s/%s.pub", store_dir(), tk_pub.id);
    CHECK(stat(name, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0644);
    /* The file is named by the key's own fingerprint, SHA-256(raw key). */
    {
        char expect[65];
        lpm_sha256_buffer(tk_pub.raw, 32, expect, &err);
        CHECK(strcmp(expect, tk_pub.id) == 0);
    }
    CHECK(lpm_read_bounded_fileat(AT_FDCWD, name, LPM_KEY_PEM_MAX, &pem, &len, &err) == LPM_OK);
    CHECK(lpm_pubkey_from_pem(pem, len, &back, &err) == LPM_OK);
    CHECK(memcmp(back.raw, tk_pub.raw, 32) == 0);
    free(pem);
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &back, &err) == LPM_OK);
    /* no temporary files left behind */
    CHECK(count_entries(store_dir()) == 1);
    close(fd);
}

static void test_duplicate_import(void)
{
    lpm_meta_error err;
    int fd;

    fresh();
    fd = root_fd();
    CHECK(lpm_trust_add(fd, &tk_pub, &err) == LPM_ERR_EXISTS);
    CHECK(strstr(err.message, "already trusted") != NULL);
    CHECK(count_entries(store_dir()) == 1);
    close(fd);
}

static void test_list_remove_unknown(void)
{
    lpm_pubkey *keys, k;
    size_t n;
    lpm_meta_error err;
    int fd;

    fresh();
    fd = root_fd();
    CHECK(lpm_trust_add(fd, &tk_other_pub, &err) == LPM_OK);
    CHECK(lpm_trust_list(fd, &keys, &n, &err) == LPM_OK && n == 2);
    CHECK(strcmp(keys[0].id, keys[1].id) < 0);               /* sorted */
    free(keys);
    CHECK(lpm_trust_remove(fd, tk_other_pub.id, &err) == LPM_OK);
    CHECK(lpm_trust_lookup(fd, tk_other_pub.id, &k, &err) == LPM_ERR_UNTRUSTED);
    CHECK(err.code == LPM_META_ERR_KEY_UNTRUSTED);
    CHECK(lpm_trust_remove(fd, tk_other_pub.id, &err) == LPM_ERR_NOT_FOUND);
    CHECK(lpm_trust_remove(fd, "../../etc/passwd", &err) == LPM_ERR_INVALID);
    CHECK(lpm_trust_remove(fd, "ABC", &err) == LPM_ERR_INVALID);
    CHECK(lpm_trust_list(fd, &keys, &n, &err) == LPM_OK && n == 1);
    free(keys);
    close(fd);

    fresh_with(0);                                          /* no store at all */
    fd = root_fd();
    CHECK(lpm_trust_list(fd, &keys, &n, &err) == LPM_OK && n == 0);
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &k, &err) == LPM_ERR_UNTRUSTED);
    close(fd);
}

static void test_store_tampering_detected(void)
{
    char good[1000], fake[1000], *pem;
    size_t len;
    lpm_pubkey k, *keys;
    size_t n;
    lpm_meta_error err;
    FILE *f;
    int fd;

    fresh();
    fd = root_fd();
    /* Attacker writes THEIR key under the trusted key's file name. */
    snprintf(good, sizeof(good), "%s/%s.pub", store_dir(), tk_pub.id);
    lpm_pubkey_to_pem(&tk_other_pub, &pem, &len, &err);
    f = fopen(good, "w");
    fwrite(pem, 1, len, f);
    fclose(f);
    free(pem);
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &k, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_KEY_MISMATCH);
    CHECK(lpm_trust_list(fd, &keys, &n, &err) == LPM_ERR_INVALID);
    /* A stray file in the store is not silently ignored either. */
    fresh();
    snprintf(fake, sizeof(fake), "%s/notes.txt", store_dir());
    f = fopen(fake, "w");
    fputs("hello\n", f);
    fclose(f);
    close(fd);
    fd = root_fd();
    CHECK(lpm_trust_list(fd, &keys, &n, &err) == LPM_ERR_INVALID);
    close(fd);
}

static void test_store_symlink_and_permissions(void)
{
    char lpmdir[900];
    lpm_meta_error err;
    lpm_pubkey k;
    int fd;

    /* etc/lpm/trusted-keys -> a directory the attacker controls */
    fresh_with(0);
    snprintf(lpmdir, sizeof(lpmdir), "%s/etc", root);
    mkdir(lpmdir, 0755);
    snprintf(lpmdir, sizeof(lpmdir), "%s/etc/lpm", root);
    mkdir(lpmdir, 0755);
    CHECK(symlink(outside, store_dir()) == 0);
    fd = root_fd();
    CHECK(lpm_trust_add(fd, &tk_pub, &err) == LPM_ERR_INVALID);
    CHECK(count_entries(outside) == 0);                    /* nothing written there */
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &k, &err) == LPM_ERR_INVALID);
    close(fd);

    /* a group-writable store is not trusted */
    fresh();
    chmod(store_dir(), 0775);
    fd = root_fd();
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &k, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_UNTRUSTED);
    chmod(store_dir(), 0755);
    CHECK(lpm_trust_lookup(fd, tk_pub.id, &k, &err) == LPM_OK);
    close(fd);
}

static void test_roots_have_separate_stores(void)
{
    char first[600];
    lpm_meta_error err;
    lpm_auth_result a;
    bool intact;

    fresh();
    make("hello", "1.0", NULL, tk_key);
    snprintf(first, sizeof(first), "%s", pkg_path("hello", "1.0"));
    CHECK(verify(first, &a, &intact, &err) == LPM_OK && a.status == LPM_AUTH_TRUSTED);
    /* Same package, a root that trusts nothing: not authenticated. */
    {
        char other[700];
        lpm_config c2;
        lpm_pkg_summary s;
        snprintf(other, sizeof(other), "%s/other-root", base);
        mkdir(other, 0755);
        c2.root = other;
        CHECK(lpm_verify_authenticated(&c2, first, NULL, &s, &a, &intact, &err) ==
              LPM_ERR_UNTRUSTED);
        CHECK(intact && a.signature_valid && !a.key_trusted);
    }
}

static void test_key_add_fault_injection(void)
{
    int k, points = 0;

    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 200; n++) {
            lpm_meta_error err;
            lpm_pubkey got;
            lpm_status rc, look;
            int fd;

            fresh_with(0);
            fd = root_fd();
            fault_arm((fault_kind)k, n, EIO);
            rc = lpm_trust_add(fd, &tk_pub, &err);
            fault_reset();
            look = lpm_trust_lookup(fd, tk_pub.id, &got, &err);
            close(fd);
            if (!fault_fired) {
                CHECK(rc == LPM_OK && look == LPM_OK);
                break;
            }
            points++;
            /* Either the key is fully trusted (lookup re-checks that the
             * file holds exactly this key), or not at all. A failed final
             * cleanup may leave a hidden .lpm-tmp.* file, which is never
             * read as a key; there is never a second visible key file. */
            CHECK(look == LPM_OK || look == LPM_ERR_UNTRUSTED);
            if (rc != LPM_OK)
                CHECK(look == LPM_ERR_UNTRUSTED || rc == LPM_ERR_IO);
            CHECK(count_visible(store_dir()) <= 1);
        }
    }
    CHECK(points >= 8);
}

/* ==================================================================== */
/* Package authentication                                                */
/* ==================================================================== */

static void test_package_outcomes(void)
{
    lpm_meta_error err;
    lpm_auth_result a;
    bool intact;
    spec s;

    fresh();
    make("good", "1.0", NULL, tk_key);
    CHECK(verify(pkg_path("good", "1.0"), &a, &intact, &err) == LPM_OK);
    CHECK(a.status == LPM_AUTH_TRUSTED && a.signature_valid && a.key_trusted);
    CHECK(strcmp(a.key_id, tk_pub.id) == 0);

    make("nosig", "1.0", NULL, NULL);                       /* unsigned */
    CHECK(verify(pkg_path("nosig", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(intact && a.status == LPM_AUTH_UNSIGNED && err.code == LPM_META_ERR_SIG_MISSING);

    make("stranger", "1.0", NULL, tk_other);                 /* unknown signer */
    CHECK(verify(pkg_path("stranger", "1.0"), &a, &intact, &err) == LPM_ERR_UNTRUSTED);
    CHECK(intact && a.signature_valid && !a.key_trusted && a.status == LPM_AUTH_UNTRUSTED);
    CHECK(strcmp(a.key_id, tk_other_pub.id) == 0);

    memset(&s, 0, sizeof(s));                                /* tampered metadata */
    s.key = tk_key;
    s.tamper_metadata = 1;
    build(pkg_path("tmeta", "1.0"), "tmeta", "1.0", NULL, &s);
    CHECK(verify(pkg_path("tmeta", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(intact && a.status == LPM_AUTH_INVALID && !a.signature_valid);
    CHECK(err.code == LPM_META_ERR_SIG_INVALID);

    memset(&s, 0, sizeof(s));                                /* tampered manifest */
    s.key = tk_key;
    s.tamper_manifest = 1;
    build(pkg_path("tman", "1.0"), "tman", "1.0", NULL, &s);
    CHECK(verify(pkg_path("tman", "1.0"), &a, &intact, &err) == LPM_ERR_INTEGRITY);
    CHECK(!intact);

    memset(&s, 0, sizeof(s));                                /* tampered payload */
    s.key = tk_key;
    s.tamper_payload = 1;
    build(pkg_path("tpay", "1.0"), "tpay", "1.0", NULL, &s);
    CHECK(verify(pkg_path("tpay", "1.0"), &a, &intact, &err) == LPM_ERR_INTEGRITY);
    CHECK(!intact && err.code == LPM_META_ERR_HASH_MISMATCH);
}

static void test_signature_record_attacks(void)
{
    char rec[LPM_SIG_RECORD_MAX + 1], evil[2 * LPM_SIG_RECORD_MAX];
    char meta[512], hex[65], manifest[256], content[128];
    lpm_meta_error err;
    lpm_auth_result a;
    bool intact;
    size_t n;
    spec s;

    fresh();
    /* Reconstruct the exact metadata build() will write for "victim". */
    snprintf(content, sizeof(content), "victim 1.0 /usr/share/victim/README\n");
    lpm_sha256_buffer(content, strlen(content), hex, &err);
    snprintf(manifest, sizeof(manifest), "file %s 0644 /usr/share/victim/README\n", hex);
    lpm_sha256_buffer(manifest, strlen(manifest), hex, &err);
    snprintf(meta, sizeof(meta), "name=victim\nversion=1.0\nmanifest_sha256=%s\n", hex);

    /* 1. Signed by a stranger, but claiming the trusted key's identity:
     *    public_key and key_id of the trusted key, stranger's signature. */
    n = tk_sign(tk_other, meta, strlen(meta), rec);
    rec[n] = '\0';
    {
        char pub_t[65], pub_o[65], *p;
        lpm_hex_encode(tk_pub.raw, 32, pub_t);
        lpm_hex_encode(tk_other_pub.raw, 32, pub_o);
        snprintf(evil, sizeof(evil), "%s", rec);
        p = strstr(evil, pub_o);
        memcpy(p, pub_t, 64);
        p = strstr(evil, tk_other_pub.id);
        memcpy(p, tk_pub.id, 64);
    }
    memset(&s, 0, sizeof(s));
    s.signature = evil;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(a.status == LPM_AUTH_INVALID);
    CHECK(install(pkg_path("victim", "1.0"), NULL, &err) == LPM_ERR_SIGNATURE);
    CHECK(nothing_installed(1));

    /* 2. Trusted key_id with the stranger's public_key: inconsistent. */
    snprintf(evil, sizeof(evil), "%s", rec);
    memcpy(strstr(evil, tk_other_pub.id), tk_pub.id, 64);
    s.signature = evil;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(a.status == LPM_AUTH_BAD_RECORD && err.code == LPM_META_ERR_KEY_MISMATCH);

    /* 3. Unsupported format. */
    n = tk_sign(tk_key, meta, strlen(meta), rec);
    rec[n] = '\0';
    snprintf(evil, sizeof(evil), "%s", rec);
    memcpy(strstr(evil, "-v1"), "-v9", 3);
    s.signature = evil;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(err.code == LPM_META_ERR_SIG_UNSUPPORTED);

    /* 4. Garbage signature bytes (valid layout). */
    snprintf(evil, sizeof(evil), "%s", rec);
    {
        char *sg = strstr(evil, "signature=") + 10;
        memset(sg, '0', 128);
    }
    s.signature = evil;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_SIGNATURE);
    CHECK(a.status == LPM_AUTH_INVALID);

    /* 5. Two signature records, or one in the wrong place. */
    memset(&s, 0, sizeof(s));
    s.key = tk_key;
    s.signature_twice = 1;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_INVALID);
    s.signature_twice = 0;
    s.signature_last = 1;
    build(pkg_path("victim", "1.0"), "victim", "1.0", NULL, &s);
    CHECK(verify(pkg_path("victim", "1.0"), &a, &intact, &err) == LPM_ERR_INVALID);
    CHECK(nothing_installed(1));
}

static void test_removed_key_revokes(void)
{
    lpm_meta_error err;
    lpm_auth_result a;
    bool intact;
    int fd;

    fresh();
    make("hello", "1.0", NULL, tk_key);
    CHECK(verify(pkg_path("hello", "1.0"), &a, &intact, &err) == LPM_OK);
    fd = root_fd();
    CHECK(lpm_trust_remove(fd, tk_pub.id, &err) == LPM_OK);
    close(fd);
    CHECK(verify(pkg_path("hello", "1.0"), &a, &intact, &err) == LPM_ERR_UNTRUSTED);
    CHECK(a.signature_valid && !a.key_trusted);
    CHECK(install(pkg_path("hello", "1.0"), NULL, &err) == LPM_ERR_UNTRUSTED);
    CHECK(nothing_installed(0));
}

static void test_unsigned_and_untrusted_install_rejected(void)
{
    lpm_meta_error err;

    fresh();
    make("nosig", "1.0", NULL, NULL);
    CHECK(install(pkg_path("nosig", "1.0"), NULL, &err) == LPM_ERR_SIGNATURE);
    CHECK(err.code == LPM_META_ERR_SIG_MISSING);
    CHECK(strstr(err.message, "nosig 1.0") != NULL);
    CHECK(nothing_installed(1));
    make("stranger", "1.0", NULL, tk_other);
    CHECK(install(pkg_path("stranger", "1.0"), NULL, &err) == LPM_ERR_UNTRUSTED);
    CHECK(nothing_installed(1));
    /* After an explicit `key add`, the stranger's package installs. */
    {
        int fd = root_fd();
        CHECK(lpm_trust_add(fd, &tk_other_pub, &err) == LPM_OK);
        close(fd);
    }
    CHECK(install(pkg_path("stranger", "1.0"), NULL, &err) == LPM_OK);
    CHECK(registered_count() == 1);
}

/* ==================================================================== */
/* Dependency authentication                                             */
/* ==================================================================== */

static void diamond(const lpm_privkey *c, const lpm_privkey *a, const lpm_privkey *b,
                    const lpm_privkey *app)
{
    make("libc", "1.0", NULL, c);
    make("liba", "1.0", "libc>=1.0", a);
    make("libb", "1.0", "libc>=1.0", b);
    make("app", "1.0", "liba>=1.0 libb>=1.0", app);
}

static void test_all_dependencies_trusted(void)
{
    lpm_meta_error err;

    fresh();
    diamond(tk_key, tk_key, tk_key, tk_key);
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_OK);
    CHECK(registered_count() == 4);
}

static void test_unsigned_dependency_rejects_all(void)
{
    lpm_meta_error err;

    fresh();
    diamond(tk_key, tk_key, NULL, tk_key);   /* libb unsigned */
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_SIGNATURE);
    CHECK(strstr(err.message, "libb 1.0") != NULL);
    CHECK(nothing_installed(1));              /* not libc, liba or app either */
}

static void test_untrusted_dependency_rejects_all(void)
{
    lpm_meta_error err;

    fresh();
    diamond(tk_key, tk_key, tk_other, tk_key);   /* libb by a stranger */
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_UNTRUSTED);
    CHECK(strstr(err.message, "libb 1.0") != NULL);
    CHECK(nothing_installed(1));
}

static void test_multiple_trusted_signers(void)
{
    lpm_meta_error err;
    int fd;

    fresh();
    fd = root_fd();
    CHECK(lpm_trust_add(fd, &tk_other_pub, &err) == LPM_OK);
    close(fd);
    diamond(tk_key, tk_other, tk_key, tk_other);
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_OK);
    CHECK(registered_count() == 4);
}

static void test_tampered_dependency_rejects_all(void)
{
    lpm_meta_error err;
    spec s;

    fresh();
    diamond(tk_key, tk_key, tk_key, tk_key);
    memset(&s, 0, sizeof(s));
    s.key = tk_key;                   /* still validly signed metadata ... */
    s.tamper_payload = 1;             /* ... but the payload changed */
    build(pkg_path("libc", "1.0"), "libc", "1.0", NULL, &s);
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_INTEGRITY);
    CHECK(strstr(err.message, "libc 1.0") != NULL);
    CHECK(nothing_installed(1));
}

static void test_substitution_during_install(void)
{
    char aside[800];
    lpm_meta_error err;

    /* libc is replaced, between planning and verification, by a
     * package with the same name and version signed by a stranger. */
    fresh();
    diamond(tk_key, tk_key, tk_key, tk_key);
    snprintf(aside, sizeof(aside), "%s/evil-libc.lpm", base);
    {
        spec s;
        memset(&s, 0, sizeof(s));
        s.key = tk_other;
        build(aside, "libc", "1.0", NULL, &s);
    }
    snprintf(swap_from, sizeof(swap_from), "%s", aside);
    snprintf(swap_to, sizeof(swap_to), "%s", pkg_path("libc", "1.0"));
    CHECK(install(pkg_path("app", "1.0"), pkgs, &err) == LPM_ERR_UNTRUSTED);
    CHECK(swap_from[0] == '\0');      /* the swap really happened */
    CHECK(nothing_installed(1));
}

/* ==================================================================== */
/* Installation safety                                                   */
/* ==================================================================== */

static void test_package_cannot_touch_trust_store(void)
{
    static const char *const paths[] = {
        "/etc/lpm/trusted-keys/evil.pub",
        "/etc/lpm/config",
        "/etc/lpm",
        "/var/lib/lpm/installed/fake.meta",
    };
    char before[900];
    lpm_meta_error err;
    size_t i;

    snprintf(before, sizeof(before), "%s.pub", tk_pub.id);
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        spec s;
        fresh();
        memset(&s, 0, sizeof(s));
        s.key = tk_key;               /* even a TRUSTED package may not */
        s.files = paths[i];
        build(pkg_path("evil", "1.0"), "evil", "1.0", NULL, &s);
        CHECK(install(pkg_path("evil", "1.0"), NULL, &err) == LPM_ERR_INVALID);
        CHECK(err.code == LPM_META_ERR_PROTECTED_PATH);
        CHECK(count_entries(store_dir()) == 1);       /* only the original key */
        CHECK(registered_count() <= 0);
    }
    /* Similar-looking paths are ordinary paths. */
    {
        spec s;
        fresh();
        memset(&s, 0, sizeof(s));
        s.key = tk_key;
        s.files = "/etc/lpmx/file /var/lib/lpm-extra/file";
        build(pkg_path("fine", "1.0"), "fine", "1.0", NULL, &s);
        CHECK(install(pkg_path("fine", "1.0"), NULL, &err) == LPM_OK);
    }
}

static void test_real_root_still_refused(void)
{
    lpm_config real = { "/" };
    lpm_install_options opt = { NULL, false, 0 };
    lpm_install_report rep;
    lpm_meta_error err;

    fresh();
    make("hello", "1.0", NULL, NULL);   /* unsigned: harmless even if the guard broke */
    CHECK(lpm_install_packages(&real, pkg_path("hello", "1.0"), NULL, &opt, &rep, &err) ==
          LPM_ERR_INVALID);
    CHECK(strstr(err.message, "real root") != NULL);
}

static int fault_errno_for(fault_kind k)
{
    switch (k) {
    case F_WRITE:  return ENOSPC;
    case F_OPENAT: return EMFILE;
    case F_LINKAT: return EXDEV;
    default:       return EIO;
    }
}

/* Authentication adds steps to every install; every single failure of a
 * signed 4-package install still ends with all four or none. */
static void test_signed_install_all_or_nothing(void)
{
    int k, points = 0;

    for (k = F_ALLOC; k < F_KINDS; k++) {
        long n;
        for (n = 0; n < 3000; n++) {
            lpm_meta_error err;
            lpm_status rc;
            int count;

            fresh();
            diamond(tk_key, tk_key, tk_key, tk_key);
            fault_arm((fault_kind)k, n, fault_errno_for((fault_kind)k));
            rc = install(pkg_path("app", "1.0"), pkgs, &err);
            fault_reset();
            count = registered_count();
            if (!fault_fired) {
                CHECK(rc == LPM_OK && count == 4);
                break;
            }
            points++;
            CHECK(count == 4 || nothing_installed(1));
            if (count != 4)
                CHECK(rc != LPM_OK);
        }
    }
    CHECK(points >= 150);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    fault_reset();
    umask(022);
    tk_init();

    printf("Running trust store and package authentication tests\n");
    RUN(test_import_and_fingerprint);
    RUN(test_duplicate_import);
    RUN(test_list_remove_unknown);
    RUN(test_store_tampering_detected);
    RUN(test_store_symlink_and_permissions);
    RUN(test_roots_have_separate_stores);
    RUN(test_key_add_fault_injection);
    RUN(test_package_outcomes);
    RUN(test_signature_record_attacks);
    RUN(test_removed_key_revokes);
    RUN(test_unsigned_and_untrusted_install_rejected);
    RUN(test_all_dependencies_trusted);
    RUN(test_unsigned_dependency_rejects_all);
    RUN(test_untrusted_dependency_rejects_all);
    RUN(test_multiple_trusted_signers);
    RUN(test_tampered_dependency_rejects_all);
    RUN(test_substitution_during_install);
    RUN(test_package_cannot_touch_trust_store);
    RUN(test_real_root_still_refused);
    RUN(test_signed_install_all_or_nothing);
    if (base[0])
        rm_tree(base);
    tk_done();
    return tf_summary();
}
