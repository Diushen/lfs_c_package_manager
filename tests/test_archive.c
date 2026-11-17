/*
 * test_archive.c - Safe archive extraction (Milestone 4).
 *
 * Archives are built inside the test with libarchive's *write* API, so
 * malicious ones (traversal, absolute paths, symlink tricks, hard links,
 * devices) can be produced exactly. After every rejected archive the
 * test inspects the filesystem: nothing may appear outside the
 * destination, and (because a failed extraction is rolled back) nothing
 * may remain inside it either.
 *
 * Layout per test:   <tmp>/lpm-artest-XXXXXX/
 *                        root/      the extraction destination
 *                        outside/   must never receive anything
 */
#include "lpm_archive.h"
#include "safefs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#include "test_framework.h"

static char base[512], root[600], outside[600], arc[600];

typedef struct {
    const char *path;
    char type;          /* f file, d dir, l symlink, h hardlink, p fifo, c chardev */
    const char *data;   /* file contents, or link target */
    unsigned mode;
} spec;

enum { NONE, GZIP, XZ };

/* Write an archive with the given entries. Returns 0 on success. */
static int build(const char *out, const spec *s, size_t n, int filter)
{
    struct archive *a = archive_write_new();
    size_t i;
    int ok = 0;

    archive_write_set_format_pax_restricted(a);
    if (filter == GZIP)
        archive_write_add_filter_gzip(a);
    else if (filter == XZ)
        archive_write_add_filter_xz(a);
    if (archive_write_open_filename(a, out) != ARCHIVE_OK)
        ok = -1;
    for (i = 0; ok == 0 && i < n; i++) {
        struct archive_entry *e = archive_entry_new();
        size_t len = s[i].type == 'f' && s[i].data ? strlen(s[i].data) : 0;

        archive_entry_set_pathname(e, s[i].path);
        archive_entry_set_perm(e, s[i].mode ? s[i].mode : 0644);
        archive_entry_set_size(e, (la_int64_t)len);
        switch (s[i].type) {
        case 'd': archive_entry_set_filetype(e, AE_IFDIR); break;
        case 'l': archive_entry_set_filetype(e, AE_IFLNK);
                  archive_entry_set_symlink(e, s[i].data); break;
        case 'h': archive_entry_set_filetype(e, AE_IFREG);
                  archive_entry_set_hardlink(e, s[i].data); break;
        case 'p': archive_entry_set_filetype(e, AE_IFIFO); break;
        case 'c': archive_entry_set_filetype(e, AE_IFCHR);
                  archive_entry_set_rdev(e, 0x0105); break;
        default:  archive_entry_set_filetype(e, AE_IFREG); break;
        }
        if (archive_write_header(a, e) < ARCHIVE_WARN)   /* WARN: odd names wanted */
            ok = -1;
        else if (len > 0 && archive_write_data(a, s[i].data, len) != (la_ssize_t)len)
            ok = -1;
        if (ok != 0)
            fprintf(stderr, "    test archive builder: %s: %s\n", s[i].path,
                    archive_error_string(a));
        archive_entry_free(e);
    }
    if (archive_write_close(a) < ARCHIVE_WARN) {
        fprintf(stderr, "    test archive builder: close: %s\n", archive_error_string(a));
        ok = -1;
    }
    archive_write_free(a);
    return ok;
}

static void rm_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *de;
        while (d && (de = readdir(d)) != NULL) {
            char sub[1200];
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
    snprintf(base, sizeof(base), "%s/lpm-artest-XXXXXX", (t && *t) ? t : "/tmp");
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(root, sizeof(root), "%s/root", base);
    snprintf(outside, sizeof(outside), "%s/outside", base);
    snprintf(arc, sizeof(arc), "%s/test.tar", base);
    mkdir(root, 0755);
    mkdir(outside, 0755);
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

/* Number of open descriptors, to detect leaks. */
static int open_fds(void)
{
    return count_entries("/proc/self/fd");
}

static int exists(const char *dir, const char *rel)
{
    char p[1400];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, rel);
    return lstat(p, &st) == 0;
}

static int file_is(const char *dir, const char *rel, const char *content)
{
    char p[1400], buf[256];
    FILE *f;
    size_t n;
    snprintf(p, sizeof(p), "%s/%s", dir, rel);
    f = fopen(p, "rb");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strcmp(buf, content) == 0;
}

static mode_t mode_of(const char *dir, const char *rel)
{
    char p[1400];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, rel);
    return lstat(p, &st) == 0 ? st.st_mode : 0;
}

/* Extract; on expected failure check the reason and that nothing changed. */
static lpm_status extract(lpm_meta_error *err)
{
    lpm_status rc = lpm_archive_extract(arc, root, err);
    if (tf_verbose && rc != LPM_OK)
        printf("      rejected: %s\n", err->message);
    return rc;
}

#define REJECTED_CLEANLY(rc, code_)                                        \
    do {                                                                   \
        CHECK((rc) != LPM_OK);                                             \
        CHECK(err.code == (code_));                                        \
        CHECK(count_entries(root) == 0);    /* rolled back */              \
        CHECK(count_entries(outside) == 0); /* nothing escaped */          \
        CHECK(count_entries(base) == 3);    /* root, outside, test.tar */  \
    } while (0)

static const spec NORMAL[] = {
    { "usr/", 'd', NULL, 0755 },
    { "usr/bin/", 'd', NULL, 0755 },
    { "usr/bin/example", 'f', "#!/bin/sh\necho example\n", 0755 },
    { "etc/", 'd', NULL, 0755 },
    { "etc/example.conf", 'f', "key=value\n", 0644 },
};

/* ---- normal extraction ------------------------------------------------- */

static void test_normal_extraction(void)
{
    lpm_meta_error err;
    int fds;

    fresh();
    CHECK(build(arc, NORMAL, 5, NONE) == 0);
    fds = open_fds();
    CHECK(extract(&err) == LPM_OK);
    CHECK(open_fds() == fds);                         /* no descriptor leaked */
    CHECK(file_is(root, "usr/bin/example", "#!/bin/sh\necho example\n"));
    CHECK(file_is(root, "etc/example.conf", "key=value\n"));
    CHECK((mode_of(root, "usr/bin/example") & 0777) == 0755);
    CHECK((mode_of(root, "etc/example.conf") & 0777) == 0644);
    CHECK(count_entries(outside) == 0);
}

static void test_compressed_formats(void)
{
    static const int filters[] = { GZIP, XZ };
    lpm_meta_error err;
    size_t i;

    for (i = 0; i < 2; i++) {
        fresh();
        CHECK(build(arc, NORMAL, 5, filters[i]) == 0);
        CHECK(extract(&err) == LPM_OK);
        CHECK(file_is(root, "usr/bin/example", "#!/bin/sh\necho example\n"));
    }
}

static void test_nested_directories_created(void)
{
    static const spec s[] = {   /* no directory entries at all */
        { "a/b/c/d/e/deep.txt", 'f', "deep\n", 0644 },
        { "./x/y.txt", 'f', "dot prefix\n", 0644 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 2, NONE) == 0);
    CHECK(extract(&err) == LPM_OK);
    CHECK(file_is(root, "a/b/c/d/e/deep.txt", "deep\n"));
    CHECK(file_is(root, "x/y.txt", "dot prefix\n"));
    CHECK(S_ISDIR(mode_of(root, "a/b/c")));
}

static void test_empty_directories(void)
{
    static const spec s[] = {
        { "./", 'd', NULL, 0755 },
        { "var/empty/", 'd', NULL, 0755 },
        { "opt/", 'd', NULL, 0700 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 3, NONE) == 0);
    CHECK(extract(&err) == LPM_OK);
    CHECK(S_ISDIR(mode_of(root, "var/empty")));
    CHECK(count_entries(root) == 2);
}

static void test_safe_relative_symlink(void)
{
    static const spec s[] = {
        { "usr/lib/libfoo.so.1", 'f', "elf\n", 0755 },
        { "usr/lib/libfoo.so", 'l', "libfoo.so.1", 0777 },
        { "usr/lib/sub/x", 'f', "x\n", 0644 },
        { "usr/lib/sublink", 'l', "sub/x", 0777 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 4, NONE) == 0);
    CHECK(extract(&err) == LPM_OK);
    CHECK(S_ISLNK(mode_of(root, "usr/lib/libfoo.so")));
    CHECK(file_is(root, "usr/lib/libfoo.so", "elf\n"));    /* resolves inside */
}

static void test_dangerous_modes_stripped(void)
{
    static const spec s[] = {
        { "bin/suid", 'f', "x\n", 04755 },
        { "bin/world", 'f', "x\n", 0666 },
        { "tmpdir/", 'd', NULL, 01777 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 3, NONE) == 0);
    CHECK(extract(&err) == LPM_OK);
    CHECK((mode_of(root, "bin/suid") & 07777) == 0755);    /* no setuid */
    CHECK((mode_of(root, "bin/world") & 07777) == 0644);   /* not world-writable */
    CHECK((mode_of(root, "tmpdir") & 07000) == 0);         /* no sticky bit */
}

/* ---- malformed input --------------------------------------------------------- */

static void test_invalid_archive(void)
{
    lpm_meta_error err;
    unsigned char junk[4096];
    size_t i;
    FILE *f;

    fresh();
    for (i = 0; i < sizeof(junk); i++)
        junk[i] = (unsigned char)tf_rand();
    f = fopen(arc, "wb");
    fwrite(junk, 1, sizeof(junk), f);
    fclose(f);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_ARCHIVE);
}

static void test_truncated_archive(void)
{
    static char big[200000];
    spec s[2];
    lpm_meta_error err;
    struct stat st;
    int fds;

    memset(big, 'z', sizeof(big) - 1);
    s[0].path = "usr/share/first.txt"; s[0].type = 'f'; s[0].data = "first\n"; s[0].mode = 0644;
    s[1].path = "usr/share/big.bin";   s[1].type = 'f'; s[1].data = big;       s[1].mode = 0644;
    fresh();
    CHECK(build(arc, s, 2, NONE) == 0);
    CHECK(stat(arc, &st) == 0);
    CHECK(truncate(arc, st.st_size / 2) == 0);      /* cut inside big.bin */
    fds = open_fds();
    /* first.txt was already extracted when the damage is found: the
     * rollback must remove it again. */
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_ARCHIVE);
    CHECK(open_fds() == fds);
}

static void test_corrupt_compressed_archive(void)
{
    lpm_meta_error err;
    FILE *f;
    long size;
    unsigned char b;

    fresh();
    CHECK(build(arc, NORMAL, 5, GZIP) == 0);
    f = fopen(arc, "r+b");
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, size / 2, SEEK_SET);       /* flip bits in the deflate stream */
    b = (unsigned char)fgetc(f);
    fseek(f, size / 2, SEEK_SET);
    fputc(b ^ 0xff, f);
    fclose(f);
    CHECK(extract(&err) != LPM_OK);
    CHECK(count_entries(root) == 0 && count_entries(outside) == 0);
}

static void test_missing_archive_and_destination(void)
{
    lpm_meta_error err;

    fresh();
    CHECK(lpm_archive_extract("/nonexistent/x.tar", root, &err) == LPM_ERR_NOT_FOUND);
    CHECK(build(arc, NORMAL, 5, NONE) == 0);
    CHECK(lpm_archive_extract(arc, "/nonexistent/dir", &err) == LPM_ERR_NOT_FOUND);
}

/* ---- attacks ------------------------------------------------------------------- */

static void test_path_traversal(void)
{
    static const char *const evil[] = {
        "../escape.txt",                 /* -> <base>/escape.txt     */
        "../../escape.txt",              /* -> <tmp>/escape.txt      */
        "usr/../../outside/escape.txt",  /* climbs out via usr/..    */
        "usr/../../../etc/escape.txt",
        "./../escape.txt",
        "a/b/../../../escape.txt",
        "..",
    };
    char tmpesc[600];
    lpm_meta_error err;
    size_t i;
    spec s[2];

    snprintf(tmpesc, sizeof(tmpesc), "%s/../escape.txt", base);
    for (i = 0; i < sizeof(evil) / sizeof(evil[0]); i++) {
        fresh();
        /* A harmless entry first, so the rollback is exercised too. */
        s[0].path = "usr/share/ok.txt"; s[0].type = 'f'; s[0].data = "ok\n"; s[0].mode = 0644;
        s[1].path = evil[i];            s[1].type = 'f'; s[1].data = "pwned\n"; s[1].mode = 0644;
        CHECK(build(arc, s, 2, NONE) == 0);
        REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
        CHECK(strstr(err.message, "traversal") != NULL);
        CHECK(!exists(base, "escape.txt"));
        CHECK(access(tmpesc, F_OK) != 0);
    }
}

static void test_absolute_paths(void)
{
    char abs_target[700];
    lpm_meta_error err;
    spec s[1];

    fresh();
    /* An absolute path that names a real, writable place. */
    snprintf(abs_target, sizeof(abs_target), "%s/abs.txt", outside);
    s[0].path = abs_target; s[0].type = 'f'; s[0].data = "pwned\n"; s[0].mode = 0644;
    CHECK(build(arc, s, 1, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(strstr(err.message, "absolute path") != NULL);
    CHECK(access(abs_target, F_OK) != 0);

    fresh();
    s[0].path = "/etc/lpm-test-should-never-exist";
    CHECK(build(arc, s, 1, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(access("/etc/lpm-test-should-never-exist", F_OK) != 0);
}

static void test_symlink_with_absolute_target(void)
{
    static const spec s[] = {
        { "usr/lib/link", 'l', "/etc", 0777 },
        { "usr/lib/link/passwd", 'f', "pwned\n", 0644 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 2, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
}

static void test_symlink_with_dotdot_target(void)
{
    char target[700];
    spec s[2];
    lpm_meta_error err;

    fresh();
    snprintf(target, sizeof(target), "../outside");   /* root/../outside */
    s[0].path = "link"; s[0].type = 'l'; s[0].data = target; s[0].mode = 0777;
    s[1].path = "link/pwned.txt"; s[1].type = 'f'; s[1].data = "pwned\n"; s[1].mode = 0644;
    CHECK(build(arc, s, 2, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(!exists(outside, "pwned.txt"));
}

static void test_write_through_archive_symlink(void)
{
    /* The link target is "safe" (relative, no ".."), but a later entry
     * tries to use the link as a directory. Writing through it is
     * refused, whatever it points to. */
    static const spec s[] = {
        { "usr/lib/real/", 'd', NULL, 0755 },
        { "usr/lib/link", 'l', "real", 0777 },
        { "usr/lib/link/passwd", 'f', "pwned\n", 0644 },
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 3, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(strstr(err.message, "symbolic link") != NULL);
}

static void test_preexisting_symlink_in_destination(void)
{
    /* An attacker planted root/usr -> ../outside before extraction. */
    static const spec s[] = { { "usr/bin/tool", 'f', "pwned\n", 0755 } };
    char lnk[700];
    lpm_meta_error err;

    fresh();
    snprintf(lnk, sizeof(lnk), "%s/usr", root);
    CHECK(symlink(outside, lnk) == 0);
    CHECK(build(arc, s, 1, NONE) == 0);
    CHECK(extract(&err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(count_entries(outside) == 0);       /* nothing written through it */
    CHECK(S_ISLNK(mode_of(root, "usr")));     /* and it was not removed */
}

static void test_symlink_file_overwrite_attempt(void)
{
    /* A symlink entry followed by a regular file of the same name: the
     * file must not be written through the link. */
    char target[700];
    spec s[2];
    lpm_meta_error err;

    fresh();
    snprintf(target, sizeof(target), "%s/victim", outside);
    s[0].path = "etc/conf"; s[0].type = 'l'; s[0].data = "conf.real"; s[0].mode = 0777;
    s[1].path = "etc/conf"; s[1].type = 'f'; s[1].data = "pwned\n"; s[1].mode = 0644;
    CHECK(build(arc, s, 2, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(!exists(root, "etc/conf.real"));
}

static void test_hardlinks_rejected(void)
{
    static const spec s[] = {
        { "etc/passwd-copy", 'h', "/etc/passwd", 0644 },
    };
    static const spec s2[] = {
        { "a.txt", 'f', "a\n", 0644 },
        { "b.txt", 'h', "a.txt", 0644 },   /* even an internal one */
    };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, s, 1, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    CHECK(strstr(err.message, "hard link") != NULL);
    fresh();
    CHECK(build(arc, s2, 2, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
}

static void test_special_files_rejected(void)
{
    static const spec fifo[] = { { "dev/fifo", 'p', NULL, 0644 } };
    static const spec dev[]  = { { "dev/mem", 'c', NULL, 0644 } };
    lpm_meta_error err;

    fresh();
    CHECK(build(arc, fifo, 1, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    fresh();
    CHECK(build(arc, dev, 1, NONE) == 0);
    REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
}

static void test_existing_file_not_overwritten(void)
{
    static const spec s[] = { { "etc/example.conf", 'f', "new\n", 0644 } };
    char p[700];
    lpm_meta_error err;
    FILE *f;

    fresh();
    snprintf(p, sizeof(p), "%s/etc", root);
    mkdir(p, 0755);
    snprintf(p, sizeof(p), "%s/etc/example.conf", root);
    f = fopen(p, "w");
    fputs("original\n", f);
    fclose(f);
    CHECK(build(arc, s, 1, NONE) == 0);
    CHECK(extract(&err) == LPM_ERR_CONFLICT);
    CHECK(file_is(root, "etc/example.conf", "original\n"));
    CHECK(S_ISDIR(mode_of(root, "etc")));     /* rollback keeps what existed */
}

static void test_malformed_names_rejected(void)
{
    static const char *const bad[] = {
        "usr//bin/x", "usr/./bin/x", "usr/bin/x\n", "usr/bin/ x", "caf\xc3\xa9",
        "usr/bin/x\x1b[31m",
    };
    lpm_meta_error err;
    size_t i;
    spec s[1];

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        fresh();
        s[0].path = bad[i]; s[0].type = 'f'; s[0].data = "x\n"; s[0].mode = 0644;
        CHECK(build(arc, s, 1, NONE) == 0);
        REJECTED_CLEANLY(extract(&err), LPM_META_ERR_UNSAFE_ENTRY);
    }
}

/* ---- the path cleaner on its own --------------------------------------------- */

static void test_clean_path_rules(void)
{
    char buf[64];
    const char *out;
    lpm_meta_error err;

    CHECK(lpm_archive_clean_path("usr/bin/x", false, buf, sizeof(buf), &out, &err) == LPM_OK);
    CHECK(strcmp(out, "usr/bin/x") == 0);
    CHECK(lpm_archive_clean_path("./usr/", true, buf, sizeof(buf), &out, &err) == LPM_OK);
    CHECK(strcmp(out, "usr") == 0);
    CHECK(lpm_archive_clean_path("./", true, buf, sizeof(buf), &out, &err) == LPM_OK);
    CHECK(out[0] == '\0');
    CHECK(lpm_archive_clean_path("/etc/x", false, buf, sizeof(buf), &out, &err) == LPM_ERR_INVALID);
    CHECK(lpm_archive_clean_path("a/../b", false, buf, sizeof(buf), &out, &err) == LPM_ERR_INVALID);
    CHECK(lpm_archive_clean_path("a/..", true, buf, sizeof(buf), &out, &err) == LPM_ERR_INVALID);
    CHECK(lpm_archive_clean_path("a/b..c", false, buf, sizeof(buf), &out, &err) == LPM_OK);
    CHECK(lpm_archive_clean_path("usr/", false, buf, sizeof(buf), &out, &err) == LPM_ERR_INVALID);
    CHECK(out == NULL);
    CHECK(lpm_archive_clean_path("0123456789012345678901234567890123456789"
                                 "01234567890123456789012345", false, buf,
                                 sizeof(buf), &out, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_TOO_LONG);
}

static void test_symlink_target_rules(void)
{
    CHECK(lpm_is_safe_symlink_target("libfoo.so.1"));
    CHECK(lpm_is_safe_symlink_target("sub/dir/file"));
    CHECK(lpm_is_safe_symlink_target("..hidden"));
    CHECK(!lpm_is_safe_symlink_target("/etc"));
    CHECK(!lpm_is_safe_symlink_target(".."));
    CHECK(!lpm_is_safe_symlink_target("../lib"));
    CHECK(!lpm_is_safe_symlink_target("a/../../b"));
    CHECK(!lpm_is_safe_symlink_target("a//b"));
    CHECK(!lpm_is_safe_symlink_target("a/"));
    CHECK(!lpm_is_safe_symlink_target(""));
    CHECK(!lpm_is_safe_symlink_target(NULL));
    CHECK(!lpm_is_safe_symlink_target("a\nb"));
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    umask(022);

    printf("Running archive extraction unit tests\n");
    RUN(test_normal_extraction);
    RUN(test_compressed_formats);
    RUN(test_nested_directories_created);
    RUN(test_empty_directories);
    RUN(test_safe_relative_symlink);
    RUN(test_dangerous_modes_stripped);
    RUN(test_invalid_archive);
    RUN(test_truncated_archive);
    RUN(test_corrupt_compressed_archive);
    RUN(test_missing_archive_and_destination);
    RUN(test_path_traversal);
    RUN(test_absolute_paths);
    RUN(test_symlink_with_absolute_target);
    RUN(test_symlink_with_dotdot_target);
    RUN(test_write_through_archive_symlink);
    RUN(test_preexisting_symlink_in_destination);
    RUN(test_symlink_file_overwrite_attempt);
    RUN(test_hardlinks_rejected);
    RUN(test_special_files_rejected);
    RUN(test_existing_file_not_overwritten);
    RUN(test_malformed_names_rejected);
    RUN(test_clean_path_rules);
    RUN(test_symlink_target_rules);
    if (base[0])
        rm_tree(base);
    return tf_summary();
}
