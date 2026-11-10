/*
 * test_metadata.c - Unit tests for the metadata parser (Milestone 2).
 *
 *   build/test_metadata [-v] <fixtures-dir>
 *
 *   -v   also print the diagnostic produced for every rejected input
 *
 * Tests assert on return codes, error codes, line numbers and the
 * resulting structures, not merely on "did not crash". Run the debug
 * build (`make debug && make test`) to add AddressSanitizer,
 * LeakSanitizer and UBSan checking on top of these assertions.
 *
 * The binary is linked with -Wl,--wrap=malloc,calloc,realloc so that
 * test_allocation_failures() can make the Nth allocation fail.
 */
#include "metadata.h"
#include "util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ================================================================== */
/* Allocation-failure injection (GNU ld --wrap)                        */
/* ================================================================== */

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

static long alloc_seen;          /* allocations since injection was armed */
static long alloc_fail_at = -1;  /* index of the allocation to fail; -1 = off */

static int inject_failure(void)
{
    if (alloc_fail_at < 0)
        return 0;
    return alloc_seen++ == alloc_fail_at;
}

void *__wrap_malloc(size_t size)
{
    return inject_failure() ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    return inject_failure() ? NULL : __real_calloc(nmemb, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    return inject_failure() ? NULL : __real_realloc(ptr, size);
}

/* ================================================================== */
/* Minimal test framework                                              */
/* ================================================================== */

static int verbose;
static const char *fixture_dir;
static char tmp_dir[512];

static int tests_run, tests_failed, tests_skipped;
static long checks_run;
static int current_failures;
static const char *current_skip;

#define CHECK_AT(cond, at)                                                 \
    do {                                                                   \
        checks_run++;                                                      \
        if (!(cond)) {                                                     \
            current_failures++;                                            \
            fprintf(stderr, "    test_metadata.c:%d: check failed: %s\n",  \
                    (int)(at), #cond);                                     \
        }                                                                  \
    } while (0)

#define CHECK(cond) CHECK_AT(cond, __LINE__)

static void run_test(const char *name, void (*fn)(void))
{
    current_failures = 0;
    current_skip = NULL;
    fn();
    tests_run++;
    if (current_failures > 0) {
        tests_failed++;
        printf("  FAIL  %s\n", name);
    } else if (current_skip != NULL) {
        tests_skipped++;
        printf("  SKIP  %s (%s)\n", name, current_skip);
    } else {
        printf("  PASS  %s\n", name);
    }
    fflush(stdout);
}

#define RUN(fn) run_test(#fn, fn)

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static const char FULL_DIST[] =
    "name=hello\n"
    "version=1.2.0\n"
    "description=A simple hello world program\n"
    "depends=libfoo>=1.0\n"
    "depends=libbar=2.1\n"
    "manifest_sha256=" HEX64 "\n";

static int str_eq(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static int pkg_is_empty(const lpm_package *p)
{
    return p->name == NULL && p->version == NULL && p->description == NULL &&
           p->dependencies == NULL && p->dependency_count == 0 &&
           !p->has_manifest_sha256 && p->manifest_sha256[0] == '\0';
}

static lpm_status parse_ok_at(const char *data, size_t len, lpm_meta_profile prof,
                              lpm_package *pkg, int at)
{
    lpm_meta_error err;
    lpm_status rc = lpm_metadata_parse_buffer(data, len, prof, pkg, &err);

    CHECK_AT(rc == LPM_OK, at);
    if (rc != LPM_OK)
        fprintf(stderr, "    unexpected error (line %zu): %s\n", err.line, err.message);
    CHECK_AT(err.code == LPM_META_ERR_NONE, at);
    return rc;
}

#define PARSE_OK(s, prof, pkg) parse_ok_at((s), strlen(s), (prof), (pkg), __LINE__)
#define PARSE_OK_MEM(d, n, prof, pkg) parse_ok_at((d), (n), (prof), (pkg), __LINE__)

/*
 * Expect a parse to fail with a specific error code and line number,
 * and verify the output object was reset to the empty state even
 * though it started out filled with garbage bytes.
 */
static void expect_fail_at(const char *data, size_t len, lpm_meta_profile prof,
                           lpm_meta_error_code code, size_t line, int at)
{
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    memset(&pkg, 0xA5, sizeof(pkg));
    rc = lpm_metadata_parse_buffer(data, len, prof, &pkg, &err);

    CHECK_AT(rc == LPM_ERR_INVALID, at);
    CHECK_AT(err.code == code, at);
    CHECK_AT(err.line == line, at);
    CHECK_AT(err.message[0] != '\0', at);
    CHECK_AT(pkg_is_empty(&pkg), at);

    if (rc != LPM_ERR_INVALID || err.code != code || err.line != line)
        fprintf(stderr, "    got rc=%d code=%d line=%zu: %s\n",
                (int)rc, (int)err.code, err.line, err.message);
    else if (verbose)
        printf("          -> line %zu: %s\n", err.line, err.message);

    if (rc == LPM_OK)
        lpm_package_free(&pkg);
}

#define EXPECT_FAIL(s, prof, code, line) \
    expect_fail_at((s), strlen(s), (prof), (code), (line), __LINE__)
#define EXPECT_FAIL_MEM(d, n, prof, code, line) \
    expect_fail_at((d), (n), (prof), (code), (line), __LINE__)

/* malloc'd string of n copies of c. */
static char *repeat(char c, size_t n)
{
    char *s = malloc(n + 1);
    if (s == NULL) {
        perror("malloc");
        exit(2);
    }
    memset(s, c, n);
    s[n] = '\0';
    return s;
}

/* malloc'd "<header><value>\n" */
static char *field_line(const char *header, const char *key, const char *value)
{
    size_t len = strlen(header) + strlen(key) + 1 + strlen(value) + 2;
    char *s = malloc(len);
    if (s == NULL) {
        perror("malloc");
        exit(2);
    }
    snprintf(s, len, "%s%s=%s\n", header, key, value);
    return s;
}

/*
 * Valid metadata padded with comment lines to exactly `total` bytes.
 * Every padding line is well below the line limit.
 */
static char *make_padded(size_t total)
{
    static const char header[] = "name=hello\nversion=1.0\n";
    size_t pos = sizeof(header) - 1;
    char *buf = malloc(total + 1);

    if (buf == NULL || total < pos) {
        perror("make_padded");
        exit(2);
    }
    memcpy(buf, header, pos);
    while (pos < total) {
        size_t chunk = total - pos;
        if (chunk > 1001)
            chunk = 1001;
        if (chunk == 1) {
            buf[pos] = '\n';
        } else {
            buf[pos] = '#';
            memset(buf + pos + 1, 'x', chunk - 2);
            buf[pos + chunk - 1] = '\n';
        }
        pos += chunk;
    }
    buf[total] = '\0';
    return buf;
}

/* Create a file in the temp dir; returns 0 on success, path in out. */
static int write_tmp(const char *name, const char *data, size_t len,
                     char *out, size_t out_size)
{
    FILE *fp;

    snprintf(out, out_size, "%s/%s", tmp_dir, name);
    fp = fopen(out, "wb");
    if (fp == NULL)
        return -1;
    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    return fclose(fp) == 0 ? 0 : -1;
}

static void tmp_path(const char *name, char *out, size_t out_size)
{
    snprintf(out, out_size, "%s/%s", tmp_dir, name);
}

static void fixture_path(const char *name, char *out, size_t out_size)
{
    snprintf(out, out_size, "%s/%s", fixture_dir, name);
}

/* Structural invariants every successfully parsed package must satisfy. */
static int package_invariants_hold(const lpm_package *p)
{
    size_t i, j;

    if (!lpm_is_valid_package_name(p->name) || !lpm_is_valid_version(p->version))
        return 0;
    if (p->dependency_count > LPM_META_MAX_DEPENDS)
        return 0;
    if ((p->dependency_count == 0) != (p->dependencies == NULL))
        return 0;
    if (p->description && strlen(p->description) > LPM_META_MAX_DESC_LEN)
        return 0;
    if (p->has_manifest_sha256 != lpm_is_valid_sha256_hex(p->manifest_sha256))
        return 0;
    for (i = 0; i < p->dependency_count; i++) {
        const lpm_dependency *d = &p->dependencies[i];
        if (!lpm_is_valid_package_name(d->name) || !lpm_is_valid_version(d->version))
            return 0;
        if (d->op != LPM_DEP_EXACT && d->op != LPM_DEP_MINIMUM)
            return 0;
        if (strcmp(d->name, p->name) == 0)
            return 0;
        for (j = 0; j < i; j++)
            if (strcmp(p->dependencies[j].name, d->name) == 0)
                return 0;
    }
    return 1;
}

/* ================================================================== */
/* Positive tests                                                      */
/* ================================================================== */

static void test_minimal_installed(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=hello\nversion=1.0\n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.name, "hello"));
    CHECK(str_eq(pkg.version, "1.0"));
    CHECK(pkg.description == NULL);
    CHECK(pkg.dependency_count == 0);
    CHECK(pkg.dependencies == NULL);
    CHECK(!pkg.has_manifest_sha256);
    CHECK(pkg.manifest_sha256[0] == '\0');
    lpm_package_free(&pkg);
}

static void test_full_distributable(void)
{
    lpm_package pkg;

    if (PARSE_OK(FULL_DIST, LPM_META_DISTRIBUTABLE, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.name, "hello"));
    CHECK(str_eq(pkg.version, "1.2.0"));
    CHECK(str_eq(pkg.description, "A simple hello world program"));
    CHECK(pkg.dependency_count == 2);
    if (pkg.dependency_count == 2) {
        CHECK(str_eq(pkg.dependencies[0].name, "libfoo"));
        CHECK(pkg.dependencies[0].op == LPM_DEP_MINIMUM);
        CHECK(str_eq(pkg.dependencies[0].version, "1.0"));
        CHECK(str_eq(pkg.dependencies[1].name, "libbar"));
        CHECK(pkg.dependencies[1].op == LPM_DEP_EXACT);
        CHECK(str_eq(pkg.dependencies[1].version, "2.1"));
    }
    CHECK(pkg.has_manifest_sha256);
    CHECK(strcmp(pkg.manifest_sha256, HEX64) == 0);
    CHECK(package_invariants_hold(&pkg));
    lpm_package_free(&pkg);
}

static void test_description_preserves_internal_spaces(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=a\nversion=1\ndescription=   A  simple\thello   world   \n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.description, "A  simple\thello   world"));
    lpm_package_free(&pkg);
}

static void test_empty_description(void)
{
    lpm_package pkg;

    /* Policy: an empty description is allowed and stored as "" (not
     * NULL), so "present but empty" differs from "absent". */
    if (PARSE_OK("name=a\nversion=1\ndescription=\n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.description, ""));
    lpm_package_free(&pkg);

    if (PARSE_OK("name=a\nversion=1\ndescription=  \t  \n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.description, ""));
    lpm_package_free(&pkg);
}

static void test_one_dependency(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=app\nversion=1\ndepends=libfoo>=1.0\n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(pkg.dependency_count == 1);
    CHECK(pkg.dependencies != NULL);
    if (pkg.dependency_count == 1) {
        CHECK(str_eq(pkg.dependencies[0].name, "libfoo"));
        CHECK(str_eq(pkg.dependencies[0].version, "1.0"));
    }
    lpm_package_free(&pkg);
}

static void test_multiple_dependencies(void)
{
    static const char *names[] = { "libc", "libfoo", "libbar", "gtk+-3.0", "libstdc++" };
    lpm_package pkg;
    size_t i;

    if (PARSE_OK("name=app\nversion=1\n"
                 "depends=libc>=2.40\n"
                 "depends=libfoo>=1.0\n"
                 "depends=libbar=2.1\n"
                 "depends=gtk+-3.0=3\n"
                 "depends=libstdc++>=0\n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(pkg.dependency_count == 5);
    for (i = 0; i < pkg.dependency_count && i < 5; i++)
        CHECK(str_eq(pkg.dependencies[i].name, names[i]));   /* order kept */
    CHECK(package_invariants_hold(&pkg));
    lpm_package_free(&pkg);
}

static void test_exact_dependency(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=app\nversion=1\ndepends=zlib=1.3\n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(pkg.dependency_count == 1);
    if (pkg.dependency_count == 1) {
        CHECK(str_eq(pkg.dependencies[0].name, "zlib"));
        CHECK(pkg.dependencies[0].op == LPM_DEP_EXACT);
        CHECK(str_eq(pkg.dependencies[0].version, "1.3"));
        CHECK(str_eq(lpm_dep_operator_str(pkg.dependencies[0].op), "="));
    }
    lpm_package_free(&pkg);
}

static void test_minimum_dependency(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=app\nversion=1\ndepends=openssl>=3.0\n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(pkg.dependency_count == 1);
    if (pkg.dependency_count == 1) {
        CHECK(str_eq(pkg.dependencies[0].name, "openssl"));
        CHECK(pkg.dependencies[0].op == LPM_DEP_MINIMUM);
        CHECK(str_eq(pkg.dependencies[0].version, "3.0"));
        CHECK(str_eq(lpm_dep_operator_str(pkg.dependencies[0].op), ">="));
    }
    lpm_package_free(&pkg);
}

static void test_valid_versions(void)
{
    static const char *ok[] = {
        "0", "1", "1.0", "1.2.3", "16.2.0", "0.0.1", "10.20.30.40",
        "2024.11.10", "123456789012345678901234567890",
    };
    size_t i;

    for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        char buf[128];
        lpm_package pkg;

        CHECK(lpm_is_valid_version(ok[i]));
        snprintf(buf, sizeof(buf), "name=a\nversion=%s\n", ok[i]);
        if (PARSE_OK(buf, LPM_META_INSTALLED, &pkg) == LPM_OK) {
            CHECK(str_eq(pkg.version, ok[i]));
            lpm_package_free(&pkg);
        }
    }
}

static void test_valid_sha256(void)
{
    lpm_package pkg;

    CHECK(lpm_is_valid_sha256_hex(HEX64));
    CHECK(!lpm_is_valid_sha256_hex(NULL));
    CHECK(!lpm_is_valid_sha256_hex(""));
    if (PARSE_OK("name=a\nversion=1\nmanifest_sha256=" HEX64 "\n",
                 LPM_META_DISTRIBUTABLE, &pkg) != LPM_OK)
        return;
    CHECK(pkg.has_manifest_sha256);
    CHECK(strcmp(pkg.manifest_sha256, HEX64) == 0);
    CHECK(strlen(pkg.manifest_sha256) == LPM_SHA256_HEX_LEN);
    lpm_package_free(&pkg);
}

static void test_whitespace_policy(void)
{
    lpm_package pkg;

    if (PARSE_OK("  name =  hello  \n\tversion\t=\t1.0\t\n  depends =  libfoo>=1.0 \n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.name, "hello"));
    CHECK(str_eq(pkg.version, "1.0"));
    CHECK(pkg.dependency_count == 1);
    if (pkg.dependency_count == 1)
        CHECK(str_eq(pkg.dependencies[0].version, "1.0"));
    lpm_package_free(&pkg);
}

static void test_blank_lines(void)
{
    lpm_package pkg;

    if (PARSE_OK("\n\n   \n\t\nname=hello\n\n \t \nversion=1.0\n\n\n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.name, "hello"));
    lpm_package_free(&pkg);
}

static void test_comments(void)
{
    lpm_package pkg;

    if (PARSE_OK("# leading comment\n"
                 "   # indented comment\n"
                 "\t# tab-indented comment\n"
                 "name=hello\n"
                 "#version=9.9\n"
                 "version=1.0\n"
                 "description=Inline # is not a comment\n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.version, "1.0"));
    CHECK(str_eq(pkg.description, "Inline # is not a comment"));
    lpm_package_free(&pkg);
}

static void test_crlf_line_endings(void)
{
    lpm_package pkg;

    /* Policy: LF and CRLF terminators are both accepted, also mixed. */
    if (PARSE_OK("name=hello\r\nversion=1.0\r\ndescription=x\r\n",
                 LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.name, "hello"));
    CHECK(str_eq(pkg.version, "1.0"));      /* no stray '\r' */
    CHECK(str_eq(pkg.description, "x"));
    lpm_package_free(&pkg);

    if (PARSE_OK("name=hello\r\nversion=1.0\n", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    lpm_package_free(&pkg);

    /* A CR that is not part of CRLF is a control character. */
    EXPECT_FAIL("name=hello\rversion=1.0\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 1);
    EXPECT_FAIL("name=hello\nversion=1.0\r", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 2);
}

static void test_no_trailing_newline(void)
{
    lpm_package pkg;

    if (PARSE_OK("name=hello\nversion=1.0", LPM_META_INSTALLED, &pkg) != LPM_OK)
        return;
    CHECK(str_eq(pkg.version, "1.0"));
    lpm_package_free(&pkg);
}

static void test_ownership_and_cleanup(void)
{
    lpm_package pkg, zero;

    /* Zero-initialised object: free is a no-op, repeatedly. */
    memset(&zero, 0, sizeof(zero));
    lpm_package_free(&zero);
    lpm_package_free(&zero);
    lpm_package_free(&zero);
    CHECK(pkg_is_empty(&zero));
    lpm_package_free(NULL);

    /* Fully populated: free resets to empty; a second free is safe;
     * the object can then be reused for another parse. */
    if (PARSE_OK(FULL_DIST, LPM_META_DISTRIBUTABLE, &pkg) != LPM_OK)
        return;
    lpm_package_free(&pkg);
    CHECK(pkg_is_empty(&pkg));
    lpm_package_free(&pkg);
    CHECK(pkg_is_empty(&pkg));
    if (PARSE_OK(FULL_DIST, LPM_META_DISTRIBUTABLE, &pkg) != LPM_OK)
        return;
    CHECK(pkg.dependency_count == 2);
    lpm_package_free(&pkg);

    /* Partially constructed by hand: spare capacity beyond
     * dependency_count is never touched by lpm_package_free(). */
    lpm_package_init(&pkg);
    pkg.name = lpm_strdup("partial");
    pkg.dependencies = malloc(4 * sizeof(*pkg.dependencies));
    CHECK(pkg.name != NULL && pkg.dependencies != NULL);
    if (pkg.dependencies != NULL) {
        pkg.dependencies[0].name = lpm_strdup("dep");
        pkg.dependencies[0].version = lpm_strdup("1");
        pkg.dependencies[0].op = LPM_DEP_EXACT;
        pkg.dependency_count = 1;
    }
    lpm_package_free(&pkg);
    CHECK(pkg_is_empty(&pkg));
}

/* ================================================================== */
/* Negative tests                                                      */
/* ================================================================== */

static void test_empty_input(void)
{
    EXPECT_FAIL("", LPM_META_INSTALLED, LPM_META_ERR_MISSING_FIELD, 0);
    EXPECT_FAIL_MEM(NULL, 0, LPM_META_INSTALLED, LPM_META_ERR_MISSING_FIELD, 0);
    EXPECT_FAIL("# only a comment\n\n", LPM_META_INSTALLED, LPM_META_ERR_MISSING_FIELD, 0);
}

static void test_missing_name(void)
{
    lpm_package pkg;
    lpm_meta_error err;

    EXPECT_FAIL("version=1.0\n", LPM_META_INSTALLED, LPM_META_ERR_MISSING_FIELD, 0);
    lpm_metadata_parse_buffer("version=1.0\n", 12, LPM_META_INSTALLED, &pkg, &err);
    CHECK(str_eq(err.field, "name"));
}

static void test_missing_version(void)
{
    lpm_package pkg;
    lpm_meta_error err;

    EXPECT_FAIL("name=hello\n", LPM_META_INSTALLED, LPM_META_ERR_MISSING_FIELD, 0);
    lpm_metadata_parse_buffer("name=hello\n", 11, LPM_META_INSTALLED, &pkg, &err);
    CHECK(str_eq(err.field, "version"));
}

static void test_duplicate_name(void)
{
    EXPECT_FAIL("name=a\nname=b\nversion=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_DUPLICATE_KEY, 2);
    /* Even an identical repeat is rejected: one key, one occurrence. */
    EXPECT_FAIL("name=a\nversion=1\nname=a\n", LPM_META_INSTALLED,
                LPM_META_ERR_DUPLICATE_KEY, 3);
}

static void test_duplicate_version(void)
{
    EXPECT_FAIL("name=a\nversion=1\nversion=2\n", LPM_META_INSTALLED,
                LPM_META_ERR_DUPLICATE_KEY, 3);
}

static void test_duplicate_manifest(void)
{
    EXPECT_FAIL("name=a\nversion=1\nmanifest_sha256=" HEX64 "\nmanifest_sha256=" HEX64 "\n",
                LPM_META_DISTRIBUTABLE, LPM_META_ERR_DUPLICATE_KEY, 4);
}

static void test_duplicate_description(void)
{
    EXPECT_FAIL("name=a\nversion=1\ndescription=\ndescription=x\n",
                LPM_META_INSTALLED, LPM_META_ERR_DUPLICATE_KEY, 4);
}

static void test_unsupported_key(void)
{
    EXPECT_FAIL("name=a\nversion=1\nlicense=MIT\n", LPM_META_INSTALLED,
                LPM_META_ERR_UNKNOWN_KEY, 3);
    EXPECT_FAIL("Name=hello\nversion=1\n", LPM_META_INSTALLED,   /* case-sensitive */
                LPM_META_ERR_UNKNOWN_KEY, 1);
    EXPECT_FAIL("name=a\nversion=1\narch=x86_64\n", LPM_META_INSTALLED,
                LPM_META_ERR_UNKNOWN_KEY, 3);
}

static void test_missing_equals(void)
{
    EXPECT_FAIL("name hello\nversion=1\n", LPM_META_INSTALLED, LPM_META_ERR_SYNTAX, 1);
    EXPECT_FAIL("name=a\nversion=1\njunk\n", LPM_META_INSTALLED, LPM_META_ERR_SYNTAX, 3);
    EXPECT_FAIL("=hello\n", LPM_META_INSTALLED, LPM_META_ERR_SYNTAX, 1);
    EXPECT_FAIL("na me=hello\n", LPM_META_INSTALLED, LPM_META_ERR_SYNTAX, 1);
    EXPECT_FAIL("name.x=hello\n", LPM_META_INSTALLED, LPM_META_ERR_SYNTAX, 1);
}

static void test_empty_name(void)
{
    EXPECT_FAIL("name=\nversion=1\n", LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 1);
    EXPECT_FAIL("name=   \nversion=1\n", LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 1);
}

static void test_invalid_names(void)
{
    static const char *bad[] = {
        "../hello", "/hello", "hello/world", "Hello", "-rf", ".hidden",
        "..", ".", "hel lo", "hello\\", "hello*", "hello;rm", "_x", "+x",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "name=%s\nversion=1\n", bad[i]);
        EXPECT_FAIL(buf, LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 1);
        CHECK(!lpm_is_valid_package_name(bad[i]));
    }
}

static void test_invalid_versions(void)
{
    static const char *bad[] = {
        "1..2", ".1", "1.", "1.2beta", "v1.0", "1.0-rc1", "01", "1.02", "00",
        "1 .0", "1. 0", "-1", "1,0", "+1", "..", "1e3", "0x10", "1.0.", "1.0_1",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "name=a\nversion=%s\n", bad[i]);
        EXPECT_FAIL(buf, LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 2);
        CHECK(!lpm_is_valid_version(bad[i]));
    }
    CHECK(!lpm_is_valid_version(NULL));
    CHECK(!lpm_is_valid_version(""));
    EXPECT_FAIL("name=a\nversion=\n", LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 2);
}

static void test_invalid_dependency_names(void)
{
    static const char *bad[] = {
        "Libfoo>=1", "../x>=1", "lib foo>=1", "-x>=1", "/x=1", "lib/foo=1",
        "lib\\foo=1", ".x>=1",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "name=a\nversion=1\ndepends=%s\n", bad[i]);
        EXPECT_FAIL(buf, LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 3);
    }
}

static void test_missing_dependency_version(void)
{
    static const char *bad[] = {
        "libfoo>=", "libfoo=", "libfoo", ">=1.0", "=1.0", "libfoo>= ", "libfoo>=1..0",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "name=a\nversion=1\ndepends=%s\n", bad[i]);
        EXPECT_FAIL(buf, LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 3);
    }
    EXPECT_FAIL("name=a\nversion=1\ndepends=\n", LPM_META_INSTALLED,
                LPM_META_ERR_INVALID_VALUE, 3);
}

static void test_unsupported_dependency_operators(void)
{
    static const char *bad[] = {
        "libfoo<1", "libfoo<=1", "libfoo>1", "libfoo!=1", "libfoo~1", "libfoo^1",
        "libfoo==1", "libfoo>==1", "libfoo~=1", "libfoo=>1", "libfoo=<1",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char buf[128];
        lpm_package pkg;
        lpm_meta_error err;

        snprintf(buf, sizeof(buf), "name=a\nversion=1\ndepends=%s\n", bad[i]);
        EXPECT_FAIL(buf, LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 3);
        lpm_metadata_parse_buffer(buf, strlen(buf), LPM_META_INSTALLED, &pkg, &err);
        CHECK(strstr(err.message, "unsupported operator") != NULL);
    }
}

static void test_duplicate_dependencies(void)
{
    static const char input[] =
        "name=app\nversion=1\n"
        "depends=libfoo>=1\n"
        "depends=libbar=1\n"
        "depends=libfoo=2\n";   /* different constraint, same package */
    lpm_package pkg;
    lpm_meta_error err;

    EXPECT_FAIL(input, LPM_META_INSTALLED, LPM_META_ERR_DUPLICATE_DEPEND, 5);
    lpm_metadata_parse_buffer(input, strlen(input), LPM_META_INSTALLED, &pkg, &err);
    CHECK(strstr(err.message, "line 3") != NULL);   /* points at the first one */
}

static void test_self_dependency(void)
{
    EXPECT_FAIL("name=a\nversion=1\ndepends=b>=1\ndepends=a>=1\n",
                LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 4);
    /* Detected even when depends= comes before name=. */
    EXPECT_FAIL("depends=a>=1\nname=a\nversion=1\n",
                LPM_META_INSTALLED, LPM_META_ERR_INVALID_VALUE, 1);
}

static void test_sha256_length(void)
{
    const char *hdr = "name=a\nversion=1\n";
    char *short_hex = repeat('a', LPM_SHA256_HEX_LEN - 1);
    char *long_hex = repeat('a', LPM_SHA256_HEX_LEN + 1);
    char *s;

    s = field_line(hdr, "manifest_sha256", short_hex);
    EXPECT_FAIL(s, LPM_META_DISTRIBUTABLE, LPM_META_ERR_INVALID_VALUE, 3);
    free(s);
    s = field_line(hdr, "manifest_sha256", long_hex);
    EXPECT_FAIL(s, LPM_META_DISTRIBUTABLE, LPM_META_ERR_INVALID_VALUE, 3);
    free(s);
    EXPECT_FAIL("name=a\nversion=1\nmanifest_sha256=\n", LPM_META_DISTRIBUTABLE,
                LPM_META_ERR_INVALID_VALUE, 3);
    CHECK(!lpm_is_valid_sha256_hex(short_hex));
    CHECK(!lpm_is_valid_sha256_hex(long_hex));
    free(short_hex);
    free(long_hex);
}

static void test_sha256_invalid_hex(void)
{
    /* 'g' is not hex; uppercase is rejected by policy; space inside. */
    EXPECT_FAIL("name=a\nversion=1\nmanifest_sha256="
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\n",
                LPM_META_DISTRIBUTABLE, LPM_META_ERR_INVALID_VALUE, 3);
    EXPECT_FAIL("name=a\nversion=1\nmanifest_sha256="
                "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\n",
                LPM_META_DISTRIBUTABLE, LPM_META_ERR_INVALID_VALUE, 3);
    EXPECT_FAIL("name=a\nversion=1\nmanifest_sha256="
                "0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef\n",
                LPM_META_DISTRIBUTABLE, LPM_META_ERR_INVALID_VALUE, 3);
    CHECK(!lpm_is_valid_sha256_hex(
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));
}

static void test_distributable_requires_digest(void)
{
    static const char input[] = "name=hello\nversion=1.0\n";
    lpm_package pkg;
    lpm_meta_error err;

    /* Same bytes: fine as an installed record, not as a .pkg. */
    if (PARSE_OK(input, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);
    EXPECT_FAIL(input, LPM_META_DISTRIBUTABLE, LPM_META_ERR_MISSING_FIELD, 0);
    lpm_metadata_parse_buffer(input, strlen(input), LPM_META_DISTRIBUTABLE, &pkg, &err);
    CHECK(str_eq(err.field, "manifest_sha256"));
}

/* ================================================================== */
/* Boundary tests: exactly at each limit, and one above it            */
/* ================================================================== */

static void test_name_length_boundary(void)
{
    char *at = repeat('a', LPM_MAX_NAME_LEN);
    char *over = repeat('a', LPM_MAX_NAME_LEN + 1);
    char *s, *dep;
    lpm_package pkg;
    size_t len;

    s = field_line("version=1\n", "name", at);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK) {
        CHECK(strlen(pkg.name) == LPM_MAX_NAME_LEN);
        lpm_package_free(&pkg);
    }
    free(s);
    s = field_line("version=1\n", "name", over);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_LONG, 2);
    free(s);

    /* Dependency names share the same limit. */
    len = LPM_MAX_NAME_LEN + 4;
    dep = malloc(len + 1);
    CHECK(dep != NULL);
    if (dep == NULL)
        goto out;
    snprintf(dep, len + 1, "%s>=1", at);
    s = field_line("name=x\nversion=1\n", "depends", dep);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);
    free(s);
    free(dep);

    len = LPM_MAX_NAME_LEN + 5;
    dep = malloc(len + 1);
    CHECK(dep != NULL);
    if (dep == NULL)
        goto out;
    snprintf(dep, len + 1, "%s>=1", over);
    s = field_line("name=x\nversion=1\n", "depends", dep);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_LONG, 3);
    free(s);
    free(dep);
out:
    free(at);
    free(over);
}

static void test_version_length_boundary(void)
{
    char *at = repeat('1', LPM_META_MAX_VERSION_LEN);
    char *over = repeat('1', LPM_META_MAX_VERSION_LEN + 1);
    char dep[LPM_META_MAX_VERSION_LEN + 16];
    char *s;
    lpm_package pkg;

    s = field_line("name=a\n", "version", at);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK) {
        CHECK(strlen(pkg.version) == LPM_META_MAX_VERSION_LEN);
        lpm_package_free(&pkg);
    }
    free(s);
    s = field_line("name=a\n", "version", over);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_LONG, 2);
    free(s);

    snprintf(dep, sizeof(dep), "x>=%s", at);
    s = field_line("name=a\nversion=1\n", "depends", dep);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);
    free(s);
    snprintf(dep, sizeof(dep), "x>=%s", over);
    s = field_line("name=a\nversion=1\n", "depends", dep);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_LONG, 3);
    free(s);

    free(at);
    free(over);
}

static void test_description_length_boundary(void)
{
    char *at = repeat('d', LPM_META_MAX_DESC_LEN);
    char *over = repeat('d', LPM_META_MAX_DESC_LEN + 1);
    char *s;
    lpm_package pkg;

    s = field_line("name=a\nversion=1\n", "description", at);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK) {
        CHECK(strlen(pkg.description) == LPM_META_MAX_DESC_LEN);
        lpm_package_free(&pkg);
    }
    free(s);
    s = field_line("name=a\nversion=1\n", "description", over);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_LONG, 3);
    free(s);
    free(at);
    free(over);
}

/* "name=app\nversion=1\n" followed by n depends= lines. */
static char *make_deps(size_t n)
{
    size_t cap = 32 + n * 24, pos, i;
    char *buf = malloc(cap);

    if (buf == NULL) {
        perror("malloc");
        exit(2);
    }
    pos = (size_t)snprintf(buf, cap, "name=app\nversion=1\n");
    for (i = 0; i < n; i++)
        pos += (size_t)snprintf(buf + pos, cap - pos, "depends=dep%zu>=1\n", i);
    return buf;
}

static void test_dependency_count_boundary(void)
{
    char *s;
    lpm_package pkg;

    s = make_deps(LPM_META_MAX_DEPENDS);
    if (PARSE_OK(s, LPM_META_INSTALLED, &pkg) == LPM_OK) {
        CHECK(pkg.dependency_count == LPM_META_MAX_DEPENDS);
        CHECK(str_eq(pkg.dependencies[LPM_META_MAX_DEPENDS - 1].name, "dep127"));
        CHECK(package_invariants_hold(&pkg));
        lpm_package_free(&pkg);
    }
    free(s);

    /* The 129th depends= is on line 2 + 129 = 131. */
    s = make_deps(LPM_META_MAX_DEPENDS + 1);
    EXPECT_FAIL(s, LPM_META_INSTALLED, LPM_META_ERR_TOO_MANY_DEPENDS,
                (size_t)LPM_META_MAX_DEPENDS + 3);
    free(s);
}

static void test_file_size_boundary(void)
{
    char *at = make_padded(LPM_META_MAX_FILE_SIZE);
    char *over = make_padded((size_t)LPM_META_MAX_FILE_SIZE + 1);
    lpm_package pkg;

    if (PARSE_OK_MEM(at, LPM_META_MAX_FILE_SIZE, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);
    /* Rejected before any line is looked at: error is for line 0. */
    EXPECT_FAIL_MEM(over, (size_t)LPM_META_MAX_FILE_SIZE + 1, LPM_META_INSTALLED,
                    LPM_META_ERR_FILE_TOO_LARGE, 0);
    free(at);
    free(over);
}

static void test_line_length_boundary(void)
{
    const char *hdr = "name=a\nversion=1\n";
    size_t hlen = strlen(hdr);
    size_t n = LPM_META_MAX_LINE_LEN;
    char *buf = malloc(hlen + n + 3);
    lpm_package pkg;

    CHECK(buf != NULL);
    if (buf == NULL)
        return;

    /* Exactly at the limit: "#" + (n-1) x */
    memcpy(buf, hdr, hlen);
    buf[hlen] = '#';
    memset(buf + hlen + 1, 'x', n - 1);
    buf[hlen + n] = '\n';
    if (PARSE_OK_MEM(buf, hlen + n + 1, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);

    /* At the limit with CRLF: the CR is a terminator, not content. */
    buf[hlen + n] = '\r';
    buf[hlen + n + 1] = '\n';
    if (PARSE_OK_MEM(buf, hlen + n + 2, LPM_META_INSTALLED, &pkg) == LPM_OK)
        lpm_package_free(&pkg);

    /* One byte over. */
    buf[hlen + n] = 'x';
    buf[hlen + n + 1] = '\n';
    EXPECT_FAIL_MEM(buf, hlen + n + 2, LPM_META_INSTALLED, LPM_META_ERR_LINE_TOO_LONG, 3);

    /* An over-long final line with no newline is caught the same way. */
    EXPECT_FAIL_MEM(buf, hlen + n + 1, LPM_META_INSTALLED, LPM_META_ERR_LINE_TOO_LONG, 3);
    free(buf);
}

/* ================================================================== */
/* Encoding / byte-level tests                                         */
/* ================================================================== */

static void test_embedded_nul(void)
{
    static const char a[] = "name=hel\0lo\nversion=1\n";
    static const char b[] = "#\0 comment\nname=a\nversion=1\n";
    static const char c[] = "name=a\nversion=1\n\0";

    EXPECT_FAIL_MEM(a, sizeof(a) - 1, LPM_META_INSTALLED, LPM_META_ERR_NUL_BYTE, 1);
    EXPECT_FAIL_MEM(b, sizeof(b) - 1, LPM_META_INSTALLED, LPM_META_ERR_NUL_BYTE, 1);
    EXPECT_FAIL_MEM(c, sizeof(c) - 1, LPM_META_INSTALLED, LPM_META_ERR_NUL_BYTE, 3);
}

static void test_control_characters(void)
{
    EXPECT_FAIL("name=a\nversion=1\ndescription=\x1b[31mred\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 3);
    EXPECT_FAIL("name=a\x01" "b\nversion=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 1);
    EXPECT_FAIL("name=a\nversion=1\x7f\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 2);
    EXPECT_FAIL("name=a\vb\nversion=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 1);
    EXPECT_FAIL("name=a\nversion=1\f\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 2);
    /* Control characters inside comments are rejected too. */
    EXPECT_FAIL("# \x07 bell\nname=a\nversion=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_CONTROL_CHAR, 1);
}

static void test_non_ascii(void)
{
    EXPECT_FAIL("name=a\nversion=1\ndescription=caf\xc3\xa9\n", LPM_META_INSTALLED,
                LPM_META_ERR_ENCODING, 3);
    EXPECT_FAIL("\xef\xbb\xbfname=a\nversion=1\n", LPM_META_INSTALLED,   /* UTF-8 BOM */
                LPM_META_ERR_ENCODING, 1);
    EXPECT_FAIL("name=a\xff\nversion=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_ENCODING, 1);
}

/* ================================================================== */
/* File input tests                                                    */
/* ================================================================== */

static void test_missing_file(void)
{
    char path[1024];
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    tmp_path("does-not-exist.meta", path, sizeof(path));
    memset(&pkg, 0xA5, sizeof(pkg));
    rc = lpm_metadata_parse_file(path, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_NOT_FOUND);
    CHECK(err.code == LPM_META_ERR_IO);
    CHECK(pkg_is_empty(&pkg));
}

static void test_non_regular_inputs(void)
{
    char file[1024], lnk[1024], fifo[1024];
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    /* A directory. */
    rc = lpm_metadata_parse_file(tmp_dir, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_NOT_REGULAR);
    CHECK(pkg_is_empty(&pkg));

    /* A symlink to a perfectly valid file is still refused. */
    CHECK(write_tmp("target.meta", "name=a\nversion=1\n", 17, file, sizeof(file)) == 0);
    tmp_path("link.meta", lnk, sizeof(lnk));
    CHECK(symlink(file, lnk) == 0);
    rc = lpm_metadata_parse_file(lnk, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_NOT_REGULAR);
    CHECK(pkg_is_empty(&pkg));
    rc = lpm_metadata_parse_file(file, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_OK);
    lpm_package_free(&pkg);

    /* A FIFO: must be rejected without blocking on open or read. */
    tmp_path("fifo.meta", fifo, sizeof(fifo));
    CHECK(mkfifo(fifo, 0600) == 0);
    rc = lpm_metadata_parse_file(fifo, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_NOT_REGULAR);

    /* /dev/null is a character device, not metadata. */
    rc = lpm_metadata_parse_file("/dev/null", LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_NOT_REGULAR);
}

static void test_permission_denied(void)
{
    char path[1024];
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    if (geteuid() == 0) {
        current_skip = "running as root: file permissions are not enforced";
        return;
    }
    CHECK(write_tmp("noperm.meta", "name=a\nversion=1\n", 17, path, sizeof(path)) == 0);
    CHECK(chmod(path, 0) == 0);
    rc = lpm_metadata_parse_file(path, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_IO);
    CHECK(err.code == LPM_META_ERR_IO);
    CHECK(pkg_is_empty(&pkg));
    chmod(path, 0600);
}

static void test_oversized_file(void)
{
    char path[1024];
    char *at = make_padded(LPM_META_MAX_FILE_SIZE);
    char *over = make_padded((size_t)LPM_META_MAX_FILE_SIZE + 1);
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    CHECK(write_tmp("at-limit.meta", at, LPM_META_MAX_FILE_SIZE, path, sizeof(path)) == 0);
    rc = lpm_metadata_parse_file(path, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_OK);
    lpm_package_free(&pkg);

    CHECK(write_tmp("over-limit.meta", over, (size_t)LPM_META_MAX_FILE_SIZE + 1,
                    path, sizeof(path)) == 0);
    rc = lpm_metadata_parse_file(path, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_FILE_TOO_LARGE);
    CHECK(pkg_is_empty(&pkg));
    free(at);
    free(over);
}

static void test_raw_bytes_are_preserved(void)
{
    /* The future signature check needs the exact file bytes, CRs and
     * comments included; read_file must return them unchanged. */
    static const char raw[] = "# signed\r\nname=a\r\nversion=1\n";
    char path[1024];
    char *data;
    size_t len;
    lpm_meta_error err;

    CHECK(write_tmp("raw.meta", raw, sizeof(raw) - 1, path, sizeof(path)) == 0);
    CHECK(lpm_metadata_read_file(path, &data, &len, &err) == LPM_OK);
    CHECK(len == sizeof(raw) - 1);
    CHECK(data != NULL && memcmp(data, raw, len) == 0);
    free(data);
}

static void test_fixture_files(void)
{
    static const struct {
        const char *file;
        lpm_meta_profile profile;
        lpm_status rc;
        lpm_meta_error_code code;
        size_t line;
    } cases[] = {
        { "valid-installed.meta",           LPM_META_INSTALLED,     LPM_OK, LPM_META_ERR_NONE, 0 },
        { "valid-distributable.meta",       LPM_META_DISTRIBUTABLE, LPM_OK, LPM_META_ERR_NONE, 0 },
        { "valid-comments-whitespace.meta", LPM_META_INSTALLED,     LPM_OK, LPM_META_ERR_NONE, 0 },
        { "valid-installed.meta",           LPM_META_DISTRIBUTABLE, LPM_ERR_INVALID, LPM_META_ERR_MISSING_FIELD, 0 },
        { "invalid-missing-version.meta",   LPM_META_INSTALLED,     LPM_ERR_INVALID, LPM_META_ERR_MISSING_FIELD, 0 },
        { "invalid-duplicate-name.meta",    LPM_META_INSTALLED,     LPM_ERR_INVALID, LPM_META_ERR_DUPLICATE_KEY, 2 },
        { "invalid-unknown-key.meta",       LPM_META_INSTALLED,     LPM_ERR_INVALID, LPM_META_ERR_UNKNOWN_KEY, 3 },
        { "invalid-dependency.meta",        LPM_META_INSTALLED,     LPM_ERR_INVALID, LPM_META_ERR_INVALID_VALUE, 4 },
        { "invalid-sha256.meta",            LPM_META_DISTRIBUTABLE, LPM_ERR_INVALID, LPM_META_ERR_INVALID_VALUE, 3 },
        { "invalid-path-name.meta",         LPM_META_INSTALLED,     LPM_ERR_INVALID, LPM_META_ERR_INVALID_VALUE, 1 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char path[1024];
        lpm_package pkg;
        lpm_meta_error err;
        lpm_status rc;

        fixture_path(cases[i].file, path, sizeof(path));
        rc = lpm_metadata_parse_file(path, cases[i].profile, &pkg, &err);
        CHECK(rc == cases[i].rc);
        CHECK(err.code == cases[i].code);
        CHECK(err.line == cases[i].line);
        if (rc != cases[i].rc || err.code != cases[i].code || err.line != cases[i].line)
            fprintf(stderr, "    %s: rc=%d code=%d line=%zu: %s\n", cases[i].file,
                    (int)rc, (int)err.code, err.line, err.message);
        else if (verbose && rc != LPM_OK) {
            char msg[512];
            lpm_meta_error_format(&err, cases[i].file, msg, sizeof(msg));
            printf("          -> %s\n", msg);
        }
        if (rc == LPM_OK) {
            CHECK(package_invariants_hold(&pkg));
            lpm_package_free(&pkg);
        } else {
            CHECK(pkg_is_empty(&pkg));
        }
    }
}

/* ================================================================== */
/* Failure-path and robustness tests                                   */
/* ================================================================== */

static void test_error_then_valid_input(void)
{
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    /* The parser stops at the first problem; later valid lines do not
     * "rescue" a malformed file. */
    EXPECT_FAIL("garbage\nname=hello\nversion=1.0\n", LPM_META_INSTALLED,
                LPM_META_ERR_SYNTAX, 1);

    /* The same objects can be reused right away; no state carries over. */
    rc = lpm_metadata_parse_buffer("garbage\n", 8, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_ERR_INVALID);
    rc = lpm_metadata_parse_buffer("name=hello\nversion=1.0\n", 23,
                                   LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_OK);
    CHECK(err.code == LPM_META_ERR_NONE);
    CHECK(err.message[0] == '\0');
    CHECK(str_eq(pkg.name, "hello"));
    lpm_package_free(&pkg);
}

static void test_cleanup_after_failure(void)
{
    /* Fails on the last line, after name/version/description and three
     * dependencies were already allocated: all of it must be released
     * (LeakSanitizer verifies this in the debug build). */
    EXPECT_FAIL("name=a\nversion=1\ndescription=d\n"
                "depends=b>=1\ndepends=c>=1\ndepends=d=2\n"
                "manifest_sha256=" HEX64 "\n"
                "bogus\n",
                LPM_META_DISTRIBUTABLE, LPM_META_ERR_SYNTAX, 8);
    /* Fails in the final whole-package check instead. */
    EXPECT_FAIL("name=a\ndescription=d\ndepends=b>=1\n", LPM_META_INSTALLED,
                LPM_META_ERR_MISSING_FIELD, 0);
}

static void test_allocation_failures(void)
{
    char path[1024];
    long k;
    int saw_nomem = 0, succeeded = 0;

    /* Fail allocation #0, then #1, #2, ... until the parse needs no
     * more allocations than we skip and finally succeeds. Every
     * failure must report NOMEM and leave the output empty. */
    for (k = 0; k < 1000 && !succeeded; k++) {
        lpm_package pkg;
        lpm_meta_error err;
        lpm_status rc;

        alloc_seen = 0;
        alloc_fail_at = k;
        rc = lpm_metadata_parse_buffer(FULL_DIST, strlen(FULL_DIST),
                                       LPM_META_DISTRIBUTABLE, &pkg, &err);
        alloc_fail_at = -1;

        if (rc == LPM_ERR_NOMEM) {
            saw_nomem++;
            CHECK(err.code == LPM_META_ERR_NOMEM);
            CHECK(pkg_is_empty(&pkg));
        } else {
            CHECK(rc == LPM_OK);
            if (rc == LPM_OK) {
                CHECK(package_invariants_hold(&pkg));
                lpm_package_free(&pkg);
            }
            succeeded = 1;
        }
    }
    CHECK(succeeded);
    CHECK(saw_nomem >= 7);   /* name, version, desc, deps array, 2x2 dep strings */

    /* Same for the file path (adds the read buffer allocation). */
    CHECK(write_tmp("alloc.meta", FULL_DIST, strlen(FULL_DIST), path, sizeof(path)) == 0);
    succeeded = 0;
    for (k = 0; k < 1000 && !succeeded; k++) {
        lpm_package pkg;
        lpm_meta_error err;
        lpm_status rc;

        alloc_seen = 0;
        alloc_fail_at = k;
        rc = lpm_metadata_parse_file(path, LPM_META_DISTRIBUTABLE, &pkg, &err);
        alloc_fail_at = -1;

        if (rc == LPM_ERR_NOMEM) {
            CHECK(pkg_is_empty(&pkg));
        } else {
            CHECK(rc == LPM_OK);
            if (rc == LPM_OK)
                lpm_package_free(&pkg);
            succeeded = 1;
        }
    }
    CHECK(succeeded);
}

static void test_repeated_parsing(void)
{
    char path[1024];
    int i, ok = 0;

    for (i = 0; i < 2000; i++) {
        lpm_package pkg;
        if (lpm_metadata_parse_buffer(FULL_DIST, strlen(FULL_DIST),
                                      LPM_META_DISTRIBUTABLE, &pkg, NULL) == LPM_OK) {
            ok++;
            lpm_package_free(&pkg);
        }
    }
    CHECK(ok == 2000);

    fixture_path("valid-distributable.meta", path, sizeof(path));
    for (ok = 0, i = 0; i < 500; i++) {
        lpm_package pkg;
        if (lpm_metadata_parse_file(path, LPM_META_DISTRIBUTABLE, &pkg, NULL) == LPM_OK) {
            ok++;
            lpm_package_free(&pkg);
        }
    }
    CHECK(ok == 500);
}

/* xorshift32: deterministic, so a failing fuzz case is reproducible. */
static uint32_t rng_state = 0x2545F491u;

static uint32_t rng(void)
{
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static void fuzz_one(const char *data, size_t len, long *accepted)
{
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;

    rc = lpm_metadata_parse_buffer(data, len, LPM_META_INSTALLED, &pkg, &err);
    CHECK(rc == LPM_OK || rc == LPM_ERR_INVALID);
    if (rc == LPM_OK) {
        (*accepted)++;
        CHECK(err.code == LPM_META_ERR_NONE);
        CHECK(package_invariants_hold(&pkg));
        lpm_package_free(&pkg);
    } else {
        CHECK(err.code != LPM_META_ERR_NONE);
        CHECK(err.message[0] != '\0');
        CHECK(pkg_is_empty(&pkg));
    }
}

static void test_mutation_fuzz(void)
{
    static const char interesting[] = "=\n\r\0#> <.A0\t-+/\x7f\x80\xff";
    static const char *seeds[] = {
        FULL_DIST,
        "  name = hello \r\n# c\nversion=16.2.0\ndepends=libc>=0\ndescription=x # y\n",
    };
    enum { ITERATIONS = 20000, RANDOM_INPUTS = 3000, CAP = 512 };
    char buf[CAP];
    long accepted = 0, i;
    size_t j;

    /* Mutated valid inputs: byte replacement, insertion, deletion and
     * truncation, 1-4 mutations each. */
    for (i = 0; i < ITERATIONS; i++) {
        const char *seed = seeds[(size_t)i % (sizeof(seeds) / sizeof(seeds[0]))];
        size_t len = strlen(seed);
        int m, mutations = 1 + (int)(rng() % 4);

        memcpy(buf, seed, len);
        for (m = 0; m < mutations && len > 0; m++) {
            size_t pos = rng() % len;
            char ch = interesting[rng() % (sizeof(interesting) - 1)];

            switch (rng() % 5) {
            case 0: buf[pos] = ch; break;
            case 1: buf[pos] = (char)(rng() & 0xff); break;
            case 2: memmove(buf + pos, buf + pos + 1, len - pos - 1); len--; break;
            case 3:
                if (len < CAP) {
                    memmove(buf + pos + 1, buf + pos, len - pos);
                    buf[pos] = ch;
                    len++;
                }
                break;
            default: len = pos; break;
            }
        }
        fuzz_one(buf, len, &accepted);
    }

    /* Pure random bytes, biased towards metadata-like characters. */
    for (i = 0; i < RANDOM_INPUTS; i++) {
        size_t len = rng() % CAP;
        for (j = 0; j < len; j++)
            buf[j] = (rng() % 2) ? interesting[rng() % (sizeof(interesting) - 1)]
                                 : (char)(rng() & 0xff);
        fuzz_one(buf, len, &accepted);
    }

    if (verbose)
        printf("          -> fuzz: %d inputs, %ld accepted, %ld rejected\n",
               ITERATIONS + RANDOM_INPUTS, accepted,
               (long)(ITERATIONS + RANDOM_INPUTS) - accepted);
}

/* ================================================================== */

static void cleanup_tmp(void)
{
    static const char *names[] = {
        "target.meta", "link.meta", "fifo.meta", "noperm.meta", "at-limit.meta",
        "over-limit.meta", "raw.meta", "alloc.meta",
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[1024];
        tmp_path(names[i], path, sizeof(path));
        unlink(path);
    }
    if (rmdir(tmp_dir) != 0)
        fprintf(stderr, "warning: could not remove %s: %s\n", tmp_dir, strerror(errno));
}

int main(int argc, char **argv)
{
    const char *tmp_base = getenv("TMPDIR");
    int argi = 1;

    if (argi < argc && strcmp(argv[argi], "-v") == 0) {
        verbose = 1;
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-v] <fixtures-dir>\n", argv[0]);
        return 2;
    }
    fixture_dir = argv[argi];

    if (tmp_base == NULL || tmp_base[0] == '\0')
        tmp_base = "/tmp";
    snprintf(tmp_dir, sizeof(tmp_dir), "%s/lpm-test-XXXXXX", tmp_base);
    if (mkdtemp(tmp_dir) == NULL) {
        perror("mkdtemp");
        return 2;
    }

    printf("Running metadata parser unit tests\n");

    printf(" positive\n");
    RUN(test_minimal_installed);
    RUN(test_full_distributable);
    RUN(test_description_preserves_internal_spaces);
    RUN(test_empty_description);
    RUN(test_one_dependency);
    RUN(test_multiple_dependencies);
    RUN(test_exact_dependency);
    RUN(test_minimum_dependency);
    RUN(test_valid_versions);
    RUN(test_valid_sha256);
    RUN(test_whitespace_policy);
    RUN(test_blank_lines);
    RUN(test_comments);
    RUN(test_crlf_line_endings);
    RUN(test_no_trailing_newline);
    RUN(test_ownership_and_cleanup);

    printf(" negative\n");
    RUN(test_empty_input);
    RUN(test_missing_name);
    RUN(test_missing_version);
    RUN(test_duplicate_name);
    RUN(test_duplicate_version);
    RUN(test_duplicate_manifest);
    RUN(test_duplicate_description);
    RUN(test_unsupported_key);
    RUN(test_missing_equals);
    RUN(test_empty_name);
    RUN(test_invalid_names);
    RUN(test_invalid_versions);
    RUN(test_invalid_dependency_names);
    RUN(test_missing_dependency_version);
    RUN(test_unsupported_dependency_operators);
    RUN(test_duplicate_dependencies);
    RUN(test_self_dependency);
    RUN(test_sha256_length);
    RUN(test_sha256_invalid_hex);
    RUN(test_distributable_requires_digest);

    printf(" boundaries\n");
    RUN(test_name_length_boundary);
    RUN(test_version_length_boundary);
    RUN(test_description_length_boundary);
    RUN(test_dependency_count_boundary);
    RUN(test_file_size_boundary);
    RUN(test_line_length_boundary);

    printf(" encoding\n");
    RUN(test_embedded_nul);
    RUN(test_control_characters);
    RUN(test_non_ascii);

    printf(" files\n");
    RUN(test_missing_file);
    RUN(test_non_regular_inputs);
    RUN(test_permission_denied);
    RUN(test_oversized_file);
    RUN(test_raw_bytes_are_preserved);
    RUN(test_fixture_files);

    printf(" robustness\n");
    RUN(test_error_then_valid_input);
    RUN(test_cleanup_after_failure);
    RUN(test_allocation_failures);
    RUN(test_repeated_parsing);
    RUN(test_mutation_fuzz);

    cleanup_tmp();

    printf("\nResults: %d passed, %d failed, %d skipped (%ld checks)\n",
           tests_run - tests_failed - tests_skipped, tests_failed, tests_skipped,
           checks_run);
    return tests_failed == 0 ? 0 : 1;
}
