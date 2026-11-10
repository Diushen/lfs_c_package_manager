/*
 * test_filelist.c - Unit tests for file-ownership records (Milestone 3):
 * path validation, parsing, canonical serialisation, conflict detection,
 * resource limits, allocation failures and mutation fuzzing.
 *
 * Linked with -Wl,--wrap=malloc,calloc,realloc for failure injection.
 */
#include "filelist.h"
#include "metadata.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

/* ---- allocation-failure injection ---------------------------------- */

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

static long alloc_seen, alloc_fail_at = -1;

static int inject(void)
{
    return alloc_fail_at >= 0 && alloc_seen++ == alloc_fail_at;
}
void *__wrap_malloc(size_t s) { return inject() ? NULL : __real_malloc(s); }
void *__wrap_calloc(size_t n, size_t s) { return inject() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t s) { return inject() ? NULL : __real_realloc(p, s); }

/* ---- helpers --------------------------------------------------------- */

static lpm_status parse(const char *text, lpm_file_list *out, lpm_meta_error *err)
{
    return lpm_file_list_parse_buffer(text, strlen(text), out, err);
}

/* Parse must fail with `code`, leaving the output empty. */
static void expect_reject_at(const char *data, size_t len, lpm_meta_error_code code,
                             size_t line, int at)
{
    lpm_file_list l;
    lpm_meta_error err;
    lpm_status rc;

    l.paths = (char **)(uintptr_t)0xA5A5;   /* garbage the parser must overwrite */
    l.count = 77;
    rc = lpm_file_list_parse_buffer(data, len, &l, &err);
    CHECK_AT(rc == LPM_ERR_INVALID, at);
    CHECK_AT(err.code == code, at);
    if (line != (size_t)-1)
        CHECK_AT(err.line == line, at);
    CHECK_AT(l.paths == NULL && l.count == 0, at);
    if (tf_verbose)
        printf("      rejected: line %zu: %s\n", err.line, err.message);
    lpm_file_list_free(&l);
}
#define REJECT(text, code, line) expect_reject_at(text, strlen(text), code, line, __LINE__)
#define ANYLINE ((size_t)-1)

static char *make_path(size_t len)
{
    /* "/aaaa/aaaa/..." of exactly len bytes, components <= 200 bytes. */
    char *p = malloc(len + 1);
    size_t i;

    for (i = 0; i < len; i++)
        p[i] = (i % 201 == 0) ? '/' : 'a';
    if (len > 0 && p[len - 1] == '/')
        p[len - 1] = 'a';
    p[len] = '\0';
    return p;
}

/* ---- path validation -------------------------------------------------- */

static void test_valid_paths(void)
{
    static const char *const good[] = {
        "/usr/bin/hello", "/a", "/usr/share/doc/hello-1.0/README",
        "/etc/a b", "/usr/lib/libfoo.so.1.2.3", "/.hidden", "/a/...",
        "/a/..b", "/usr/include/c++/16/x", "/x/~backup", "/a/b@c,d=e",
    };
    size_t i;

    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        CHECK(lpm_is_valid_owned_path(good[i]));
}

static void test_invalid_paths(void)
{
    static const char *const bad[] = {
        "", "/", "usr/bin/hello", "./usr", "/usr//bin", "/usr/bin/",
        "/usr/../etc/passwd", "/..", "/.", "/usr/./bin", "/a/b/..",
        "/a\tb", "/a\nb", "/a\rb", "/caf\xc3\xa9", "/ leading", "/trailing ",
        "/a/ b", "/a/b /c", "//", "/a/\x7f",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (lpm_is_valid_owned_path(bad[i]))
            fprintf(stderr, "    accepted bad path #%zu\n", i);
        CHECK(!lpm_is_valid_owned_path(bad[i]));
    }
    CHECK(!lpm_is_valid_owned_path(NULL));
}

static void test_path_length_limits(void)
{
    char *ok = make_path(LPM_FILES_MAX_PATH);
    char *over = make_path(LPM_FILES_MAX_PATH + 1);
    char comp[LPM_FILES_MAX_COMPONENT + 3];

    CHECK(strlen(ok) == LPM_FILES_MAX_PATH);
    CHECK(lpm_is_valid_owned_path(ok));
    CHECK(!lpm_is_valid_owned_path(over));

    comp[0] = '/';
    memset(comp + 1, 'x', LPM_FILES_MAX_COMPONENT);
    comp[LPM_FILES_MAX_COMPONENT + 1] = '\0';
    CHECK(lpm_is_valid_owned_path(comp));                 /* 255 bytes */
    comp[LPM_FILES_MAX_COMPONENT + 1] = 'x';
    comp[LPM_FILES_MAX_COMPONENT + 2] = '\0';
    CHECK(!lpm_is_valid_owned_path(comp));                /* 256 bytes */
    free(ok);
    free(over);
}

/* ---- parsing ------------------------------------------------------------ */

static void test_parse_and_sort(void)
{
    lpm_file_list l;
    lpm_meta_error err;

    CHECK(parse("/usr/share/doc/hello/README\n/usr/bin/hello\n", &l, &err) == LPM_OK);
    CHECK(l.count == 2);
    CHECK(strcmp(l.paths[0], "/usr/bin/hello") == 0);   /* canonical order */
    CHECK(strcmp(l.paths[1], "/usr/share/doc/hello/README") == 0);
    CHECK(lpm_file_list_contains(&l, "/usr/bin/hello"));
    CHECK(!lpm_file_list_contains(&l, "/usr/bin/hell"));
    CHECK(!lpm_file_list_contains(&l, "/usr/bin"));
    lpm_file_list_free(&l);
}

static void test_empty_list(void)
{
    lpm_file_list l;
    lpm_meta_error err;
    char *out;
    size_t len;

    CHECK(lpm_file_list_parse_buffer("", 0, &l, &err) == LPM_OK);
    CHECK(l.count == 0);
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_OK);
    CHECK(len == 0 && out != NULL && out[0] == '\0');
    free(out);
    lpm_file_list_free(&l);
}

static void test_parse_rejects(void)
{
    REJECT("/usr/bin/hello", LPM_META_ERR_SYNTAX, 1);              /* no final LF */
    REJECT("/a\n/b", LPM_META_ERR_SYNTAX, 2);
    REJECT("\n", LPM_META_ERR_INVALID_PATH, 1);                    /* blank line */
    REJECT("/a\n\n/b\n", LPM_META_ERR_INVALID_PATH, 2);
    REJECT("usr/bin/x\n", LPM_META_ERR_INVALID_PATH, 1);
    REJECT("/a\n/usr/../etc/shadow\n", LPM_META_ERR_INVALID_PATH, 2);
    REJECT("/a\r\n", LPM_META_ERR_CONTROL_CHAR, 1);                /* CRLF */
    REJECT("/caf\xc3\xa9\n", LPM_META_ERR_ENCODING, 1);
    REJECT("# comment\n", LPM_META_ERR_INVALID_PATH, 1);
    REJECT("/a/\n", LPM_META_ERR_INVALID_PATH, 1);
    expect_reject_at("/a\0b\n", 5, LPM_META_ERR_NUL_BYTE, 1, __LINE__);
}

static void test_duplicates_rejected(void)
{
    REJECT("/usr/bin/hello\n/usr/bin/hello\n", LPM_META_ERR_DUPLICATE_PATH, ANYLINE);
    REJECT("/b\n/a\n/c\n/a\n", LPM_META_ERR_DUPLICATE_PATH, ANYLINE);
}

static void test_file_versus_parent_conflict(void)
{
    /* /usr/bin cannot be a file if /usr/bin/hello is inside it. Note that
     * "/usr/bin-x" sorts between the two, so neighbours are not enough. */
    REJECT("/usr/bin\n/usr/bin/hello\n", LPM_META_ERR_PATH_CONFLICT, ANYLINE);
    REJECT("/usr/bin\n/usr/bin-x\n/usr/bin/hello\n", LPM_META_ERR_PATH_CONFLICT, ANYLINE);
    REJECT("/a/b/c/d\n/a\n", LPM_META_ERR_PATH_CONFLICT, ANYLINE);
}

static void test_similar_paths_are_not_conflicts(void)
{
    lpm_file_list l;
    lpm_meta_error err;

    CHECK(parse("/usr/bin-x\n/usr/binx\n/usr/bi\n/usr/bin.d/y\n", &l, &err) == LPM_OK);
    CHECK(l.count == 4);
    lpm_file_list_free(&l);
}

static void test_line_too_long(void)
{
    char *p = make_path(LPM_FILES_MAX_PATH + 1);
    char *text = malloc(LPM_FILES_MAX_PATH + 3);

    strcpy(text, p);
    strcat(text, "\n");
    REJECT(text, LPM_META_ERR_LINE_TOO_LONG, 1);
    free(p);
    free(text);
}

/* ---- serialisation ------------------------------------------------------ */

static void test_serialize_round_trip(void)
{
    static const char text[] = "/usr/bin/hello\n/usr/share/doc/hello/README\n";
    lpm_file_list l, again;
    lpm_meta_error err;
    char *out;
    size_t len, i;

    lpm_file_list_init(&l);
    CHECK(lpm_file_list_add(&l, "/usr/share/doc/hello/README", &err) == LPM_OK);
    CHECK(lpm_file_list_add(&l, "/usr/bin/hello", &err) == LPM_OK);

    /* Not finalized yet: the writer refuses unsorted input. */
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_STATE && out == NULL);

    CHECK(lpm_file_list_finalize(&l, &err) == LPM_OK);
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_OK);
    CHECK(len == strlen(text) && memcmp(out, text, len) == 0);   /* deterministic */
    CHECK(lpm_file_list_parse_buffer(out, len, &again, &err) == LPM_OK);
    CHECK(again.count == l.count);
    for (i = 0; i < l.count && i < again.count; i++)
        CHECK(strcmp(l.paths[i], again.paths[i]) == 0);
    free(out);
    lpm_file_list_free(&again);
    lpm_file_list_free(&l);
}

static void test_add_rejects_bad_paths(void)
{
    lpm_file_list l;
    lpm_meta_error err;

    lpm_file_list_init(&l);
    CHECK(lpm_file_list_add(&l, "/ok", &err) == LPM_OK);
    CHECK(lpm_file_list_add(&l, "/a/../b", &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_INVALID_PATH);
    CHECK(lpm_file_list_add(&l, "/a\nb", &err) == LPM_ERR_INVALID);   /* injection */
    CHECK(lpm_file_list_add(&l, NULL, &err) == LPM_ERR_INVALID);
    CHECK(l.count == 1);          /* failed adds change nothing */
    CHECK(lpm_file_list_add(&l, "/ok", &err) == LPM_OK);
    CHECK(lpm_file_list_finalize(&l, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_DUPLICATE_PATH);
    lpm_file_list_free(&l);
}

static void test_serialize_rechecks_entries(void)
{
    lpm_file_list l;
    lpm_meta_error err;
    char *out;
    size_t len;

    /* A list assembled by hand, bypassing lpm_file_list_add(). */
    char *paths[2];
    paths[0] = (char *)"/a";
    paths[1] = (char *)"/b\nmanifest_sha256=evil";
    l.paths = paths;
    l.count = 2;
    l.capacity = 2;
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_ERR_INVALID);
    CHECK(out == NULL);
    paths[1] = (char *)"/a/b";   /* sorted, valid paths, but /a is a parent */
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_PATH_CONFLICT);
}

/* ---- resource bounds ------------------------------------------------------ */

static void test_maximum_file_count(void)
{
    const size_t n = LPM_FILES_MAX_ENTRIES;
    size_t i, len = 0;
    char *text = malloc((n + 1) * 10 + 1);
    lpm_file_list l;
    lpm_meta_error err;

    for (i = 0; i < n; i++)
        len += (size_t)sprintf(text + len, "/f/%06zu\n", i);
    CHECK(lpm_file_list_parse_buffer(text, len, &l, &err) == LPM_OK);
    CHECK(l.count == n);
    lpm_file_list_free(&l);

    len += (size_t)sprintf(text + len, "/f/%06zu\n", n);   /* one more */
    expect_reject_at(text, len, LPM_META_ERR_TOO_MANY_FILES, n + 1, __LINE__);

    /* lpm_file_list_add enforces the same limit. */
    lpm_file_list_init(&l);
    for (i = 0; i < n; i++) {
        char p[16];
        sprintf(p, "/g/%06zu", i);
        if (lpm_file_list_add(&l, p, &err) != LPM_OK)
            break;
    }
    CHECK(l.count == n);
    CHECK(lpm_file_list_add(&l, "/one/too/many", &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_TOO_MANY_FILES);
    CHECK(l.count == n);
    lpm_file_list_free(&l);
    free(text);
}

static void test_maximum_size(void)
{
    /* Larger than LPM_FILES_MAX_SIZE is rejected before any parsing. */
    size_t len = (size_t)LPM_FILES_MAX_SIZE + 1;
    char *big = malloc(len);

    memset(big, '\n', len);
    expect_reject_at(big, len, LPM_META_ERR_FILE_TOO_LARGE, 0, __LINE__);
    free(big);
}

static void test_writer_refuses_oversized_output(void)
{
    /* 65536 paths of ~200 bytes is ~13 MiB > 8 MiB: the writer must
     * refuse rather than produce a file the reader would reject. */
    lpm_file_list l;
    lpm_meta_error err;
    char *out, p[256];
    size_t i, len;

    lpm_file_list_init(&l);
    memset(p, 'x', sizeof(p));
    for (i = 0; i < LPM_FILES_MAX_ENTRIES; i++) {
        int n = sprintf(p, "/%06zu", i);
        p[n] = 'x';
        p[200] = '\0';
        if (lpm_file_list_add(&l, p, &err) != LPM_OK)
            break;
    }
    CHECK(l.count == LPM_FILES_MAX_ENTRIES);
    CHECK(lpm_file_list_finalize(&l, &err) == LPM_OK);
    CHECK(lpm_file_list_serialize(&l, &out, &len, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_FILE_TOO_LARGE && out == NULL);
    lpm_file_list_free(&l);
}

/* ---- cross-list conflicts --------------------------------------------------- */

typedef struct { int same, parent; } conflict_count;

static bool count_conflict(void *ctx, const lpm_owned_path *a,
                           const lpm_owned_path *b, bool same_path)
{
    conflict_count *c = ctx;
    (void)a; (void)b;
    if (same_path)
        c->same++;
    else
        c->parent++;
    return true;
}

static void test_owned_path_conflicts(void)
{
    lpm_owned_path v[] = {
        { "/usr/bin/hello", 0 }, { "/usr/share/x", 0 },
        { "/usr/bin/hello", 1 },                    /* same file, two owners */
        { "/usr/share", 2 },                        /* parent of /usr/share/x */
        { "/opt/a", 1 }, { "/opt/a-b", 2 },         /* similar, not related */
    };
    conflict_count c = { 0, 0 };
    size_t n = sizeof(v) / sizeof(v[0]);

    lpm_owned_paths_sort(v, n);
    CHECK(lpm_owned_paths_conflicts(v, n, count_conflict, &c) == 2);
    CHECK(c.same == 1 && c.parent == 1);
}

/* ---- robustness ----------------------------------------------------------- */

static void test_allocation_failures(void)
{
    static const char text[] = "/c\n/a\n/b/x\n/b/y\n/d\n/e\n/f\n/g\n/h\n/i\n"
                               "/j\n/k\n/l\n/m\n/n\n/o\n/p\n/q\n";
    long n;
    int completed = 0;

    for (n = 0; n < 200 && !completed; n++) {
        lpm_file_list l;
        lpm_meta_error err;
        char *out = NULL;
        size_t len;
        lpm_status rc;

        alloc_seen = 0;
        alloc_fail_at = n;
        rc = parse(text, &l, &err);
        if (rc == LPM_OK)
            rc = lpm_file_list_serialize(&l, &out, &len, &err);
        alloc_fail_at = -1;

        if (rc == LPM_OK) {
            completed = 1;   /* n is past the last allocation */
        } else {
            CHECK(rc == LPM_ERR_NOMEM);
            CHECK(err.code == LPM_META_ERR_NOMEM);
            CHECK(out == NULL);
        }
        free(out);
        lpm_file_list_free(&l);   /* ASan/LSan catch any leak */
    }
    CHECK(completed);
}

/* Random mutations of a valid list: never crash; anything accepted must
 * be canonical and survive a write/read round trip unchanged. */
static void test_mutation_fuzz(void)
{
    static const char seed[] = "/usr/bin/hello\n/usr/lib/libhello.so.1\n"
                               "/usr/share/doc/hello/README\n/etc/hello.conf\n";
    static const char alphabet[] = "/.a \n\r\t\0\x80~-";
    char buf[256];
    int i, accepted = 0, bad = 0;

    for (i = 0; i < 20000; i++) {
        size_t len = sizeof(seed) - 1, m, nmut = 1 + tf_rand() % 4;
        lpm_file_list l, again;
        lpm_meta_error err;

        memcpy(buf, seed, len);
        for (m = 0; m < nmut; m++) {
            size_t pos = tf_rand() % len;
            switch (tf_rand() % 3) {
            case 0: buf[pos] = alphabet[tf_rand() % (sizeof(alphabet) - 1)]; break;
            case 1: if (len > 1) { memmove(buf + pos, buf + pos + 1, len - pos - 1); len--; } break;
            default:
                if (len < sizeof(buf) - 1) {
                    memmove(buf + pos + 1, buf + pos, len - pos);
                    buf[pos] = alphabet[tf_rand() % (sizeof(alphabet) - 1)];
                    len++;
                }
            }
        }
        if (lpm_file_list_parse_buffer(buf, len, &l, &err) == LPM_OK) {
            char *out;
            size_t olen, k;
            accepted++;
            for (k = 0; k < l.count; k++)
                if (!lpm_is_valid_owned_path(l.paths[k]) ||
                    (k > 0 && strcmp(l.paths[k - 1], l.paths[k]) >= 0))
                    bad++;
            if (lpm_file_list_serialize(&l, &out, &olen, &err) != LPM_OK) {
                bad++;
            } else {
                if (lpm_file_list_parse_buffer(out, olen, &again, &err) != LPM_OK ||
                    again.count != l.count)
                    bad++;
                lpm_file_list_free(&again);
                free(out);
            }
            lpm_file_list_free(&l);
        } else {
            CHECK(l.count == 0 && l.paths == NULL);
        }
    }
    if (tf_verbose)
        printf("      %d of 20000 mutants accepted\n", accepted);
    CHECK(bad == 0);
    CHECK(accepted > 0);   /* the fuzzer did exercise the success path */
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;

    printf("Running file-list unit tests\n");
    RUN(test_valid_paths);
    RUN(test_invalid_paths);
    RUN(test_path_length_limits);
    RUN(test_parse_and_sort);
    RUN(test_empty_list);
    RUN(test_parse_rejects);
    RUN(test_duplicates_rejected);
    RUN(test_file_versus_parent_conflict);
    RUN(test_similar_paths_are_not_conflicts);
    RUN(test_line_too_long);
    RUN(test_serialize_round_trip);
    RUN(test_add_rejects_bad_paths);
    RUN(test_serialize_rechecks_entries);
    RUN(test_maximum_file_count);
    RUN(test_maximum_size);
    RUN(test_writer_refuses_oversized_output);
    RUN(test_owned_path_conflicts);
    RUN(test_allocation_failures);
    RUN(test_mutation_fuzz);
    return tf_summary();
}
