/*
 * test_version.c - Unit tests for version comparison and dependency
 * constraint evaluation (Milestone 3).
 *
 * Besides hand-picked cases, two property tests compare the
 * implementation with an independent reference model on thousands of
 * generated versions, and check that the ordering is a proper total
 * order (antisymmetric, transitive, consistent with equality).
 */
#include "version.h"
#include "metadata.h"

#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

/* ---- helpers ------------------------------------------------------- */

static int cmp_ok(const char *a, const char *b)
{
    int r = 99;
    lpm_status rc = lpm_version_compare(a, b, &r);

    if (rc != LPM_OK) {
        fprintf(stderr, "    unexpected failure comparing '%s' and '%s'\n", a, b);
        return 99;
    }
    if (tf_verbose)
        printf("      %s vs %s -> %d\n", a, b, r);
    return r;
}

#define LT(a, b) do { CHECK(cmp_ok(a, b) == -1); CHECK(cmp_ok(b, a) == 1); } while (0)
#define EQ(a, b) do { CHECK(cmp_ok(a, b) == 0);  CHECK(cmp_ok(b, a) == 0); } while (0)

/* An invalid input must fail and must not write an ordering. */
static void expect_invalid_at(const char *a, const char *b, int at)
{
    int r = 12345;
    CHECK_AT(lpm_version_compare(a, b, &r) == LPM_ERR_INVALID, at);
    CHECK_AT(r == 12345, at);
}
#define INVALID(a, b) expect_invalid_at(a, b, __LINE__)

static lpm_dependency dep(lpm_dep_operator op, const char *version)
{
    lpm_dependency d;
    d.name = (char *)"libfoo";
    d.version = (char *)version;
    d.op = op;
    return d;
}

static int sat(const char *installed, lpm_dep_operator op, const char *req)
{
    lpm_dependency d = dep(op, req);
    bool ok = false;

    if (lpm_version_satisfies(installed, &d, &ok) != LPM_OK)
        return -1;
    return ok ? 1 : 0;
}

static void repeat(char *buf, char c, size_t n)
{
    memset(buf, c, n);
    buf[n] = '\0';
}

/* ---- ordering ------------------------------------------------------ */

static void test_equal_versions(void)
{
    EQ("1", "1");
    EQ("1.0", "1.0");
    EQ("1.2.3", "1.2.3");
    EQ("16.2.0", "16.2.0");
    EQ("0", "0");
}

static void test_older_and_newer(void)
{
    LT("1.0", "2.0");
    LT("1.2.2", "1.2.3");
    LT("3.2.0", "3.2.1");
    LT("0.9", "1");
    LT("0.0.1", "0.1");
}

static void test_specification_examples(void)
{
    LT("1.9", "1.10");          /* numeric, not lexicographic */
    EQ("1.0", "1");
    EQ("1.0.0", "1");
    LT("1.99", "2.0");          /* 2.0 > 1.99 */
    LT("9.99", "10.0");         /* 10.0 > 9.99 */
    LT("1.2.2", "1.2.3");       /* 1.2.3 > 1.2.2 */
    LT("3.2.0", "3.2.1");
    EQ("2.1", "2.1.0");
}

static void test_single_component(void)
{
    LT("1", "2");
    LT("9", "10");
    LT("99", "100");
    EQ("7", "7");
    LT("0", "1");
}

static void test_multi_component(void)
{
    LT("1.2.3.4", "1.2.3.5");
    LT("1.2.3.4.5.6.7.8", "1.2.3.4.5.6.7.9");
    LT("1.2.10", "1.10.2");
    LT("2.0.0.0.1", "2.0.0.1");
}

static void test_missing_trailing_zeros(void)
{
    EQ("1", "1.0.0.0.0.0");
    EQ("2.1", "2.1.0.0");
    LT("1", "1.0.0.1");         /* only trailing ZEROS are ignored */
    LT("1.0", "1.0.0.0.1");
    LT("2", "2.1");
}

static void test_numeric_not_lexicographic(void)
{
    /* strcmp would get every one of these wrong. */
    LT("1.9", "1.10");
    LT("1.2", "1.10");
    LT("2", "10");
    LT("1.99.0", "1.100");
    CHECK(strcmp("1.9", "1.10") > 0);   /* the trap being avoided */
}

static void test_large_components(void)
{
    /* Far beyond uint64_t (max 18446744073709551615, 20 digits). */
    LT("18446744073709551615", "18446744073709551616");
    LT("99999999999999999999999999999999", "100000000000000000000000000000000");
    EQ("123456789012345678901234567890.0", "123456789012345678901234567890");
    LT("1.99999999999999999999999999999", "2");
    LT("4294967295", "4294967296");      /* 32-bit boundary */
    LT("9223372036854775807", "9223372036854775808");   /* int64 boundary */
}

static void test_maximum_length(void)
{
    char a[80], b[80], longer[80];
    size_t i;

    /* 64 digits: the longest valid version, one huge component. */
    repeat(a, '9', 64);
    repeat(b, '9', 64);
    b[0] = '8';
    CHECK(strlen(a) == LPM_META_MAX_VERSION_LEN);
    LT(b, a);
    EQ(a, a);

    /* 64 characters of "1.1.1....1" (32 components). */
    for (i = 0; i < 63; i++)
        a[i] = (i % 2) ? '.' : '1';
    a[63] = '\0';
    strcpy(b, a);
    b[62] = '2';
    LT(a, b);

    /* 65 characters is rejected, so it never gets an ordering. */
    repeat(longer, '1', 65);
    INVALID(longer, "1");
    INVALID("1", longer);
}

static void test_invalid_input(void)
{
    static const char *const bad[] = {
        "01", "1.02", "1..2", ".1", "1.", "1.0-beta", "v1.0", "1.0rc1",
        " 1", "1 ", "1,0", "-1", "+1", "1.0.", "..", ".", "1.00", "00",
        "1e5", "0x10", "1/2", "\xef\xbc\x91" /* UTF-8 fullwidth 1 */,
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        INVALID(bad[i], "1");
        INVALID("1", bad[i]);
    }
}

static void test_null_and_empty(void)
{
    int r = 12345;

    INVALID(NULL, "1");
    INVALID("1", NULL);
    INVALID(NULL, NULL);
    INVALID("", "1");
    INVALID("1", "");
    INVALID("", "");
    CHECK(lpm_version_compare("1", "2", NULL) == LPM_ERR_INVALID);
    CHECK(lpm_version_compare("1", "2", &r) == LPM_OK && r == -1);
}

/* ---- constraints ---------------------------------------------------- */

static void test_exact_constraint(void)
{
    CHECK(sat("2.0", LPM_DEP_EXACT, "2.0") == 1);
    CHECK(sat("2.0.0", LPM_DEP_EXACT, "2.0") == 1);   /* numeric equality */
    CHECK(sat("2", LPM_DEP_EXACT, "2.0.0") == 1);
    CHECK(sat("2.1", LPM_DEP_EXACT, "2.0") == 0);
    CHECK(sat("1.9", LPM_DEP_EXACT, "2.0") == 0);
}

static void test_minimum_constraint(void)
{
    CHECK(sat("2.1", LPM_DEP_MINIMUM, "2.0") == 1);
    CHECK(sat("2.0", LPM_DEP_MINIMUM, "2.0") == 1);   /* boundary: equal */
    CHECK(sat("2.0.0", LPM_DEP_MINIMUM, "2") == 1);
    CHECK(sat("10.0", LPM_DEP_MINIMUM, "9.99") == 1);
    CHECK(sat("1.10", LPM_DEP_MINIMUM, "1.9") == 1);
    CHECK(sat("5", LPM_DEP_MINIMUM, "0") == 1);       /* ">=0": any version */
}

static void test_unsatisfied_constraints(void)
{
    CHECK(sat("1.9", LPM_DEP_MINIMUM, "2.0") == 0);
    CHECK(sat("1.9", LPM_DEP_MINIMUM, "1.10") == 0);
    CHECK(sat("1.99.99", LPM_DEP_MINIMUM, "2") == 0);
    CHECK(sat("2.0.0.0.0.1", LPM_DEP_EXACT, "2") == 0);
}

static void test_constraint_invalid_input(void)
{
    lpm_dependency d = dep(LPM_DEP_MINIMUM, "1.0");
    bool ok = true;

    CHECK(lpm_version_satisfies(NULL, &d, &ok) == LPM_ERR_INVALID);
    CHECK(lpm_version_satisfies("1.0", NULL, &ok) == LPM_ERR_INVALID);
    CHECK(lpm_version_satisfies("1.0", &d, NULL) == LPM_ERR_INVALID);
    CHECK(lpm_version_satisfies("01", &d, &ok) == LPM_ERR_INVALID);
    CHECK(lpm_version_satisfies("", &d, &ok) == LPM_ERR_INVALID);
    d.version = (char *)"1..0";
    CHECK(lpm_version_satisfies("1.0", &d, &ok) == LPM_ERR_INVALID);
    d.version = NULL;
    CHECK(lpm_version_satisfies("1.0", &d, &ok) == LPM_ERR_INVALID);
    d = dep((lpm_dep_operator)42, "1.0");
    CHECK(lpm_version_satisfies("1.0", &d, &ok) == LPM_ERR_INVALID);
    CHECK(ok == true);   /* never written on failure */
}

/* ---- property tests ------------------------------------------------- */

/* Random valid version with small components (fits in unsigned long). */
static void random_version(char *buf, unsigned long *comp, size_t *ncomp)
{
    size_t n = 1 + tf_rand() % 5, i, pos = 0;

    for (i = 0; i < n; i++) {
        /* Bias towards 0 and small numbers, where the edge cases are. */
        unsigned r = tf_rand() % 10;
        unsigned long v = r < 3 ? 0 : r < 7 ? tf_rand() % 12 : tf_rand() % 100000;
        comp[i] = v;
        pos += (size_t)sprintf(buf + pos, i ? ".%lu" : "%lu", v);
    }
    *ncomp = n;
}

/* Independent reference: integer comparison, trailing zeros ignored. */
static int reference_compare(const unsigned long *a, size_t na,
                             const unsigned long *b, size_t nb)
{
    size_t i, n = na > nb ? na : nb;

    for (i = 0; i < n; i++) {
        unsigned long x = i < na ? a[i] : 0, y = i < nb ? b[i] : 0;
        if (x != y)
            return x < y ? -1 : 1;
    }
    return 0;
}

static void test_matches_reference_model(void)
{
    char a[64], b[64];
    unsigned long ca[5], cb[5];
    size_t na, nb;
    int i, mismatches = 0;

    for (i = 0; i < 20000; i++) {
        int r = 99;
        random_version(a, ca, &na);
        random_version(b, cb, &nb);
        if (lpm_version_compare(a, b, &r) != LPM_OK ||
            r != reference_compare(ca, na, cb, nb)) {
            if (mismatches++ < 5)
                fprintf(stderr, "    mismatch: %s vs %s -> %d\n", a, b, r);
        }
    }
    CHECK(mismatches == 0);
}

static void test_total_order_properties(void)
{
    char v[3][64];
    unsigned long c[5];
    size_t n;
    int i, k, bad = 0;

    for (i = 0; i < 10000; i++) {
        int ab, ba, bc, ac;
        for (k = 0; k < 3; k++)
            random_version(v[k], c, &n);
        ab = cmp_ok(v[0], v[1]);
        ba = cmp_ok(v[1], v[0]);
        bc = cmp_ok(v[1], v[2]);
        ac = cmp_ok(v[0], v[2]);
        if (ab != -ba)                                   /* antisymmetry */
            bad++;
        if (ab <= 0 && bc <= 0 && ac > 0)                /* transitivity */
            bad++;
        if (cmp_ok(v[0], v[0]) != 0)                     /* reflexivity  */
            bad++;
    }
    CHECK(bad == 0);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;

    printf("Running version comparison unit tests\n");
    RUN(test_equal_versions);
    RUN(test_older_and_newer);
    RUN(test_specification_examples);
    RUN(test_single_component);
    RUN(test_multi_component);
    RUN(test_missing_trailing_zeros);
    RUN(test_numeric_not_lexicographic);
    RUN(test_large_components);
    RUN(test_maximum_length);
    RUN(test_invalid_input);
    RUN(test_null_and_empty);
    RUN(test_exact_constraint);
    RUN(test_minimum_constraint);
    RUN(test_unsatisfied_constraints);
    RUN(test_constraint_invalid_input);
    RUN(test_matches_reference_model);
    RUN(test_total_order_properties);
    return tf_summary();
}
