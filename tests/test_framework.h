/*
 * test_framework.h - Minimal unit-test framework shared by the
 * Milestone 3 test programs (test_metadata.c keeps its own copy so that
 * the Milestone 2 suite stays exactly as it was reviewed).
 *
 * Header-only on purpose: each test program is a single translation
 * unit, so `static` state here is private to that program.
 */
#ifndef LPM_TEST_FRAMEWORK_H
#define LPM_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int tf_verbose;
static int tf_tests_run, tf_tests_failed, tf_tests_skipped;
static long tf_checks_run;
static int tf_current_failures;
static const char *tf_current_skip;

#define CHECK_AT(cond, at)                                                 \
    do {                                                                   \
        tf_checks_run++;                                                   \
        if (!(cond)) {                                                     \
            tf_current_failures++;                                         \
            fprintf(stderr, "    %s:%d: check failed: %s\n",              \
                    __FILE__, (int)(at), #cond);                           \
        }                                                                  \
    } while (0)

#define CHECK(cond) CHECK_AT(cond, __LINE__)

/* Mark the current test as skipped (with a reason) and return. */
#define SKIP(reason)                 \
    do {                             \
        tf_current_skip = (reason);  \
        return;                      \
    } while (0)

static void tf_run(const char *name, void (*fn)(void))
{
    tf_current_failures = 0;
    tf_current_skip = NULL;
    fn();
    tf_tests_run++;
    if (tf_current_failures > 0) {
        tf_tests_failed++;
        printf("  FAIL  %s\n", name);
    } else if (tf_current_skip != NULL) {
        tf_tests_skipped++;
        printf("  SKIP  %s (%s)\n", name, tf_current_skip);
    } else {
        printf("  PASS  %s\n", name);
    }
    fflush(stdout);
}

#define RUN(fn) tf_run(#fn, fn)

/* Parse "-v"; returns 0 on success, 2 on a usage error. */
static int tf_parse_args(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            tf_verbose = 1;
        } else {
            fprintf(stderr, "usage: %s [-v]\n", argv[0]);
            return 2;
        }
    }
    return 0;
}

static int tf_summary(void)
{
    printf("\nResults: %d passed, %d failed, %d skipped (%ld checks)\n",
           tf_tests_run - tf_tests_failed - tf_tests_skipped, tf_tests_failed,
           tf_tests_skipped, tf_checks_run);
    return tf_tests_failed == 0 ? 0 : 1;
}

/* Deterministic PRNG (xorshift32) for reproducible fuzzing. */
static unsigned tf_rng_state = 0x9e3779b9u;

static unsigned tf_rand(void)
{
    unsigned x = tf_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return tf_rng_state = x;
}

#endif /* LPM_TEST_FRAMEWORK_H */
