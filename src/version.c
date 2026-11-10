/*
 * version.c - Overflow-free numeric version comparison.
 *
 * Example: 1.9 vs 1.10
 *   component 1: "1"  vs "1"   same length, same digits  -> equal
 *   component 2: "9"  vs "10"  1 digit vs 2 digits        -> 1.9 is older
 *
 * strcmp("1.9", "1.10") would say the opposite ('9' > '1'), and
 * converting to floating point would make 1.10 == 1.1. Neither is used.
 *
 * Complexity: O(len(a) + len(b)), at most 64 characters each; no
 * allocation.
 */
#include "version.h"

#include <string.h>

#define DIGITS "0123456789"

/*
 * Compare two digit runs with no leading zeros. More digits means a
 * larger number; with equal lengths, character order equals numeric
 * order. Returns -1, 0 or 1.
 */
static int compare_component(const char *a, size_t alen,
                             const char *b, size_t blen)
{
    int c;

    if (alen != blen)
        return alen < blen ? -1 : 1;
    c = memcmp(a, b, alen);
    return (c > 0) - (c < 0);
}

lpm_status lpm_version_compare(const char *a, const char *b, int *result)
{
    if (result == NULL || !lpm_is_valid_version(a) || !lpm_is_valid_version(b))
        return LPM_ERR_INVALID;

    /* Validation guarantees: every component is a non-empty digit run,
     * and components are separated by exactly one '.'. */
    while (*a != '\0' || *b != '\0') {
        /* A version that has run out contributes an implicit "0". */
        const char *ca = *a ? a : "0";
        const char *cb = *b ? b : "0";
        size_t la = strspn(ca, DIGITS);
        size_t lb = strspn(cb, DIGITS);
        int c = compare_component(ca, la, cb, lb);

        if (c != 0) {
            *result = c;
            return LPM_OK;
        }
        if (*a) {
            a += la;
            if (*a == '.')
                a++;
        }
        if (*b) {
            b += lb;
            if (*b == '.')
                b++;
        }
    }
    *result = 0;
    return LPM_OK;
}

lpm_status lpm_version_satisfies(const char *installed_version,
                                 const lpm_dependency *requirement,
                                 bool *satisfied)
{
    int cmp;

    if (requirement == NULL || satisfied == NULL)
        return LPM_ERR_INVALID;
    if (requirement->op != LPM_DEP_EXACT && requirement->op != LPM_DEP_MINIMUM)
        return LPM_ERR_INVALID;
    if (lpm_version_compare(installed_version, requirement->version, &cmp) != LPM_OK)
        return LPM_ERR_INVALID;

    *satisfied = requirement->op == LPM_DEP_EXACT ? cmp == 0 : cmp >= 0;
    return LPM_OK;
}
