/*
 * version.h - Version ordering and dependency-constraint evaluation.
 *
 * Versions are the numeric dotted strings accepted by
 * lpm_is_valid_version() (metadata.h): "1", "1.10", "16.2.0". There is
 * exactly one validator; this module never accepts a version that the
 * metadata parser would reject.
 *
 * Ordering rules:
 *   - components are compared left to right, numerically;
 *   - a missing trailing component counts as 0, so 1 == 1.0 == 1.0.0.
 *
 * Components are never converted to integers. Because leading zeros are
 * forbidden, a component with more digits is always the larger number,
 * and two components with the same number of digits compare like their
 * characters. That works for components of any length (e.g. 40 digits),
 * so there is nothing to overflow.
 *
 * This module is pure: it touches no files and knows nothing about the
 * installed database. The dependency solver (Milestone 4) builds on it.
 */
#ifndef LPM_VERSION_H
#define LPM_VERSION_H

#include <stdbool.h>
#include "lpm.h"
#include "metadata.h"

/*
 * Compare two versions.
 *
 * Preconditions: a and b are valid versions; result is non-NULL.
 * On success returns LPM_OK and sets *result to -1 (a older than b),
 * 0 (equal) or 1 (a newer than b).
 * If either version is NULL or invalid, or result is NULL, returns
 * LPM_ERR_INVALID and leaves *result untouched: an invalid input never
 * produces an ordering.
 */
lpm_status lpm_version_compare(const char *a, const char *b, int *result);

/*
 * Does installed_version satisfy one parsed dependency constraint?
 *
 *   LPM_DEP_EXACT    installed == required   (numerically: 2.0 == 2.0.0)
 *   LPM_DEP_MINIMUM  installed >= required
 *
 * Only versions are compared: requirement->name is ignored, and the
 * database is not consulted.
 * On success returns LPM_OK and sets *satisfied. Returns LPM_ERR_INVALID
 * (leaving *satisfied untouched) for a NULL argument, an invalid
 * version on either side, or an unknown operator.
 */
lpm_status lpm_version_satisfies(const char *installed_version,
                                 const lpm_dependency *requirement,
                                 bool *satisfied);

#endif /* LPM_VERSION_H */
