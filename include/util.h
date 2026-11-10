/*
 * util.h - Small, self-contained helpers used by every module:
 * diagnostics, safe string/path construction and name validation.
 */
#ifndef LPM_UTIL_H
#define LPM_UTIL_H

#include <stddef.h>

#if defined(__GNUC__)
#define LPM_PRINTF(fmt_idx, arg_idx) __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#define LPM_PRINTF(fmt_idx, arg_idx)
#endif

/* Print "ERROR: <message>\n" / "WARNING: <message>\n" to stderr. */
void lpm_error(const char *fmt, ...) LPM_PRINTF(1, 2);
void lpm_warn(const char *fmt, ...) LPM_PRINTF(1, 2);

/* strdup replacement. Returns NULL on allocation failure. Caller frees. */
char *lpm_strdup(const char *s);

/*
 * Join a base directory and a relative path with exactly one '/'.
 * Leading slashes in rel are ignored, so join("/x", "/var") == "/x/var";
 * this is what lets every path be re-rooted under --root.
 * Returns a malloc'd string (caller frees) or NULL on allocation failure.
 */
char *lpm_path_join(const char *base, const char *rel);

/* Returns 1 if s ends with suffix, else 0. */
int lpm_has_suffix(const char *s, const char *suffix);

/*
 * Returns 1 if name is a valid package name, else 0.
 * Allowed: 1..LPM_MAX_NAME_LEN chars from [a-z0-9+._-], starting with
 * [a-z0-9]. This prevents names such as "../etc" or "a/b" from ever
 * being turned into database file paths.
 */
int lpm_is_valid_package_name(const char *name);

/* Trim leading/trailing whitespace in place; returns pointer into s. */
char *lpm_trim(char *s);

#endif /* LPM_UTIL_H */
