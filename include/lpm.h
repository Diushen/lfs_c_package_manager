/*
 * lpm.h - Project-wide constants, status codes and runtime configuration.
 *
 * Every module includes this header. It deliberately contains no logic:
 * just the vocabulary (status codes, paths, config struct) that all
 * modules share.
 */
#ifndef LPM_H
#define LPM_H

#define LPM_PROGRAM_NAME   "lpm"
#define LPM_LONG_NAME      "LFS Package Manager"
#define LPM_VERSION        "0.1.0"

/* Default target root. Overridden with --root during development/testing. */
#define LPM_DEFAULT_ROOT   "/"

/* Database layout, relative to the target root. */
#define LPM_DB_SUBDIR         "var/lib/lpm"
#define LPM_DB_INSTALLED_DIR  "installed"   /* <name>.meta  */
#define LPM_DB_FILES_DIR      "files"       /* <name>.list  */
#define LPM_META_SUFFIX       ".meta"
#define LPM_LIST_SUFFIX       ".list"
#define LPM_DB_LOCK_FILE      "lock"        /* flock() target  */

/* Upper bound for a package name; keeps names sane and filenames short. */
#define LPM_MAX_NAME_LEN   64

/*
 * Status codes returned by library-style functions.
 * Functions return an lpm_status instead of calling exit(), so the
 * caller (ultimately main) decides how to report and exit.
 */
typedef enum {
    LPM_OK = 0,
    LPM_ERR_USAGE,            /* bad command-line usage                */
    LPM_ERR_NOMEM,            /* allocation failure                    */
    LPM_ERR_IO,               /* filesystem / read / write failure     */
    LPM_ERR_NOT_FOUND,        /* requested item does not exist         */
    LPM_ERR_INVALID,          /* malformed input / failed validation   */
    LPM_ERR_NOT_IMPLEMENTED,  /* command planned for a later milestone */
    LPM_ERR_EXISTS,           /* item already exists (e.g. registered) */
    LPM_ERR_BUSY,             /* database locked by another process    */
    LPM_ERR_CONFLICT          /* file already owned by another package */
} lpm_status;

/* Runtime configuration built from global command-line options. */
typedef struct {
    const char *root;   /* target root directory; not owned (argv/literal) */
} lpm_config;

/* Human-readable name of a status code (for diagnostics). */
const char *lpm_status_str(lpm_status status);

/* Map a status code to a process exit code: 0 ok, 2 usage, 1 other. */
int lpm_status_to_exit(lpm_status status);

#endif /* LPM_H */
