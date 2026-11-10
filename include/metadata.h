/*
 * metadata.h - Package metadata parser and package data structures.
 *
 * Metadata is a strict, line-oriented, ASCII "key=value" format:
 *
 *   # comment
 *   name=hello
 *   version=1.2.0
 *   description=A simple hello world program
 *   depends=libfoo>=1.0
 *   depends=libbar=2.1
 *   manifest_sha256=<64 lowercase hex digits>
 *
 * The parser is a pure function of its input bytes: it performs no
 * installation, dependency resolution, hashing or signature checking,
 * and depends only on lpm.h and util.h (never on the database or CLI).
 *
 * TRUST: parsed metadata is UNTRUSTED until a later milestone verifies
 * the Ed25519 signature over the exact raw bytes. Callers that need to
 * verify should use lpm_metadata_read_file() to obtain the raw bytes,
 * verify those bytes, then hand the *same buffer* to
 * lpm_metadata_parse_buffer(). Never re-read the file in between, and
 * never verify a re-serialised form of the parsed structure.
 */
#ifndef LPM_METADATA_H
#define LPM_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"

/* ---- Resource limits (enforced while parsing, not afterwards) ------- */

#define LPM_META_MAX_FILE_SIZE    (64 * 1024) /* bytes, whole metadata file  */
#define LPM_META_MAX_LINE_LEN     4096        /* bytes, excluding LF / CRLF  */
#define LPM_META_MAX_VERSION_LEN  64          /* characters                  */
#define LPM_META_MAX_DESC_LEN     1024        /* characters                  */
#define LPM_META_MAX_DEPENDS      128         /* depends= lines per package  */
#define LPM_SHA256_HEX_LEN        64          /* exactly, lowercase hex      */
/* Package and dependency names use LPM_MAX_NAME_LEN (lpm.h), the same
 * limit already applied to database filenames in Milestone 1. */

/* ---- Data structures ------------------------------------------------ */

typedef enum {
    LPM_DEP_EXACT,     /* name=VERSION  */
    LPM_DEP_MINIMUM    /* name>=VERSION */
} lpm_dep_operator;

/* One "depends=" entry. Strings are owned by the enclosing lpm_package. */
typedef struct {
    char *name;
    char *version;
    lpm_dep_operator op;
} lpm_dependency;

/*
 * A parsed package. The package owns every string and the dependency
 * array; release everything with a single lpm_package_free() call.
 */
typedef struct {
    char *name;                 /* always set on success                */
    char *version;              /* always set on success                */
    char *description;          /* NULL = absent, "" = present but empty */

    lpm_dependency *dependencies;   /* NULL when dependency_count == 0  */
    size_t dependency_count;

    char manifest_sha256[LPM_SHA256_HEX_LEN + 1];  /* "" when absent    */
    bool has_manifest_sha256;
} lpm_package;

/*
 * Validation profile. One parser, two sets of required fields:
 *   INSTALLED      name + version (database records, Milestone 1 data)
 *   DISTRIBUTABLE  name + version + manifest_sha256 (.pkg files)
 */
typedef enum {
    LPM_META_INSTALLED,
    LPM_META_DISTRIBUTABLE
} lpm_meta_profile;

/* ---- Error reporting ------------------------------------------------ */

/* Precise reason for a failure; tests assert on these, not on text. */
typedef enum {
    LPM_META_ERR_NONE = 0,
    LPM_META_ERR_IO,               /* open/read failed                   */
    LPM_META_ERR_NOT_REGULAR,      /* symlink, directory, FIFO, device   */
    LPM_META_ERR_NOMEM,            /* allocation failed                  */
    LPM_META_ERR_FILE_TOO_LARGE,   /* > LPM_META_MAX_FILE_SIZE           */
    LPM_META_ERR_LINE_TOO_LONG,    /* > LPM_META_MAX_LINE_LEN            */
    LPM_META_ERR_NUL_BYTE,         /* embedded '\0'                      */
    LPM_META_ERR_CONTROL_CHAR,     /* control char (incl. lone CR)       */
    LPM_META_ERR_ENCODING,         /* byte >= 0x80: metadata is ASCII    */
    LPM_META_ERR_SYNTAX,           /* no '=', empty or malformed key     */
    LPM_META_ERR_UNKNOWN_KEY,      /* well-formed but unsupported key    */
    LPM_META_ERR_DUPLICATE_KEY,    /* scalar key repeated                */
    LPM_META_ERR_MISSING_FIELD,    /* required field absent              */
    LPM_META_ERR_INVALID_VALUE,    /* value fails validation             */
    LPM_META_ERR_TOO_LONG,         /* value exceeds its length limit     */
    LPM_META_ERR_TOO_MANY_DEPENDS, /* > LPM_META_MAX_DEPENDS             */
    LPM_META_ERR_DUPLICATE_DEPEND  /* same dependency name twice         */
} lpm_meta_error_code;

/*
 * Filled in by the parser instead of printing, so the caller decides
 * whether a problem is an error (lpm info) or a warning (lpm list), and
 * each problem is reported exactly once.
 */
typedef struct {
    lpm_meta_error_code code;
    size_t line;          /* 1-based line number; 0 = whole file      */
    char field[32];       /* key involved, "" if none                 */
    char message[256];    /* human-readable reason, never untruncated */
} lpm_meta_error;

/* Record an error (no-op when err is NULL). Used by the parser and by
 * callers that add their own checks, e.g. the database name check. */
void lpm_meta_error_set(lpm_meta_error *err, lpm_meta_error_code code,
                        size_t line, const char *field, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 5, 6)))
#endif
    ;

/* Format as "<source>:<line>: <message>" (or "<source>: <message>"
 * when line is 0) into buf. Always NUL-terminates when size > 0. */
void lpm_meta_error_format(const lpm_meta_error *err, const char *source,
                           char *buf, size_t size);

/* ---- Package lifetime ----------------------------------------------- */

/* Set every field to the empty state. Does not free anything. */
void lpm_package_init(lpm_package *pkg);

/*
 * Free everything the package owns, then reset it to the empty state.
 * Safe on NULL, on a zero-initialised package, on a partially built one
 * and when called repeatedly on the same object.
 */
void lpm_package_free(lpm_package *pkg);

/* ---- Parsing -------------------------------------------------------- */

/*
 * Parse len bytes at data. data need NOT be NUL-terminated and may
 * contain any bytes; it is never modified.
 *
 * Precondition: *out must not own memory (it is overwritten without
 * being freed). Pass a fresh or lpm_package_free()d object.
 *
 * On success: returns LPM_OK and *out holds a fully validated package.
 * On failure: returns LPM_ERR_INVALID or LPM_ERR_NOMEM, *out is in the
 * empty state (nothing to free) and *err (if non-NULL) says why.
 */
lpm_status lpm_metadata_parse_buffer(const char *data, size_t len,
                                     lpm_meta_profile profile,
                                     lpm_package *out, lpm_meta_error *err);

/*
 * Read a metadata file's raw bytes into a new heap buffer.
 *
 * Refuses symlinks (O_NOFOLLOW) and anything that is not a regular file
 * (checked with fstat on the opened descriptor, so there is no
 * check-then-open race). Never reads more than LPM_META_MAX_FILE_SIZE+1
 * bytes. *data is NUL-terminated for convenience, but *len is
 * authoritative. The caller frees *data.
 *
 * Returns LPM_OK, LPM_ERR_NOT_FOUND (no such file), LPM_ERR_INVALID
 * (not a regular file / too large), LPM_ERR_IO or LPM_ERR_NOMEM.
 */
lpm_status lpm_metadata_read_file(const char *path, char **data, size_t *len,
                                  lpm_meta_error *err);

/* lpm_metadata_read_file() + lpm_metadata_parse_buffer(). Same output
 * guarantees as lpm_metadata_parse_buffer(). */
lpm_status lpm_metadata_parse_file(const char *path, lpm_meta_profile profile,
                                   lpm_package *out, lpm_meta_error *err);

/* ---- Field validators (reusable by later milestones) ---------------- */

/*
 * Numeric dotted version: [0-9]+ ( "." [0-9]+ )*, 1..64 characters, no
 * leading zeros in a component ("0" itself is fine, "01" is not).
 */
bool lpm_is_valid_version(const char *version);

/* Exactly 64 characters from [0-9a-f]. Uppercase is rejected. */
bool lpm_is_valid_sha256_hex(const char *hex);

/* ">=" or "=" */
const char *lpm_dep_operator_str(lpm_dep_operator op);

#endif /* LPM_METADATA_H */
