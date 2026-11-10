/*
 * metadata.c - Strict, bounded parser for package metadata.
 *
 * Processing order for every input (all limits are checked BEFORE the
 * work they protect, so hostile input cannot make us allocate or scan
 * without bound):
 *
 *   1. whole-input size     <= LPM_META_MAX_FILE_SIZE    (before parsing)
 *   2. per line: length     <= LPM_META_MAX_LINE_LEN     (before copying)
 *   3. per line: bytes are printable ASCII or TAB        (before parsing)
 *   4. per line: syntax, key, value validation, duplicates
 *   5. per value: its own length limit                   (before strdup)
 *   6. dependency count     <= LPM_META_MAX_DEPENDS      (before growing)
 *   7. whole package: required fields for the chosen profile
 *
 * The package is built in a private temporary and copied to the
 * caller's object only after step 7 succeeds, so a failed parse can
 * never leak a half-built package to the caller.
 */
#include "metadata.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Longest slice of an untrusted value echoed back in a diagnostic. */
#define QUOTE_MAX 48

/* Parser working state. Lives on the caller's stack for one parse. */
typedef struct {
    lpm_package pkg;                          /* package under construction */
    size_t dep_capacity;                      /* allocated dependency slots */
    size_t dep_lines[LPM_META_MAX_DEPENDS];   /* line of each depends=      */
    size_t line_no;                           /* current line, 1-based      */
    lpm_meta_error *err;                      /* may be NULL                */
} parser;

/* ------------------------------------------------------------------ */
/* Error helpers                                                       */
/* ------------------------------------------------------------------ */

void lpm_meta_error_set(lpm_meta_error *err, lpm_meta_error_code code,
                        size_t line, const char *field, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL)
        return;
    err->code = code;
    err->line = line;
    snprintf(err->field, sizeof(err->field), "%s", field ? field : "");
    va_start(ap, fmt);
    vsnprintf(err->message, sizeof(err->message), fmt, ap);
    va_end(ap);
}

static void error_clear(lpm_meta_error *err)
{
    if (err == NULL)
        return;
    err->code = LPM_META_ERR_NONE;
    err->line = 0;
    err->field[0] = '\0';
    err->message[0] = '\0';
}

void lpm_meta_error_format(const lpm_meta_error *err, const char *source,
                           char *buf, size_t size)
{
    if (buf == NULL || size == 0)
        return;
    if (err == NULL) {
        snprintf(buf, size, "%s: unknown metadata error", source);
        return;
    }
    if (err->line > 0)
        snprintf(buf, size, "%s:%zu: %s", source, err->line, err->message);
    else
        snprintf(buf, size, "%s: %s", source, err->message);
}

/* "..." when a value is longer than what we echo in messages. */
static const char *ellipsis(const char *s)
{
    return strnlen(s, QUOTE_MAX + 1) > QUOTE_MAX ? "..." : "";
}

static lpm_status nomem(parser *p)
{
    lpm_meta_error_set(p->err, LPM_META_ERR_NOMEM, p->line_no, NULL,
                       "out of memory while parsing metadata");
    return LPM_ERR_NOMEM;
}

/* ------------------------------------------------------------------ */
/* Package lifetime                                                    */
/* ------------------------------------------------------------------ */

void lpm_package_init(lpm_package *pkg)
{
    if (pkg == NULL)
        return;
    pkg->name = NULL;
    pkg->version = NULL;
    pkg->description = NULL;
    pkg->dependencies = NULL;
    pkg->dependency_count = 0;
    pkg->manifest_sha256[0] = '\0';
    pkg->has_manifest_sha256 = false;
}

void lpm_package_free(lpm_package *pkg)
{
    size_t i;

    if (pkg == NULL)
        return;
    free(pkg->name);
    free(pkg->version);
    free(pkg->description);
    /* Only the first dependency_count slots are ever initialised. */
    for (i = 0; i < pkg->dependency_count; i++) {
        free(pkg->dependencies[i].name);
        free(pkg->dependencies[i].version);
    }
    free(pkg->dependencies);
    lpm_package_init(pkg);   /* safe to free again or reuse */
}

/* ------------------------------------------------------------------ */
/* Field validators                                                    */
/* ------------------------------------------------------------------ */

bool lpm_is_valid_version(const char *version)
{
    size_t i, len, comp_len = 0;

    if (version == NULL)
        return false;
    len = strnlen(version, LPM_META_MAX_VERSION_LEN + 1);
    if (len == 0 || len > LPM_META_MAX_VERSION_LEN)
        return false;

    /* i == len visits the terminating NUL, closing the last component. */
    for (i = 0; i <= len; i++) {
        char c = version[i];

        if (c == '.' || c == '\0') {
            if (comp_len == 0)          /* ".1", "1.", "1..2" */
                return false;
            comp_len = 0;
        } else if (c >= '0' && c <= '9') {
            /* A second digit after a leading '0' means "01", "007". */
            if (comp_len == 1 && version[i - 1] == '0')
                return false;
            comp_len++;
        } else {
            return false;               /* "v1", "1.2beta", "1.0-rc1" */
        }
    }
    return true;
}

bool lpm_is_valid_sha256_hex(const char *hex)
{
    size_t i;

    if (hex == NULL || strnlen(hex, LPM_SHA256_HEX_LEN + 1) != LPM_SHA256_HEX_LEN)
        return false;
    for (i = 0; i < LPM_SHA256_HEX_LEN; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

const char *lpm_dep_operator_str(lpm_dep_operator op)
{
    return op == LPM_DEP_MINIMUM ? ">=" : "=";
}

/* A well-formed key is [A-Za-z0-9_]+; anything else (spaces, '.', ...)
 * is a syntax error. Uppercase is accepted here only so that "Name=" is
 * reported precisely as an unsupported (case-sensitive) field. */
static bool is_wellformed_key(const char *key)
{
    const char *c;

    if (*key == '\0')
        return false;
    for (c = key; *c != '\0'; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9') || *c == '_'))
            return false;
    }
    return true;
}

/* Shared by name= and the name part of depends=: one rule everywhere,
 * identical to the rule used for database filenames. */
static lpm_status check_name(parser *p, const char *field, const char *what,
                             const char *v)
{
    size_t len = strlen(v);   /* v is a NUL-terminated slice of one line */

    if (len == 0) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, field,
                           "empty %s", what);
        return LPM_ERR_INVALID;
    }
    if (len > LPM_MAX_NAME_LEN) {
        lpm_meta_error_set(p->err, LPM_META_ERR_TOO_LONG, p->line_no, field,
                           "%s is %zu characters, maximum is %d",
                           what, len, LPM_MAX_NAME_LEN);
        return LPM_ERR_INVALID;
    }
    if (!lpm_is_valid_package_name(v)) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, field,
                           "invalid %s '%.*s%s': use a-z 0-9 + . _ - and start "
                           "with a letter or digit", what, QUOTE_MAX, v, ellipsis(v));
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static lpm_status check_version(parser *p, const char *field, const char *what,
                                const char *v)
{
    size_t len = strlen(v);

    if (len == 0) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, field,
                           "empty %s", what);
        return LPM_ERR_INVALID;
    }
    if (len > LPM_META_MAX_VERSION_LEN) {
        lpm_meta_error_set(p->err, LPM_META_ERR_TOO_LONG, p->line_no, field,
                           "%s is %zu characters, maximum is %d",
                           what, len, LPM_META_MAX_VERSION_LEN);
        return LPM_ERR_INVALID;
    }
    if (!lpm_is_valid_version(v)) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, field,
                           "invalid %s '%.*s%s': expected numbers separated by "
                           "dots, e.g. 1.2.3, without leading zeros",
                           what, QUOTE_MAX, v, ellipsis(v));
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static lpm_status duplicate_key(parser *p, const char *key)
{
    lpm_meta_error_set(p->err, LPM_META_ERR_DUPLICATE_KEY, p->line_no, key,
                       "duplicate field '%s' (it may appear only once)", key);
    return LPM_ERR_INVALID;
}

/* ------------------------------------------------------------------ */
/* Field handlers: each receives a trimmed, NUL-terminated value.      */
/* ------------------------------------------------------------------ */

static lpm_status field_name(parser *p, const char *v)
{
    lpm_status rc;

    if (p->pkg.name != NULL)
        return duplicate_key(p, "name");
    rc = check_name(p, "name", "package name", v);
    if (rc != LPM_OK)
        return rc;
    p->pkg.name = lpm_strdup(v);
    return p->pkg.name ? LPM_OK : nomem(p);
}

static lpm_status field_version(parser *p, const char *v)
{
    lpm_status rc;

    if (p->pkg.version != NULL)
        return duplicate_key(p, "version");
    rc = check_version(p, "version", "version", v);
    if (rc != LPM_OK)
        return rc;
    p->pkg.version = lpm_strdup(v);
    return p->pkg.version ? LPM_OK : nomem(p);
}

static lpm_status field_description(parser *p, const char *v)
{
    size_t len = strlen(v);

    if (p->pkg.description != NULL)
        return duplicate_key(p, "description");
    if (len > LPM_META_MAX_DESC_LEN) {
        lpm_meta_error_set(p->err, LPM_META_ERR_TOO_LONG, p->line_no, "description",
                           "description is %zu characters, maximum is %d",
                           len, LPM_META_MAX_DESC_LEN);
        return LPM_ERR_INVALID;
    }
    /* An empty description is allowed and stored as "" (not NULL). */
    p->pkg.description = lpm_strdup(v);
    return p->pkg.description ? LPM_OK : nomem(p);
}

static lpm_status field_manifest_sha256(parser *p, const char *v)
{
    size_t i, len = strlen(v);

    if (p->pkg.has_manifest_sha256)
        return duplicate_key(p, "manifest_sha256");
    if (len != LPM_SHA256_HEX_LEN) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no,
                           "manifest_sha256",
                           "manifest_sha256 must be exactly %d hexadecimal "
                           "characters, got %zu", LPM_SHA256_HEX_LEN, len);
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < len; i++) {
        char c = v[i];
        if (c >= 'A' && c <= 'F') {
            lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no,
                               "manifest_sha256",
                               "manifest_sha256 must use lowercase hexadecimal "
                               "(uppercase '%c' at position %zu)", c, i + 1);
            return LPM_ERR_INVALID;
        }
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no,
                               "manifest_sha256",
                               "manifest_sha256 contains non-hexadecimal "
                               "character '%c' at position %zu", c, i + 1);
            return LPM_ERR_INVALID;
        }
    }
    memcpy(p->pkg.manifest_sha256, v, LPM_SHA256_HEX_LEN + 1);
    p->pkg.has_manifest_sha256 = true;
    return LPM_OK;
}

/* Grow the dependency array if full. Never exceeds LPM_META_MAX_DEPENDS. */
static lpm_status reserve_dependency(parser *p)
{
    size_t new_cap;
    lpm_dependency *grown;

    if (p->pkg.dependency_count < p->dep_capacity)
        return LPM_OK;

    new_cap = p->dep_capacity ? p->dep_capacity * 2 : 4;
    if (new_cap > LPM_META_MAX_DEPENDS)
        new_cap = LPM_META_MAX_DEPENDS;
    if (new_cap > SIZE_MAX / sizeof(*grown))   /* multiplication overflow */
        return nomem(p);

    /* Assign through a temporary: on failure the old block is still
     * owned by the package and gets freed by the normal cleanup path. */
    grown = realloc(p->pkg.dependencies, new_cap * sizeof(*grown));
    if (grown == NULL)
        return nomem(p);
    p->pkg.dependencies = grown;
    p->dep_capacity = new_cap;
    return LPM_OK;
}

/*
 * depends=NAME>=VERSION or depends=NAME=VERSION
 *
 * The operator is the maximal run of operator characters after the
 * name, and it must be exactly ">=" or "=". This makes "<", "==", ">==",
 * "~=", "!=" ... fail as unsupported operators instead of being
 * misread as some other split of name/operator/version.
 */
static lpm_status field_depends(parser *p, const char *v)
{
    static const char opchars[] = "<>=!~^";
    char name[LPM_MAX_NAME_LEN + 1];
    size_t name_len, op_len, i;
    const char *op_str, *ver;
    lpm_dep_operator op;
    lpm_dependency *dep;
    lpm_status rc;

    if (p->pkg.dependency_count >= LPM_META_MAX_DEPENDS) {
        lpm_meta_error_set(p->err, LPM_META_ERR_TOO_MANY_DEPENDS, p->line_no,
                           "depends", "too many dependencies (maximum is %d)",
                           LPM_META_MAX_DEPENDS);
        return LPM_ERR_INVALID;
    }
    if (*v == '\0') {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no,
                           "depends", "empty dependency");
        return LPM_ERR_INVALID;
    }

    name_len = strcspn(v, opchars);
    op_str = v + name_len;
    op_len = strspn(op_str, opchars);
    ver = op_str + op_len;

    if (name_len == 0) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, "depends",
                           "invalid dependency '%.*s%s': missing package name",
                           QUOTE_MAX, v, ellipsis(v));
        return LPM_ERR_INVALID;
    }
    if (op_len == 0) {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, "depends",
                           "invalid dependency '%.*s%s': missing version constraint "
                           "(write NAME>=VERSION or NAME=VERSION)",
                           QUOTE_MAX, v, ellipsis(v));
        return LPM_ERR_INVALID;
    }
    if (name_len > LPM_MAX_NAME_LEN) {
        lpm_meta_error_set(p->err, LPM_META_ERR_TOO_LONG, p->line_no, "depends",
                           "dependency name is %zu characters, maximum is %d",
                           name_len, LPM_MAX_NAME_LEN);
        return LPM_ERR_INVALID;
    }
    memcpy(name, v, name_len);
    name[name_len] = '\0';
    rc = check_name(p, "depends", "dependency name", name);
    if (rc != LPM_OK)
        return rc;

    if (op_len == 2 && op_str[0] == '>' && op_str[1] == '=') {
        op = LPM_DEP_MINIMUM;
    } else if (op_len == 1 && op_str[0] == '=') {
        op = LPM_DEP_EXACT;
    } else {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, "depends",
                           "invalid dependency '%.*s%s': unsupported operator "
                           "'%.*s' (only '>=' and '=' are supported)",
                           QUOTE_MAX, v, ellipsis(v),
                           (int)(op_len > 8 ? 8 : op_len), op_str);
        return LPM_ERR_INVALID;
    }

    if (*ver == '\0') {
        lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->line_no, "depends",
                           "invalid dependency '%.*s%s': missing version",
                           QUOTE_MAX, v, ellipsis(v));
        return LPM_ERR_INVALID;
    }
    rc = check_version(p, "depends", "dependency version", ver);
    if (rc != LPM_OK)
        return rc;

    /* Reject a second constraint on the same package, even a different
     * one: "libfoo>=1" plus "libfoo=2" has no single clear meaning. */
    for (i = 0; i < p->pkg.dependency_count; i++) {
        if (strcmp(p->pkg.dependencies[i].name, name) == 0) {
            lpm_meta_error_set(p->err, LPM_META_ERR_DUPLICATE_DEPEND, p->line_no,
                               "depends", "duplicate dependency on '%s' (first "
                               "declared on line %zu)", name, p->dep_lines[i]);
            return LPM_ERR_INVALID;
        }
    }

    rc = reserve_dependency(p);
    if (rc != LPM_OK)
        return rc;

    /* Fill the slot completely before counting it, so cleanup never
     * sees a half-initialised dependency. */
    dep = &p->pkg.dependencies[p->pkg.dependency_count];
    dep->name = lpm_strdup(name);
    dep->version = lpm_strdup(ver);
    dep->op = op;
    if (dep->name == NULL || dep->version == NULL) {
        free(dep->name);
        free(dep->version);
        return nomem(p);
    }
    p->dep_lines[p->pkg.dependency_count] = p->line_no;
    p->pkg.dependency_count++;
    return LPM_OK;
}

typedef lpm_status (*field_handler)(parser *p, const char *value);

static const struct {
    const char *key;
    field_handler handler;
} field_table[] = {
    { "name",            field_name },
    { "version",         field_version },
    { "description",     field_description },
    { "depends",         field_depends },
    { "manifest_sha256", field_manifest_sha256 },
};

/* ------------------------------------------------------------------ */
/* Line-level parsing                                                  */
/* ------------------------------------------------------------------ */

/*
 * Reject anything but printable ASCII and TAB. Runs on the raw line
 * bytes BEFORE they are copied into a C string, which is what makes
 * strlen/strchr on that copy safe (no embedded NUL can exist).
 */
static lpm_status check_line_bytes(parser *p, const char *s, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\t' || (c >= 0x20 && c < 0x7f))
            continue;
        if (c == '\0') {
            lpm_meta_error_set(p->err, LPM_META_ERR_NUL_BYTE, p->line_no, NULL,
                               "embedded NUL byte at column %zu", i + 1);
        } else if (c >= 0x80) {
            lpm_meta_error_set(p->err, LPM_META_ERR_ENCODING, p->line_no, NULL,
                               "non-ASCII byte 0x%02x at column %zu "
                               "(metadata must be plain ASCII)", c, i + 1);
        } else {
            lpm_meta_error_set(p->err, LPM_META_ERR_CONTROL_CHAR, p->line_no, NULL,
                               "invalid control character 0x%02x at column %zu",
                               c, i + 1);
        }
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

/* line is a modifiable, NUL-terminated copy with no control chars. */
static lpm_status parse_line(parser *p, char *line)
{
    char *s = lpm_trim(line);
    char *eq, *key, *value;
    size_t i;

    if (*s == '\0' || *s == '#')     /* blank line or whole-line comment */
        return LPM_OK;

    eq = strchr(s, '=');             /* split at the FIRST '=' */
    if (eq == NULL) {
        lpm_meta_error_set(p->err, LPM_META_ERR_SYNTAX, p->line_no, NULL,
                           "expected 'key=value' but no '=' was found");
        return LPM_ERR_INVALID;
    }
    *eq = '\0';
    key = lpm_trim(s);
    value = lpm_trim(eq + 1);

    if (*key == '\0') {
        lpm_meta_error_set(p->err, LPM_META_ERR_SYNTAX, p->line_no, NULL,
                           "missing key before '='");
        return LPM_ERR_INVALID;
    }
    if (!is_wellformed_key(key)) {
        lpm_meta_error_set(p->err, LPM_META_ERR_SYNTAX, p->line_no, NULL,
                           "malformed key '%.*s%s' (keys contain only letters, "
                           "digits and '_')", QUOTE_MAX, key, ellipsis(key));
        return LPM_ERR_INVALID;
    }

    for (i = 0; i < sizeof(field_table) / sizeof(field_table[0]); i++) {
        if (strcmp(field_table[i].key, key) == 0)
            return field_table[i].handler(p, value);
    }

    lpm_meta_error_set(p->err, LPM_META_ERR_UNKNOWN_KEY, p->line_no, key,
                       "unsupported field '%.*s%s' (field names are "
                       "case-sensitive)", QUOTE_MAX, key, ellipsis(key));
    return LPM_ERR_INVALID;
}

/* Whole-package checks that need every line to have been seen. */
static lpm_status finalize(parser *p, lpm_meta_profile profile)
{
    size_t i;

    p->line_no = 0;   /* errors from here on concern the whole file */

    if (p->pkg.name == NULL) {
        lpm_meta_error_set(p->err, LPM_META_ERR_MISSING_FIELD, 0, "name",
                           "missing required field 'name'");
        return LPM_ERR_INVALID;
    }
    if (p->pkg.version == NULL) {
        lpm_meta_error_set(p->err, LPM_META_ERR_MISSING_FIELD, 0, "version",
                           "missing required field 'version'");
        return LPM_ERR_INVALID;
    }
    if (profile == LPM_META_DISTRIBUTABLE && !p->pkg.has_manifest_sha256) {
        lpm_meta_error_set(p->err, LPM_META_ERR_MISSING_FIELD, 0, "manifest_sha256",
                           "missing required field 'manifest_sha256' "
                           "(required for distributable packages)");
        return LPM_ERR_INVALID;
    }
    /* A self-dependency is a one-node cycle; it is cheap to reject here. */
    for (i = 0; i < p->pkg.dependency_count; i++) {
        if (strcmp(p->pkg.dependencies[i].name, p->pkg.name) == 0) {
            lpm_meta_error_set(p->err, LPM_META_ERR_INVALID_VALUE, p->dep_lines[i],
                               "depends", "package '%s' cannot depend on itself",
                               p->pkg.name);
            return LPM_ERR_INVALID;
        }
    }
    return LPM_OK;
}

lpm_status lpm_metadata_parse_buffer(const char *data, size_t len,
                                     lpm_meta_profile profile,
                                     lpm_package *out, lpm_meta_error *err)
{
    /* One line copy: 4 KiB on the stack, a fixed and modest amount
     * regardless of input size. */
    char line[LPM_META_MAX_LINE_LEN + 1];
    parser p;
    size_t pos = 0;
    lpm_status rc = LPM_OK;

    error_clear(err);
    lpm_package_init(out);

    if (data == NULL && len > 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "no input buffer");
        return LPM_ERR_INVALID;
    }
    if (len > LPM_META_MAX_FILE_SIZE) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "metadata is %zu bytes, maximum is %d",
                           len, LPM_META_MAX_FILE_SIZE);
        return LPM_ERR_INVALID;
    }

    lpm_package_init(&p.pkg);
    p.dep_capacity = 0;
    p.line_no = 0;
    p.err = err;

    while (pos < len) {
        const char *start = data + pos;
        const char *nl = memchr(start, '\n', len - pos);
        size_t raw_len = nl ? (size_t)(nl - start) : len - pos;
        size_t content_len = raw_len;

        p.line_no++;
        pos += raw_len + (nl ? 1 : 0);

        /* Line terminators are LF or CRLF. A CR anywhere else (including
         * a final CR with no LF) stays in the content and is rejected
         * as a control character by check_line_bytes(). */
        if (nl != NULL && content_len > 0 && start[content_len - 1] == '\r')
            content_len--;

        if (content_len > LPM_META_MAX_LINE_LEN) {
            lpm_meta_error_set(err, LPM_META_ERR_LINE_TOO_LONG, p.line_no, NULL,
                               "line is %zu bytes, maximum is %d",
                               content_len, LPM_META_MAX_LINE_LEN);
            rc = LPM_ERR_INVALID;
            break;
        }
        rc = check_line_bytes(&p, start, content_len);
        if (rc != LPM_OK)
            break;

        memcpy(line, start, content_len);
        line[content_len] = '\0';

        rc = parse_line(&p, line);
        if (rc != LPM_OK)
            break;
    }

    if (rc == LPM_OK)
        rc = finalize(&p, profile);

    if (rc != LPM_OK) {
        lpm_package_free(&p.pkg);   /* out is still in the empty state */
        return rc;
    }

    *out = p.pkg;                   /* ownership moves to the caller */
    return LPM_OK;
}

/* ------------------------------------------------------------------ */
/* File input                                                          */
/* ------------------------------------------------------------------ */

lpm_status lpm_read_bounded_fileat(int dirfd, const char *path, size_t max_size,
                                   char **data, size_t *len, lpm_meta_error *err)
{
    struct stat st;
    char *buf = NULL;
    size_t total = 0, cap;
    int fd;
    lpm_status rc = LPM_OK;

    *data = NULL;
    *len = 0;
    error_clear(err);

    /* O_NOFOLLOW: refuse a symlink as the final component.
     * O_NONBLOCK: opening a FIFO must not hang; fstat rejects it next. */
    fd = openat(dirfd, path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        int e = errno;
        if (e == ENOENT) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "file does not exist");
            return LPM_ERR_NOT_FOUND;
        }
        if (e == ELOOP) {
            lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL,
                               "refusing to read metadata through a symbolic link");
            return LPM_ERR_INVALID;
        }
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open: %s",
                           strerror(e));
        return LPM_ERR_IO;
    }

    /* fstat on the open descriptor: checks the file we will actually
     * read, not whatever the path points to a moment later. */
    if (fstat(fd, &st) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot stat: %s",
                           strerror(errno));
        rc = LPM_ERR_IO;
        goto out;
    }
    if (!S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL,
                           "not a regular file");
        rc = LPM_ERR_INVALID;
        goto out;
    }
    if (st.st_size < 0 || (uintmax_t)st.st_size > (uintmax_t)max_size) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "file is %jd bytes, maximum is %zu",
                           (intmax_t)st.st_size, max_size);
        rc = LPM_ERR_INVALID;
        goto out;
    }

    /* Size the buffer from fstat (bounded by max_size above) plus one
     * spare byte: if that byte gets filled, the file grew after fstat. */
    cap = (size_t)st.st_size + 1;
    buf = malloc(cap + 1);   /* +1 for the convenience NUL */
    if (buf == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL,
                           "out of memory reading file");
        rc = LPM_ERR_NOMEM;
        goto out;
    }

    while (total < cap) {
        ssize_t n = read(fd, buf + total, cap - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "read failed: %s",
                               strerror(errno));
            rc = LPM_ERR_IO;
            goto out;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    if (total == cap) {
        if (total > max_size)
            lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                               "file exceeds %zu bytes", max_size);
        else
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "file changed while it was being read");
        rc = total > max_size ? LPM_ERR_INVALID : LPM_ERR_IO;
        goto out;
    }

    buf[total] = '\0';
    *data = buf;
    *len = total;
    buf = NULL;   /* ownership moved to the caller */

out:
    free(buf);
    close(fd);
    return rc;
}

lpm_status lpm_metadata_read_fileat(int dirfd, const char *path, char **data,
                                    size_t *len, lpm_meta_error *err)
{
    return lpm_read_bounded_fileat(dirfd, path, LPM_META_MAX_FILE_SIZE,
                                   data, len, err);
}

lpm_status lpm_metadata_read_file(const char *path, char **data, size_t *len,
                                  lpm_meta_error *err)
{
    return lpm_metadata_read_fileat(AT_FDCWD, path, data, len, err);
}

lpm_status lpm_metadata_parse_file(const char *path, lpm_meta_profile profile,
                                   lpm_package *out, lpm_meta_error *err)
{
    char *data;
    size_t len;
    lpm_status rc;

    lpm_package_init(out);
    rc = lpm_metadata_read_file(path, &data, &len, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_metadata_parse_buffer(data, len, profile, out, err);
    free(data);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Serialisation (installed-database records)                          */
/* ------------------------------------------------------------------ */

/*
 * A description is written verbatim after "description=". It must read
 * back as exactly the same string, so reject anything the parser would
 * reject or silently change: line breaks (which would inject new
 * fields), other control characters, non-ASCII, and leading/trailing
 * blanks (which the parser trims).
 */
static lpm_status check_description_text(const char *d, lpm_meta_error *err)
{
    size_t i, len = strnlen(d, LPM_META_MAX_DESC_LEN + 1);

    if (len > LPM_META_MAX_DESC_LEN) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_LONG, 0, "description",
                           "description is longer than %d characters",
                           LPM_META_MAX_DESC_LEN);
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)d[i];
        if (c == '\t' || (c >= 0x20 && c < 0x7f))
            continue;
        lpm_meta_error_set(err, c >= 0x80 ? LPM_META_ERR_ENCODING
                                          : LPM_META_ERR_CONTROL_CHAR,
                           0, "description",
                           "description contains byte 0x%02x at column %zu "
                           "(only printable ASCII and TAB can be stored)",
                           c, i + 1);
        return LPM_ERR_INVALID;
    }
    if (len > 0 && (d[0] == ' ' || d[0] == '\t' ||
                    d[len - 1] == ' ' || d[len - 1] == '\t')) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "description",
                           "description has leading or trailing whitespace, "
                           "which would not survive a round trip");
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static lpm_status check_package_fields(const lpm_package *pkg,
                                       lpm_meta_profile profile,
                                       lpm_meta_error *err)
{
    size_t i, j;

    if (!lpm_is_valid_package_name(pkg->name)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "name",
                           "missing or invalid package name");
        return LPM_ERR_INVALID;
    }
    if (!lpm_is_valid_version(pkg->version)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "version",
                           "missing or invalid version");
        return LPM_ERR_INVALID;
    }
    if (pkg->description != NULL &&
        check_description_text(pkg->description, err) != LPM_OK)
        return LPM_ERR_INVALID;

    if (pkg->dependency_count > LPM_META_MAX_DEPENDS) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_MANY_DEPENDS, 0, "depends",
                           "too many dependencies (maximum is %d)",
                           LPM_META_MAX_DEPENDS);
        return LPM_ERR_INVALID;
    }
    if (pkg->dependency_count > 0 && pkg->dependencies == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "depends",
                           "dependency count is set but the array is missing");
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < pkg->dependency_count; i++) {
        const lpm_dependency *d = &pkg->dependencies[i];

        if (!lpm_is_valid_package_name(d->name) ||
            !lpm_is_valid_version(d->version) ||
            (d->op != LPM_DEP_EXACT && d->op != LPM_DEP_MINIMUM)) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "depends",
                               "dependency %zu is invalid", i + 1);
            return LPM_ERR_INVALID;
        }
        if (strcmp(d->name, pkg->name) == 0) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "depends",
                               "package '%s' cannot depend on itself", pkg->name);
            return LPM_ERR_INVALID;
        }
        for (j = 0; j < i; j++) {
            if (strcmp(pkg->dependencies[j].name, d->name) == 0) {
                lpm_meta_error_set(err, LPM_META_ERR_DUPLICATE_DEPEND, 0,
                                   "depends", "duplicate dependency on '%s'",
                                   d->name);
                return LPM_ERR_INVALID;
            }
        }
    }

    if (pkg->has_manifest_sha256) {
        if (!lpm_is_valid_sha256_hex(pkg->manifest_sha256)) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0,
                               "manifest_sha256",
                               "manifest_sha256 is not 64 lowercase hex digits");
            return LPM_ERR_INVALID;
        }
    } else if (profile == LPM_META_DISTRIBUTABLE) {
        lpm_meta_error_set(err, LPM_META_ERR_MISSING_FIELD, 0, "manifest_sha256",
                           "missing required field 'manifest_sha256'");
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static bool opt_str_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return strcmp(a, b) == 0;
}

bool lpm_package_equal(const lpm_package *a, const lpm_package *b)
{
    size_t i;

    if (!opt_str_eq(a->name, b->name) || !opt_str_eq(a->version, b->version) ||
        !opt_str_eq(a->description, b->description) ||
        a->dependency_count != b->dependency_count ||
        a->has_manifest_sha256 != b->has_manifest_sha256)
        return false;
    if (a->has_manifest_sha256 &&
        strcmp(a->manifest_sha256, b->manifest_sha256) != 0)
        return false;
    for (i = 0; i < a->dependency_count; i++) {
        const lpm_dependency *da = &a->dependencies[i];
        const lpm_dependency *db = &b->dependencies[i];
        if (da->op != db->op || !opt_str_eq(da->name, db->name) ||
            !opt_str_eq(da->version, db->version))
            return false;
    }
    return true;
}

/* Append a string to a buffer whose total size was computed up front. */
static void put(char *buf, size_t *pos, const char *s)
{
    size_t n = strlen(s);
    memcpy(buf + *pos, s, n);
    *pos += n;
}

lpm_status lpm_metadata_serialize(const lpm_package *pkg, lpm_meta_profile profile,
                                  char **out, size_t *out_len, lpm_meta_error *err)
{
    size_t i, size, pos = 0;
    char *buf;
    lpm_package check;
    lpm_status rc;

    *out = NULL;
    *out_len = 0;
    error_clear(err);
    if (pkg == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, NULL, "no package");
        return LPM_ERR_INVALID;
    }
    rc = check_package_fields(pkg, profile, err);
    if (rc != LPM_OK)
        return rc;

    /* Exact size. Every field is bounded above (64 + 64 + 1024 +
     * 128 * (64 + 2 + 64) + 64 plus keys), so this is far below both
     * SIZE_MAX and LPM_META_MAX_FILE_SIZE; no overflow is possible. */
    size = strlen("name=\n") + strlen(pkg->name) +
           strlen("version=\n") + strlen(pkg->version);
    if (pkg->description != NULL)
        size += strlen("description=\n") + strlen(pkg->description);
    for (i = 0; i < pkg->dependency_count; i++)
        size += strlen("depends=\n") + strlen(pkg->dependencies[i].name) +
                strlen(lpm_dep_operator_str(pkg->dependencies[i].op)) +
                strlen(pkg->dependencies[i].version);
    if (pkg->has_manifest_sha256)
        size += strlen("manifest_sha256=\n") + LPM_SHA256_HEX_LEN;

    buf = malloc(size + 1);
    if (buf == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL,
                           "out of memory serialising metadata");
        return LPM_ERR_NOMEM;
    }

    /* Fixed field order, dependencies in their given order: the same
     * package always produces the same bytes. */
    put(buf, &pos, "name=");
    put(buf, &pos, pkg->name);
    put(buf, &pos, "\nversion=");
    put(buf, &pos, pkg->version);
    put(buf, &pos, "\n");
    if (pkg->description != NULL) {
        put(buf, &pos, "description=");
        put(buf, &pos, pkg->description);
        put(buf, &pos, "\n");
    }
    for (i = 0; i < pkg->dependency_count; i++) {
        put(buf, &pos, "depends=");
        put(buf, &pos, pkg->dependencies[i].name);
        put(buf, &pos, lpm_dep_operator_str(pkg->dependencies[i].op));
        put(buf, &pos, pkg->dependencies[i].version);
        put(buf, &pos, "\n");
    }
    if (pkg->has_manifest_sha256) {
        put(buf, &pos, "manifest_sha256=");
        put(buf, &pos, pkg->manifest_sha256);
        put(buf, &pos, "\n");
    }
    buf[pos] = '\0';

    /* Safety net: the record must parse back, with the strict parser,
     * into exactly the package we were given. If it ever did not, the
     * database would store something other than what was validated. */
    rc = lpm_metadata_parse_buffer(buf, pos, profile, &check, err);
    if (rc == LPM_OK && !lpm_package_equal(pkg, &check)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, NULL,
                           "serialised record does not round-trip");
        rc = LPM_ERR_INVALID;
    }
    lpm_package_free(&check);
    if (rc != LPM_OK) {
        free(buf);
        return rc;
    }
    *out = buf;
    *out_len = pos;
    return LPM_OK;
}
