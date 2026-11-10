/*
 * util.c - Diagnostics, safe strings/paths, name validation, status codes.
 */
#include "util.h"
#include "lpm.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void vreport(const char *prefix, const char *fmt, va_list ap)
{
    fflush(stdout);   /* keep stdout/stderr ordering sane on a terminal */
    fputs(prefix, stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void lpm_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vreport("ERROR: ", fmt, ap);
    va_end(ap);
}

void lpm_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vreport("WARNING: ", fmt, ap);
    va_end(ap);
}

char *lpm_strdup(const char *s)
{
    size_t len;
    char *copy;

    if (s == NULL)
        return NULL;
    len = strlen(s);
    copy = malloc(len + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, s, len + 1);
    return copy;
}

char *lpm_path_join(const char *base, const char *rel)
{
    size_t base_len, rel_len, total;
    char *out;

    if (base == NULL || rel == NULL)
        return NULL;

    /* Drop trailing '/' from base and leading '/' from rel. */
    base_len = strlen(base);
    while (base_len > 0 && base[base_len - 1] == '/')
        base_len--;
    while (*rel == '/')
        rel++;
    rel_len = strlen(rel);

    /* base + '/' + rel + '\0', checked for size_t overflow. */
    if (base_len > SIZE_MAX - rel_len - 2)
        return NULL;
    total = base_len + 1 + rel_len + 1;

    out = malloc(total);
    if (out == NULL)
        return NULL;

    memcpy(out, base, base_len);
    out[base_len] = '/';
    memcpy(out + base_len + 1, rel, rel_len);
    out[base_len + 1 + rel_len] = '\0';
    return out;
}

int lpm_has_suffix(const char *s, const char *suffix)
{
    size_t s_len = strlen(s);
    size_t suf_len = strlen(suffix);

    if (suf_len > s_len)
        return 0;
    return memcmp(s + s_len - suf_len, suffix, suf_len) == 0;
}

int lpm_is_valid_package_name(const char *name)
{
    size_t i, len;

    if (name == NULL)
        return 0;
    len = strlen(name);
    if (len == 0 || len > LPM_MAX_NAME_LEN)
        return 0;

    /* First char must be alphanumeric: rules out ".", "..", "-rf", ... */
    if (!(islower((unsigned char)name[0]) || isdigit((unsigned char)name[0])))
        return 0;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(islower(c) || isdigit(c) || c == '+' || c == '.' ||
              c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

char *lpm_trim(char *s)
{
    char *end;

    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return s;
}

const char *lpm_status_str(lpm_status status)
{
    switch (status) {
    case LPM_OK:                  return "success";
    case LPM_ERR_USAGE:           return "usage error";
    case LPM_ERR_NOMEM:           return "out of memory";
    case LPM_ERR_IO:              return "I/O error";
    case LPM_ERR_NOT_FOUND:       return "not found";
    case LPM_ERR_INVALID:         return "invalid input";
    case LPM_ERR_NOT_IMPLEMENTED: return "not implemented";
    case LPM_ERR_EXISTS:          return "already exists";
    case LPM_ERR_BUSY:            return "database is locked";
    case LPM_ERR_CONFLICT:        return "file ownership conflict";
    }
    return "unknown error";
}

int lpm_status_to_exit(lpm_status status)
{
    if (status == LPM_OK)
        return 0;
    if (status == LPM_ERR_USAGE)
        return 2;
    return 1;
}
