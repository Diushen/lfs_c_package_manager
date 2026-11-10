/*
 * filelist.c - Validation, parsing and canonical serialisation of
 * file-ownership records (see filelist.h for the format).
 *
 * Same principles as the metadata parser: every limit is checked before
 * the work it protects, input is rejected rather than repaired, and the
 * result is all-or-nothing.
 */
#include "filelist.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUOTE_MAX 48

void lpm_file_list_init(lpm_file_list *list)
{
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

void lpm_file_list_free(lpm_file_list *list)
{
    size_t i;

    if (list == NULL)
        return;
    for (i = 0; i < list->count; i++)
        free(list->paths[i]);
    free(list->paths);
    lpm_file_list_init(list);
}

/* Returns NULL if path is valid, else a short reason. */
static const char *path_problem(const char *path)
{
    size_t len, i, start = 1;

    if (path == NULL)
        return "is missing";
    len = strnlen(path, LPM_FILES_MAX_PATH + 1);
    if (len == 0)
        return "is empty";
    if (len > LPM_FILES_MAX_PATH)
        return "is too long";
    if (path[0] != '/')
        return "must start with '/' (paths are relative to the target root)";
    if (len == 1)
        return "names the root directory itself";

    for (i = 1; i <= len; i++) {
        unsigned char c = (unsigned char)path[i];

        if (c != '\0' && c != '/') {
            if (c < 0x20 || c > 0x7e)
                return "contains a control or non-ASCII character";
            continue;
        }
        /* path[start..i) is one component. */
        {
            size_t clen = i - start;
            const char *comp = path + start;

            if (clen == 0)
                return "contains an empty component ('//' or a trailing '/')";
            if (clen > LPM_FILES_MAX_COMPONENT)
                return "has a component longer than 255 bytes";
            if ((clen == 1 && comp[0] == '.') ||
                (clen == 2 && comp[0] == '.' && comp[1] == '.'))
                return "contains a '.' or '..' component";
            if (comp[0] == ' ' || comp[clen - 1] == ' ')
                return "has a component that begins or ends with a space";
        }
        start = i + 1;
    }
    return NULL;
}

bool lpm_is_valid_owned_path(const char *path)
{
    return path_problem(path) == NULL;
}

static const char *ellipsis(const char *s)
{
    return strnlen(s, QUOTE_MAX + 1) > QUOTE_MAX ? "..." : "";
}

static lpm_status add_at_line(lpm_file_list *list, const char *path,
                              size_t line, lpm_meta_error *err)
{
    const char *why = path_problem(path);
    char *copy;

    if (why != NULL) {
        if (path == NULL)
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_PATH, line, "path",
                               "path is missing");
        else
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_PATH, line, "path",
                               "invalid path '%.*s%s': %s",
                               QUOTE_MAX, path, ellipsis(path), why);
        return LPM_ERR_INVALID;
    }
    if (list->count >= LPM_FILES_MAX_ENTRIES) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_MANY_FILES, line, "path",
                           "too many files (maximum is %d per package)",
                           LPM_FILES_MAX_ENTRIES);
        return LPM_ERR_INVALID;
    }
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 16;
        char **grown;

        if (new_cap > SIZE_MAX / sizeof(*grown))
            goto nomem;
        grown = realloc(list->paths, new_cap * sizeof(*grown));
        if (grown == NULL)
            goto nomem;
        list->paths = grown;
        list->capacity = new_cap;
    }
    copy = lpm_strdup(path);
    if (copy == NULL)
        goto nomem;
    list->paths[list->count++] = copy;
    return LPM_OK;

nomem:
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, line, NULL,
                       "out of memory building file list");
    return LPM_ERR_NOMEM;
}

lpm_status lpm_file_list_add(lpm_file_list *list, const char *path,
                             lpm_meta_error *err)
{
    return add_at_line(list, path, 0, err);
}

/* ---- Conflict detection --------------------------------------------- */

static int compare_owned(const void *pa, const void *pb)
{
    const lpm_owned_path *a = pa, *b = pb;
    int c = strcmp(a->path, b->path);

    if (c != 0)
        return c;
    return (a->owner > b->owner) - (a->owner < b->owner);
}

void lpm_owned_paths_sort(lpm_owned_path *v, size_t n)
{
    if (n > 1)
        qsort(v, n, sizeof(*v), compare_owned);
}

/* Compare s with the first klen bytes of key, as if key were cut there. */
static int compare_prefix(const char *s, const char *key, size_t klen)
{
    int c = strncmp(s, key, klen);

    if (c != 0)
        return c;
    return s[klen] != '\0';   /* s is longer: s > key */
}

/* First index whose path is >= key[0..klen) (classic lower bound). */
static size_t lower_bound(const lpm_owned_path *v, size_t n,
                          const char *key, size_t klen)
{
    size_t lo = 0, hi = n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (compare_prefix(v[mid].path, key, klen) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

size_t lpm_owned_paths_conflicts(const lpm_owned_path *v, size_t n,
                                 lpm_conflict_fn fn, void *ctx)
{
    size_t i, found = 0;

    for (i = 0; i < n; i++) {
        const char *p = v[i].path;
        size_t k;

        /* Duplicates are neighbours once sorted. */
        if (i > 0 && strcmp(v[i - 1].path, p) == 0) {
            found++;
            if (!fn(ctx, &v[i - 1], &v[i], true))
                return found;
        }
        /* Every proper parent "/a", "/a/b" of p: is it listed too? */
        for (k = 1; p[k] != '\0'; k++) {
            size_t j;

            if (p[k] != '/')
                continue;
            for (j = lower_bound(v, n, p, k);
                 j < n && compare_prefix(v[j].path, p, k) == 0; j++) {
                found++;
                if (!fn(ctx, &v[j], &v[i], false))
                    return found;
            }
        }
    }
    return found;
}

/* Stop at the first conflict and describe it. */
static bool first_conflict(void *ctx, const lpm_owned_path *a,
                           const lpm_owned_path *b, bool same_path)
{
    lpm_meta_error *err = ctx;

    if (same_path)
        lpm_meta_error_set(err, LPM_META_ERR_DUPLICATE_PATH, 0, "path",
                           "path '%.*s%s' is listed more than once",
                           QUOTE_MAX, a->path, ellipsis(a->path));
    else
        lpm_meta_error_set(err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                           "'%.*s%s' is listed as a file, but '%.*s%s' is "
                           "inside it", QUOTE_MAX, a->path, ellipsis(a->path),
                           QUOTE_MAX, b->path, ellipsis(b->path));
    return false;
}

/* Run the conflict search over a list that is already sorted. */
static lpm_status check_sorted_list(const lpm_file_list *list, lpm_meta_error *err)
{
    lpm_owned_path *v;
    size_t i, found;

    if (list->count == 0)
        return LPM_OK;
    v = malloc(list->count * sizeof(*v));   /* count <= 65536: no overflow */
    if (v == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL,
                           "out of memory checking file list");
        return LPM_ERR_NOMEM;
    }
    for (i = 0; i < list->count; i++) {
        v[i].path = list->paths[i];
        v[i].owner = 0;
    }
    found = lpm_owned_paths_conflicts(v, list->count, first_conflict, err);
    free(v);
    return found ? LPM_ERR_INVALID : LPM_OK;
}

static int compare_strings(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

lpm_status lpm_file_list_finalize(lpm_file_list *list, lpm_meta_error *err)
{
    if (list->count > 1)
        qsort(list->paths, list->count, sizeof(list->paths[0]), compare_strings);
    return check_sorted_list(list, err);
}

lpm_status lpm_file_list_parse_buffer(const char *data, size_t len,
                                      lpm_file_list *out, lpm_meta_error *err)
{
    char line[LPM_FILES_MAX_PATH + 1];
    lpm_file_list tmp;
    size_t pos = 0, line_no = 0;
    lpm_status rc = LPM_OK;

    lpm_file_list_init(out);
    lpm_file_list_init(&tmp);
    if (err != NULL)
        lpm_meta_error_set(err, LPM_META_ERR_NONE, 0, NULL, "%s", "");

    if (len > LPM_FILES_MAX_SIZE) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "file list is %zu bytes, maximum is %d",
                           len, LPM_FILES_MAX_SIZE);
        return LPM_ERR_INVALID;
    }

    while (pos < len) {
        const char *start = data + pos;
        const char *nl = memchr(start, '\n', len - pos);
        size_t llen, i;

        line_no++;
        if (nl == NULL) {
            lpm_meta_error_set(err, LPM_META_ERR_SYNTAX, line_no, NULL,
                               "last line is not terminated by a newline "
                               "(truncated file?)");
            rc = LPM_ERR_INVALID;
            goto fail;
        }
        llen = (size_t)(nl - start);
        if (llen > LPM_FILES_MAX_PATH) {
            lpm_meta_error_set(err, LPM_META_ERR_LINE_TOO_LONG, line_no, NULL,
                               "path is %zu bytes, maximum is %d",
                               llen, LPM_FILES_MAX_PATH);
            rc = LPM_ERR_INVALID;
            goto fail;
        }
        /* Raw bytes are checked before the line becomes a C string. */
        for (i = 0; i < llen; i++) {
            unsigned char c = (unsigned char)start[i];
            if (c == '\0') {
                lpm_meta_error_set(err, LPM_META_ERR_NUL_BYTE, line_no, NULL,
                                   "embedded NUL byte at column %zu", i + 1);
                rc = LPM_ERR_INVALID;
                goto fail;
            }
            if (c < 0x20 || c > 0x7e) {
                lpm_meta_error_set(err, c >= 0x80 ? LPM_META_ERR_ENCODING
                                                  : LPM_META_ERR_CONTROL_CHAR,
                                   line_no, NULL,
                                   "invalid byte 0x%02x at column %zu", c, i + 1);
                rc = LPM_ERR_INVALID;
                goto fail;
            }
        }
        memcpy(line, start, llen);
        line[llen] = '\0';
        rc = add_at_line(&tmp, line, line_no, err);
        if (rc != LPM_OK)
            goto fail;
        pos += llen + 1;
    }

    rc = lpm_file_list_finalize(&tmp, err);
    if (rc != LPM_OK)
        goto fail;
    *out = tmp;
    return LPM_OK;

fail:
    lpm_file_list_free(&tmp);
    return rc;
}

lpm_status lpm_file_list_serialize(const lpm_file_list *list, char **out,
                                   size_t *out_len, lpm_meta_error *err)
{
    size_t i, size = 0, pos = 0;
    char *buf;
    lpm_status rc;

    *out = NULL;
    *out_len = 0;

    if (list->count > LPM_FILES_MAX_ENTRIES) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_MANY_FILES, 0, "path",
                           "too many files (maximum is %d per package)",
                           LPM_FILES_MAX_ENTRIES);
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < list->count; i++) {
        const char *p = list->paths[i];

        if (!lpm_is_valid_owned_path(p)) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_PATH, 0, "path",
                               "file list entry %zu is not a valid path", i + 1);
            return LPM_ERR_INVALID;
        }
        if (i > 0 && strcmp(list->paths[i - 1], p) >= 0) {
            lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, "path",
                               "file list is not finalized (unsorted or "
                               "duplicate entries)");
            return LPM_ERR_INVALID;
        }
        size += strlen(p) + 1;   /* <= 65536 * 1025: cannot overflow */
    }
    if (size > LPM_FILES_MAX_SIZE) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "file list would be %zu bytes, maximum is %d",
                           size, LPM_FILES_MAX_SIZE);
        return LPM_ERR_INVALID;
    }
    rc = check_sorted_list(list, err);
    if (rc != LPM_OK)
        return rc;

    buf = malloc(size + 1);
    if (buf == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL,
                           "out of memory serialising file list");
        return LPM_ERR_NOMEM;
    }
    for (i = 0; i < list->count; i++) {
        size_t n = strlen(list->paths[i]);
        memcpy(buf + pos, list->paths[i], n);
        pos += n;
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';
    *out = buf;
    *out_len = pos;
    return LPM_OK;
}

bool lpm_file_list_contains(const lpm_file_list *list, const char *path)
{
    size_t lo = 0, hi = list->count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(list->paths[mid], path);
        if (c == 0)
            return true;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}
