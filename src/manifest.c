/*
 * manifest.c - Strict parser for manifest.txt (format in manifest.h).
 */
#include "manifest.h"
#include "safefs.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lpm_manifest_init(lpm_manifest *m)
{
    m->entries = NULL;
    m->count = m->capacity = 0;
    m->files = m->symlinks = m->dirs = 0;
}

void lpm_manifest_free(lpm_manifest *m)
{
    size_t i;

    if (m == NULL)
        return;
    for (i = 0; i < m->count; i++) {
        free(m->entries[i].path);
        free(m->entries[i].target);
    }
    free(m->entries);
    lpm_manifest_init(m);
}

/* "0755" / "644": 3-4 octal digits, value <= 0755 with no 022 bits. */
static bool parse_mode(const char *s, size_t len, unsigned *out)
{
    unsigned v = 0;
    size_t i;

    if (len < 3 || len > 4)
        return false;
    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '7')
            return false;
        v = v * 8 + (unsigned)(s[i] - '0');
    }
    *out = v;
    return true;
}

static lpm_status bad_line(lpm_meta_error *err, size_t line, lpm_meta_error_code code,
                           const char *msg)
{
    lpm_meta_error_set(err, code, line, NULL, "manifest: %s", msg);
    return LPM_ERR_INVALID;
}

static lpm_status add_entry(lpm_manifest *m, lpm_manifest_entry *e,
                            lpm_meta_error *err, size_t line)
{
    if (m->count == m->capacity) {
        size_t new_cap = m->capacity ? m->capacity * 2 : 32;
        lpm_manifest_entry *g;

        if (new_cap > SIZE_MAX / sizeof(*g))
            goto nomem;
        g = realloc(m->entries, new_cap * sizeof(*g));
        if (g == NULL)
            goto nomem;
        m->entries = g;
        m->capacity = new_cap;
    }
    m->entries[m->count++] = *e;
    return LPM_OK;
nomem:
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, line, NULL, "out of memory");
    return LPM_ERR_NOMEM;
}

/* line: NUL-terminated copy of one line (checked: printable ASCII). */
static lpm_status parse_line(lpm_manifest *m, char *line, size_t line_no,
                             lpm_meta_error *err)
{
    lpm_manifest_entry e;
    char *sp1, *sp2, *sp3 = NULL, *path;
    lpm_status rc;

    memset(&e, 0, sizeof(e));
    sp1 = strchr(line, ' ');
    if (sp1 == NULL)
        return bad_line(err, line_no, LPM_META_ERR_SYNTAX, "expected '<type> ...'");
    *sp1 = '\0';
    sp2 = strchr(sp1 + 1, ' ');
    if (sp2 == NULL)
        return bad_line(err, line_no, LPM_META_ERR_SYNTAX, "missing fields");
    *sp2 = '\0';

    if (strcmp(line, "file") == 0) {
        sp3 = strchr(sp2 + 1, ' ');
        if (sp3 == NULL)
            return bad_line(err, line_no, LPM_META_ERR_SYNTAX,
                            "expected 'file <sha256> <mode> <path>'");
        *sp3 = '\0';
        if (!lpm_is_valid_sha256_hex(sp1 + 1))
            return bad_line(err, line_no, LPM_META_ERR_INVALID_VALUE,
                            "file hash must be 64 lowercase hex digits");
        memcpy(e.sha256, sp1 + 1, LPM_SHA256_HEX_LEN + 1);
        if (!parse_mode(sp2 + 1, strlen(sp2 + 1), &e.mode))
            return bad_line(err, line_no, LPM_META_ERR_INVALID_VALUE,
                            "mode must be 3-4 octal digits");
        e.type = LPM_MAN_FILE;
        path = sp3 + 1;
    } else if (strcmp(line, "dir") == 0) {
        if (!parse_mode(sp1 + 1, strlen(sp1 + 1), &e.mode))
            return bad_line(err, line_no, LPM_META_ERR_INVALID_VALUE,
                            "mode must be 3-4 octal digits");
        e.type = LPM_MAN_DIR;
        path = sp2 + 1;
    } else if (strcmp(line, "symlink") == 0) {
        if (!lpm_is_safe_symlink_target(sp1 + 1))
            return bad_line(err, line_no, LPM_META_ERR_UNSAFE_ENTRY,
                            "symlink target must be relative and must not "
                            "contain '..' (it could point outside the root)");
        e.type = LPM_MAN_SYMLINK;
        path = sp2 + 1;
    } else {
        return bad_line(err, line_no, LPM_META_ERR_SYNTAX,
                        "unknown entry type (expected file, symlink or dir)");
    }

    if (e.type != LPM_MAN_SYMLINK && (e.mode & ~0755u) != 0)
        return bad_line(err, line_no, LPM_META_ERR_UNSAFE_ENTRY,
                        "mode not allowed: setuid, setgid, sticky and "
                        "group/world-writable bits are rejected");
    if (!lpm_is_valid_owned_path(path)) {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, line_no, "path",
                           "manifest: unsafe or malformed path '%.200s'", path);
        return LPM_ERR_INVALID;
    }
    if (e.type == LPM_MAN_DIR ? m->dirs >= LPM_FILES_MAX_ENTRIES
                              : m->files + m->symlinks >= LPM_FILES_MAX_ENTRIES)
        return bad_line(err, line_no, LPM_META_ERR_TOO_MANY_FILES, "too many entries");

    e.path = lpm_strdup(path);
    if (e.type == LPM_MAN_SYMLINK)
        e.target = lpm_strdup(sp1 + 1);
    if (e.path == NULL || (e.type == LPM_MAN_SYMLINK && e.target == NULL)) {
        free(e.path);
        free(e.target);
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, line_no, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    rc = add_entry(m, &e, err, line_no);
    if (rc != LPM_OK) {
        free(e.path);
        free(e.target);
        return rc;
    }
    if (e.type == LPM_MAN_FILE)
        m->files++;
    else if (e.type == LPM_MAN_SYMLINK)
        m->symlinks++;
    else
        m->dirs++;
    return LPM_OK;
}

static int compare_entries(const void *a, const void *b)
{
    return strcmp(((const lpm_manifest_entry *)a)->path,
                  ((const lpm_manifest_entry *)b)->path);
}

/* Conflicts: same path twice, or a non-directory with children. */
static bool on_conflict(void *ctx, const lpm_owned_path *a, const lpm_owned_path *b,
                        bool same_path)
{
    lpm_meta_error *err = ctx;

    if (same_path) {
        lpm_meta_error_set(err, LPM_META_ERR_DUPLICATE_PATH, 0, "path",
                           "manifest: '%.200s' is listed more than once", a->path);
        return false;
    }
    if (a->owner == LPM_MAN_DIR)
        return true;   /* a directory with entries inside: normal */
    lpm_meta_error_set(err, LPM_META_ERR_PATH_CONFLICT, 0, "path",
                       "manifest: '%.100s' is not a directory but '%.100s' is "
                       "inside it", a->path, b->path);
    return false;
}

lpm_status lpm_manifest_parse(const char *data, size_t len, lpm_manifest *out,
                              lpm_meta_error *err)
{
    char *line = NULL;
    lpm_manifest m;
    lpm_owned_path *v = NULL;
    size_t pos = 0, line_no = 0, i;
    lpm_status rc = LPM_OK;
    bool problem = false;

    lpm_manifest_init(out);
    lpm_manifest_init(&m);
    if (len > LPM_MANIFEST_MAX_SIZE) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "manifest is %zu bytes, maximum is %d", len,
                           LPM_MANIFEST_MAX_SIZE);
        return LPM_ERR_INVALID;
    }
    line = malloc(LPM_MANIFEST_MAX_LINE + 1);
    if (line == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }

    while (pos < len) {
        const char *start = data + pos;
        const char *nl = memchr(start, '\n', len - pos);
        size_t llen, k;

        line_no++;
        if (nl == NULL) {
            rc = bad_line(err, line_no, LPM_META_ERR_SYNTAX,
                          "last line is not terminated by a newline");
            goto fail;
        }
        llen = (size_t)(nl - start);
        if (llen > LPM_MANIFEST_MAX_LINE) {
            rc = bad_line(err, line_no, LPM_META_ERR_LINE_TOO_LONG, "line too long");
            goto fail;
        }
        for (k = 0; k < llen; k++) {
            unsigned char c = (unsigned char)start[k];
            if (c < 0x20 || c > 0x7e) {
                rc = bad_line(err, line_no, c == 0 ? LPM_META_ERR_NUL_BYTE
                                          : c >= 0x80 ? LPM_META_ERR_ENCODING
                                                      : LPM_META_ERR_CONTROL_CHAR,
                              "invalid byte (only printable ASCII is allowed)");
                goto fail;
            }
        }
        memcpy(line, start, llen);
        line[llen] = '\0';
        rc = parse_line(&m, line, line_no, err);
        if (rc != LPM_OK)
            goto fail;
        pos += llen + 1;
    }

    if (m.count > 1)
        qsort(m.entries, m.count, sizeof(*m.entries), compare_entries);
    if (m.count > 0) {
        v = malloc(m.count * sizeof(*v));
        if (v == NULL) {
            rc = LPM_ERR_NOMEM;
            lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
            goto fail;
        }
        for (i = 0; i < m.count; i++) {
            v[i].path = m.entries[i].path;
            v[i].owner = (size_t)m.entries[i].type;
        }
        lpm_owned_paths_sort(v, m.count);
        /* A directory with children is reported to on_conflict too, but
         * is not an error; only a filled-in error code means one. */
        {
            lpm_meta_error local;
            local.code = LPM_META_ERR_NONE;
            local.message[0] = '\0';
            lpm_owned_paths_conflicts(v, m.count, on_conflict, &local);
            problem = local.code != LPM_META_ERR_NONE;
            if (problem && err != NULL)
                *err = local;
        }
        free(v);
        v = NULL;
        if (problem) {
            rc = LPM_ERR_INVALID;
            goto fail;
        }
    }
    free(line);
    *out = m;
    return LPM_OK;

fail:
    free(v);
    free(line);
    lpm_manifest_free(&m);
    return rc;
}

const lpm_manifest_entry *lpm_manifest_find(const lpm_manifest *m, const char *path,
                                            size_t *index)
{
    size_t lo = 0, hi = m->count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(m->entries[mid].path, path);
        if (c == 0) {
            if (index != NULL)
                *index = mid;
            return &m->entries[mid];
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

lpm_status lpm_manifest_owned(const lpm_manifest *m, lpm_file_list *out,
                              lpm_meta_error *err)
{
    size_t i;
    lpm_status rc;

    lpm_file_list_init(out);
    for (i = 0; i < m->count; i++) {
        if (m->entries[i].type == LPM_MAN_DIR)
            continue;
        rc = lpm_file_list_add(out, m->entries[i].path, err);
        if (rc != LPM_OK) {
            lpm_file_list_free(out);
            return rc;
        }
    }
    rc = lpm_file_list_finalize(out, err);
    if (rc != LPM_OK)
        lpm_file_list_free(out);
    return rc;
}
