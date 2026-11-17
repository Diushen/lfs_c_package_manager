/*
 * pkg.c - Verify (and optionally stage) a package, entry by entry.
 */
#include "pkg.h"
#include "filelist.h"
#include "integrity.h"
#include "lpm_archive.h"
#include "safefs.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK (64 * 1024)

void lpm_pkg_init(lpm_pkg *p)
{
    lpm_package_init(&p->meta);
    p->metadata_raw = NULL;
    p->metadata_len = 0;
    lpm_manifest_init(&p->manifest);
    p->payload_bytes = 0;
}

void lpm_pkg_free(lpm_pkg *p)
{
    if (p == NULL)
        return;
    lpm_package_free(&p->meta);
    free(p->metadata_raw);
    lpm_manifest_free(&p->manifest);
    lpm_pkg_init(p);
}

void lpm_pkg_stage_name(size_t index, char buf[16])
{
    snprintf(buf, 16, "f%06zu", index);
}

/* Read the current (small) entry completely into a new buffer. */
static lpm_status read_small(lpm_archive *a, const lpm_archive_entry *e,
                             size_t max, char **out, size_t *out_len,
                             lpm_meta_error *err)
{
    char *buf;
    size_t len = 0;
    lpm_status rc;

    *out = NULL;
    *out_len = 0;
    if (e->size < 0 || (uint64_t)e->size > max) {
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "%s is larger than %zu bytes", e->path, max);
        return LPM_ERR_INVALID;
    }
    buf = malloc((size_t)e->size + 1);
    if (buf == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    for (;;) {
        size_t got, room = (size_t)e->size - len;
        char spare;
        /* Ask for one byte more than declared to catch inconsistencies. */
        rc = room > 0 ? lpm_archive_read(a, buf + len, room, &got, err)
                      : lpm_archive_read(a, &spare, 1, &got, err);
        if (rc != LPM_OK) {
            free(buf);
            return rc;
        }
        if (got == 0)
            break;
        if (room == 0) {
            free(buf);
            lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                               "%s is longer than its declared size", e->path);
            return LPM_ERR_INVALID;
        }
        len += got;
    }
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return LPM_OK;
}

static lpm_status expect_entry(lpm_archive *a, lpm_archive_entry *e,
                               const char *name, lpm_meta_error *err)
{
    bool end;
    lpm_status rc = lpm_archive_next(a, e, &end, err);

    if (rc != LPM_OK)
        return rc;
    if (end || e->type != LPM_AENTRY_FILE || strcmp(e->path, name) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                           "not an LPM package: expected '%s' as %s entry",
                           name, strcmp(name, LPM_PKG_METADATA) == 0 ? "the first"
                                                                    : "the second");
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

/* Stream one payload file through SHA-256 (and into the stage). */
static lpm_status take_file(lpm_archive *a, lpm_pkg *p, const lpm_manifest_entry *me,
                            size_t index, int stage_fd, lpm_meta_error *err)
{
    char buf[CHUNK], got_hex[LPM_SHA256_HEX_LEN + 1], name[16];
    lpm_sha256_ctx h;
    lpm_status rc;
    int fd = -1;

    if (stage_fd >= 0) {
        lpm_pkg_stage_name(index, name);
        fd = openat(stage_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                    O_CLOEXEC | O_NOCTTY, 0600);
        if (fd < 0) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot create staging file for %.200s: %s",
                               me->path, strerror(errno));
            return LPM_ERR_IO;
        }
    }
    rc = lpm_sha256_begin(&h, err);
    while (rc == LPM_OK) {
        size_t got;
        rc = lpm_archive_read(a, buf, sizeof(buf), &got, err);
        if (rc != LPM_OK) {
            lpm_sha256_abort(&h);
            break;
        }
        if (got == 0) {
            rc = lpm_sha256_finish(&h, got_hex, err);
            break;
        }
        if (got > LPM_ARCHIVE_MAX_BYTES - p->payload_bytes) {
            lpm_sha256_abort(&h);
            lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, NULL,
                               "payload expands to more than the 8 GiB limit");
            rc = LPM_ERR_INVALID;
            break;
        }
        p->payload_bytes += got;
        rc = lpm_sha256_update(&h, buf, got, err);
        if (rc == LPM_OK && fd >= 0 && lpm_write_all(fd, buf, got) != 0) {
            lpm_sha256_abort(&h);
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot write staging file for %.200s: %s",
                               me->path, strerror(errno));
            rc = LPM_ERR_IO;
        }
    }
    if (rc == LPM_OK && !lpm_sha256_equal(got_hex, me->sha256)) {
        lpm_meta_error_set(err, LPM_META_ERR_HASH_MISMATCH, 0, "sha256",
                           "SHA-256 mismatch for %.100s: manifest says %.16s..., "
                           "file is %.16s...", me->path, me->sha256, got_hex);
        rc = LPM_ERR_INTEGRITY;
    }
    if (fd >= 0) {
        if (rc == LPM_OK && (fchmod(fd, me->mode) != 0 || lpm_fsync_retry(fd) != 0)) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot flush staging file for %.200s: %s",
                               me->path, strerror(errno));
            rc = LPM_ERR_IO;
        }
        if (close(fd) != 0 && rc == LPM_OK) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot write staging file for %.200s: %s",
                               me->path, strerror(errno));
            rc = LPM_ERR_IO;
        }
    }
    return rc;
}

static lpm_status payload_entry(lpm_archive *a, lpm_pkg *p, const lpm_archive_entry *e,
                                unsigned char *seen, int stage_fd, lpm_meta_error *err)
{
    char clean[LPM_FILES_MAX_PATH + 2];
    const char *rel, *owned;
    const lpm_manifest_entry *me;
    size_t index, plen = strlen(LPM_PKG_PAYLOAD);
    lpm_status rc;

    if (e->type == LPM_AENTRY_HARDLINK || e->type == LPM_AENTRY_SPECIAL) {
        lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                           "'%.200s' rejected: hard links, devices, FIFOs and "
                           "sockets are not allowed in packages", e->path);
        return LPM_ERR_INVALID;
    }
    rc = lpm_archive_clean_path(e->path, e->type == LPM_AENTRY_DIR, clean,
                                sizeof(clean), &rel, err);
    if (rc != LPM_OK)
        return rc;
    /* rel is "payload" or "payload/<path>"; clean is "/" + rel. */
    if (strncmp(rel, LPM_PKG_PAYLOAD, plen) != 0 ||
        (rel[plen] != '\0' && rel[plen] != '/')) {
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                           "unexpected entry '%.200s' (package files must be "
                           "under payload/)", e->path);
        return LPM_ERR_INVALID;
    }
    if (rel[plen] == '\0') {
        if (e->type == LPM_AENTRY_DIR)
            return LPM_OK;   /* the payload/ directory itself */
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                           "'payload' must be a directory");
        return LPM_ERR_INVALID;
    }
    owned = rel + plen;   /* "/usr/bin/hello" */

    me = lpm_manifest_find(&p->manifest, owned, &index);
    if (me == NULL) {
        if (e->type == LPM_AENTRY_DIR)
            return LPM_OK;   /* intermediate dirs carry no content */
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                           "payload entry '%.200s' is not listed in manifest.txt",
                           owned);
        return LPM_ERR_INVALID;
    }
    if (seen[index]) {
        lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                           "payload entry '%.200s' appears more than once", owned);
        return LPM_ERR_INVALID;
    }
    seen[index] = 1;

    switch (me->type) {
    case LPM_MAN_DIR:
        if (e->type == LPM_AENTRY_DIR)
            return LPM_OK;
        break;
    case LPM_MAN_SYMLINK:
        if (e->type == LPM_AENTRY_SYMLINK) {
            if (strcmp(e->link, me->target) != 0) {
                lpm_meta_error_set(err, LPM_META_ERR_HASH_MISMATCH, 0, "path",
                                   "symbolic link '%.200s' does not match the "
                                   "manifest", owned);
                return LPM_ERR_INTEGRITY;
            }
            return LPM_OK;
        }
        break;
    case LPM_MAN_FILE:
        if (e->type == LPM_AENTRY_FILE)
            return take_file(a, p, me, index, stage_fd, err);
        break;
    }
    lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                       "payload entry '%.200s' has a different type than in "
                       "manifest.txt", owned);
    return LPM_ERR_INVALID;
}

lpm_status lpm_pkg_read(int fd, int stage_fd, lpm_pkg *out, lpm_meta_error *err)
{
    char digest[LPM_SHA256_HEX_LEN + 1];
    lpm_archive *a = NULL;
    lpm_archive_entry e;
    lpm_pkg p;
    char *manifest_raw = NULL;
    size_t manifest_len, i;
    unsigned char *seen = NULL;
    lpm_status rc;

    lpm_pkg_init(out);
    lpm_pkg_init(&p);

    rc = lpm_archive_open_fd(fd, &a, err);
    if (rc != LPM_OK)
        return rc;

    /* 1. metadata.txt: parsed with the strict Milestone 2 parser. The raw
     *    bytes are kept: a signature must be checked on exactly these. */
    rc = expect_entry(a, &e, LPM_PKG_METADATA, err);
    if (rc == LPM_OK)
        rc = read_small(a, &e, LPM_META_MAX_FILE_SIZE, &p.metadata_raw,
                        &p.metadata_len, err);
    if (rc == LPM_OK) {
        rc = lpm_metadata_parse_buffer(p.metadata_raw, p.metadata_len,
                                       LPM_META_DISTRIBUTABLE, &p.meta, err);
        if (rc == LPM_ERR_INVALID && err != NULL) {
            /* Prefix the file name; copy first (no overlapping writes). */
            lpm_meta_error orig = *err;
            lpm_meta_error_set(err, orig.code, orig.line, orig.field,
                               "metadata.txt: %.200s", orig.message);
        }
    }
    if (rc != LPM_OK)
        goto out;

    /* 2. manifest.txt: its hash must equal manifest_sha256 BEFORE it is
     *    trusted for anything, even before it is parsed. */
    rc = expect_entry(a, &e, LPM_PKG_MANIFEST, err);
    if (rc == LPM_OK)
        rc = read_small(a, &e, LPM_MANIFEST_MAX_SIZE, &manifest_raw, &manifest_len, err);
    if (rc == LPM_OK)
        rc = lpm_sha256_buffer(manifest_raw, manifest_len, digest, err);
    if (rc != LPM_OK)
        goto out;
    if (!lpm_sha256_equal(digest, p.meta.manifest_sha256)) {
        lpm_meta_error_set(err, LPM_META_ERR_HASH_MISMATCH, 0, "manifest_sha256",
                           "manifest.txt does not match manifest_sha256 in "
                           "metadata.txt (expected %s, got %s)",
                           p.meta.manifest_sha256, digest);
        rc = LPM_ERR_INTEGRITY;
        goto out;
    }
    rc = lpm_manifest_parse(manifest_raw, manifest_len, &p.manifest, err);
    if (rc != LPM_OK)
        goto out;

    /* 3. payload: every entry must be listed, and every file must hash
     *    to its manifest value. */
    seen = calloc(p.manifest.count ? p.manifest.count : 1, 1);
    if (seen == NULL) {
        rc = LPM_ERR_NOMEM;
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        goto out;
    }
    for (;;) {
        bool end;
        rc = lpm_archive_next(a, &e, &end, err);
        if (rc != LPM_OK || end)
            break;
        rc = payload_entry(a, &p, &e, seen, stage_fd, err);
        if (rc != LPM_OK)
            break;
    }
    if (rc != LPM_OK)
        goto out;

    /* 4. Nothing listed may be missing (directories excepted: they are
     *    created from the manifest itself). */
    for (i = 0; i < p.manifest.count; i++) {
        if (!seen[i] && p.manifest.entries[i].type != LPM_MAN_DIR) {
            lpm_meta_error_set(err, LPM_META_ERR_ARCHIVE, 0, "path",
                               "'%.200s' is listed in manifest.txt but missing "
                               "from the payload", p.manifest.entries[i].path);
            rc = LPM_ERR_INVALID;
            goto out;
        }
    }
    *out = p;
    lpm_pkg_init(&p);

out:
    free(seen);
    free(manifest_raw);
    lpm_pkg_free(&p);
    lpm_archive_close(a);
    return rc;
}
