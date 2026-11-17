/*
 * lpm_archive.h - Reading tar archives, and extracting them safely.
 *
 * (Named lpm_archive.h, not archive.h: the build searches include/
 * first, so an "archive.h" here would hide libarchive's own header.)
 *
 * libarchive does the parsing; this module is the only one that
 * includes it, so the rest of LPM never depends on libarchive's API.
 * Accepted: tar (ustar, pax, GNU) either uncompressed or compressed with
 * gzip or xz, detected automatically. Nothing else is enabled.
 *
 * libarchive is used to READ only. Files are always written by LPM
 * itself, with the directory-relative, symlink-refusing code in
 * safefs.c, so the safety rules below do not depend on library options.
 */
#ifndef LPM_ARCHIVE_H
#define LPM_ARCHIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lpm.h"
#include "metadata.h"   /* lpm_meta_error */

/* Upper bounds that stop decompression bombs and absurd archives. */
#define LPM_ARCHIVE_MAX_ENTRIES   (4 * 65536)
#define LPM_ARCHIVE_MAX_BYTES     ((uint64_t)8 * 1024 * 1024 * 1024)  /* 8 GiB */
#define LPM_ARCHIVE_MAX_PATH      4096

typedef struct lpm_archive lpm_archive;   /* opaque */

typedef enum {
    LPM_AENTRY_FILE,
    LPM_AENTRY_DIR,
    LPM_AENTRY_SYMLINK,
    LPM_AENTRY_HARDLINK,
    LPM_AENTRY_SPECIAL      /* device, FIFO, socket */
} lpm_aentry_type;

/* One entry header. Strings stay valid until the next lpm_archive_next(). */
typedef struct {
    const char *path;       /* exactly as stored in the archive */
    lpm_aentry_type type;
    const char *link;       /* symlink or hard-link target, else NULL */
    int64_t size;           /* regular files: stored size; else 0 */
    unsigned mode;          /* stored permission bits (07777) */
} lpm_archive_entry;

/* Open a file by path, or an already open descriptor (read from its
 * current offset; not closed by LPM). */
lpm_status lpm_archive_open(const char *path, lpm_archive **out, lpm_meta_error *err);
lpm_status lpm_archive_open_fd(int fd, lpm_archive **out, lpm_meta_error *err);

/* Next header. *end is set at the end of the archive. Corrupt or
 * unsupported data is LPM_ERR_INVALID (LPM_META_ERR_ARCHIVE). */
lpm_status lpm_archive_next(lpm_archive *a, lpm_archive_entry *e, bool *end,
                            lpm_meta_error *err);

/* Read the current entry's data; *got == 0 means it is complete. */
lpm_status lpm_archive_read(lpm_archive *a, void *buf, size_t cap, size_t *got,
                            lpm_meta_error *err);

/* Safe on NULL. */
void lpm_archive_close(lpm_archive *a);

/*
 * Normalise an entry path: strip one leading "./" and, for directories,
 * one trailing '/'. Then reject (LPM_ERR_INVALID, LPM_META_ERR_UNSAFE_ENTRY)
 * absolute paths, any ".." component, and anything that fails the
 * owned-path rules of filelist.h. On success *out is a relative path in
 * buf ("" for the archive root itself, e.g. "./").
 */
lpm_status lpm_archive_clean_path(const char *path, bool is_dir, char *buf,
                                  size_t size, const char **out, lpm_meta_error *err);

/*
 * Generic safe extraction of a whole archive below dest_dir.
 *
 *  - every entry path is cleaned with lpm_archive_clean_path();
 *  - regular files, directories and safe symlinks
 *    (lpm_is_safe_symlink_target) are created; hard links, devices,
 *    FIFOs and sockets are rejected;
 *  - nothing is ever written through a symlink, and nothing existing is
 *    overwritten;
 *  - permissions are limited to 0755 (no setuid/setgid/sticky, nothing
 *    group- or world-writable); ownership is never changed;
 *  - on any failure every file and directory created so far is removed
 *    again, so the destination is left as it was.
 */
lpm_status lpm_archive_extract(const char *archive_path, const char *dest_dir,
                               lpm_meta_error *err);

#endif /* LPM_ARCHIVE_H */
