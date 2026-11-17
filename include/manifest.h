/*
 * manifest.h - The manifest.txt inside a package (Milestone 4).
 *
 * One entry per line, fields separated by single spaces, path last (so
 * paths may contain spaces), every line ending in LF:
 *
 *   file <sha256> <mode> <path>      regular file with its content hash
 *   symlink <target> <path>          symbolic link
 *   dir <mode> <path>                directory (needed only if empty)
 *
 *   file 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae 0755 /usr/bin/hello
 *   symlink hello /usr/bin/hi
 *   dir 0755 /usr/share/hello
 *
 * Rules (all checked; input is rejected, never repaired):
 *   - path: the owned-path convention of filelist.h ("/usr/bin/hello");
 *   - sha256: 64 lowercase hex digits (the manifest is hashed and, later,
 *     signed, so it has one spelling);
 *   - mode: 3 or 4 octal digits, at most 0755: no setuid, setgid or
 *     sticky bit and nothing group/world-writable (rejected, not
 *     silently stripped, so a package never means something different
 *     from what it says);
 *   - symlink target: relative and without ".." (safefs.h), so a link
 *     can only point at or below its own directory;
 *   - no path twice, and no file or symlink may be the parent of another
 *     entry (only directories have children);
 *   - at most LPM_FILES_MAX_ENTRIES files+symlinks, as many directories,
 *     LPM_MANIFEST_MAX_SIZE bytes.
 *
 * Its SHA-256 is metadata.txt's manifest_sha256, which is what ties every
 * payload byte to the metadata (and, in a later milestone, to the
 * signature over metadata.txt).
 */
#ifndef LPM_MANIFEST_H
#define LPM_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "filelist.h"
#include "metadata.h"

#define LPM_MANIFEST_MAX_SIZE   (16 * 1024 * 1024)
#define LPM_MANIFEST_MAX_LINE   (8 + LPM_FILES_MAX_PATH + 1 + LPM_FILES_MAX_PATH)

typedef enum {
    LPM_MAN_FILE,
    LPM_MAN_SYMLINK,
    LPM_MAN_DIR
} lpm_manifest_type;

typedef struct {
    lpm_manifest_type type;
    char *path;                              /* "/usr/bin/hello"          */
    char *target;                            /* symlinks only, else NULL */
    char sha256[LPM_SHA256_HEX_LEN + 1];     /* files only, else ""      */
    unsigned mode;                           /* files and dirs           */
} lpm_manifest_entry;

/* Entries are kept sorted by path (byte order). */
typedef struct {
    lpm_manifest_entry *entries;
    size_t count, capacity;
    size_t files, symlinks, dirs;
} lpm_manifest;

void lpm_manifest_init(lpm_manifest *m);
void lpm_manifest_free(lpm_manifest *m);

/* All-or-nothing; *err carries the line number. */
lpm_status lpm_manifest_parse(const char *data, size_t len, lpm_manifest *out,
                              lpm_meta_error *err);

/* Binary search; index via *index (may be NULL). NULL if absent. */
const lpm_manifest_entry *lpm_manifest_find(const lpm_manifest *m, const char *path,
                                            size_t *index);

/* The paths the package will own (files and symlinks; directories are
 * shared and never owned), as a finalized file list for the database. */
lpm_status lpm_manifest_owned(const lpm_manifest *m, lpm_file_list *out,
                              lpm_meta_error *err);

#endif /* LPM_MANIFEST_H */
