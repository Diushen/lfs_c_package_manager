/*
 * filelist.h - File-ownership records: which files belong to a package.
 *
 * Stored as <root>/var/lib/lpm/files/<name>.list, one path per line:
 *
 *   /usr/bin/hello
 *   /usr/share/doc/hello/README
 *
 * Path convention (one convention, everywhere):
 *   - Each path names an object *inside the target root*, written with a
 *     leading '/': "/usr/bin/hello" means <root>/usr/bin/hello. The
 *     --root prefix is never stored.
 *   - Components are separated by exactly one '/'; no empty, "." or ".."
 *     components; no trailing '/'.
 *   - Printable ASCII only (0x20-0x7E); a component may not begin or end
 *     with a space (invisible, hence ambiguous). Non-ASCII file names are
 *     a documented limitation.
 *   - Entries are non-directory objects: regular files and symbolic
 *     links. Directories are never listed (they are shared between
 *     packages and will be removed only when empty). Consequently a path
 *     that is a parent of another listed path is a conflict.
 *   - Stored sorted (byte order) and without duplicates, so the same set
 *     of files always produces the same bytes.
 *
 * A file list records a *claim of ownership*. It does not prove that any
 * file exists, and nothing in this module touches files on disk.
 */
#ifndef LPM_FILELIST_H
#define LPM_FILELIST_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "metadata.h"   /* lpm_meta_error */

#define LPM_FILES_MAX_PATH       1024              /* bytes per path       */
#define LPM_FILES_MAX_COMPONENT  255               /* bytes, like NAME_MAX */
#define LPM_FILES_MAX_ENTRIES    65536             /* paths per package    */
#define LPM_FILES_MAX_SIZE       (8 * 1024 * 1024) /* bytes per .list file */

/* A growable list of owned paths. Owns every string. */
typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} lpm_file_list;

void lpm_file_list_init(lpm_file_list *list);

/* Free everything; leaves an empty list. Safe on an empty list. */
void lpm_file_list_free(lpm_file_list *list);

/* Does path follow the convention above? */
bool lpm_is_valid_owned_path(const char *path);

/*
 * Validate and append a copy of path (order and duplicates are checked
 * later, by lpm_file_list_finalize). Fails with LPM_ERR_INVALID for a
 * malformed path or when the list already holds LPM_FILES_MAX_ENTRIES,
 * or LPM_ERR_NOMEM. The list is unchanged on failure.
 */
lpm_status lpm_file_list_add(lpm_file_list *list, const char *path,
                             lpm_meta_error *err);

/*
 * Sort the list into canonical order and reject duplicates and
 * file-versus-parent conflicts. Required before serialising, and done
 * automatically by lpm_file_list_parse_buffer().
 */
lpm_status lpm_file_list_finalize(lpm_file_list *list, lpm_meta_error *err);

/*
 * Parse a .list file's bytes: LF-terminated lines (the last one too, so
 * a truncated file is detected), no blank lines, at most
 * LPM_FILES_MAX_SIZE bytes. Input order does not matter; the result is
 * finalized. All-or-nothing: on failure *out is empty and *err gives the
 * line number and reason.
 */
lpm_status lpm_file_list_parse_buffer(const char *data, size_t len,
                                      lpm_file_list *out, lpm_meta_error *err);

/*
 * Produce the canonical bytes of a finalized list (sorted, one path per
 * line, LF endings; an empty list is an empty file). Re-checks every
 * path, ordering and conflicts, and refuses output larger than
 * LPM_FILES_MAX_SIZE, so the writer can never produce a file the reader
 * would reject. Caller frees *out.
 */
lpm_status lpm_file_list_serialize(const lpm_file_list *list, char **out,
                                   size_t *out_len, lpm_meta_error *err);

/* Binary search in a finalized list. */
bool lpm_file_list_contains(const lpm_file_list *list, const char *path);

/* ---- Ownership conflicts across several lists ----------------------- */

/* One owned path tagged with an owner index chosen by the caller. */
typedef struct {
    const char *path;   /* not owned */
    size_t owner;
} lpm_owned_path;

/* Sort by path (byte order), then by owner. */
void lpm_owned_paths_sort(lpm_owned_path *v, size_t n);

/*
 * Called for each conflict: a and b have the same path (same_path) or
 * a is a parent directory of b. Return false to stop the search.
 */
typedef bool (*lpm_conflict_fn)(void *ctx, const lpm_owned_path *a,
                                const lpm_owned_path *b, bool same_path);

/*
 * Report every conflict in a sorted array: equal neighbours, and every
 * path that is also a parent of another path. Each parent prefix is
 * found by binary search, so the cost is O(n * depth * log n) for n
 * paths of depth `depth`, plus one callback per conflict.
 * Returns the number of conflicts reported.
 */
size_t lpm_owned_paths_conflicts(const lpm_owned_path *v, size_t n,
                                 lpm_conflict_fn fn, void *ctx);

#endif /* LPM_FILELIST_H */
