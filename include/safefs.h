/*
 * safefs.h - Writing below a root directory without ever leaving it.
 *
 * Every operation starts from an open descriptor for the root and walks
 * one path component at a time with openat(O_NOFOLLOW | O_DIRECTORY).
 * A symlink (or anything that is not a directory) in the middle of a
 * path makes the walk fail instead of being followed, so no path can be
 * redirected outside the root, whether the symlink came from the
 * archive being extracted or was already present on disk.
 *
 * Paths here are relative ("usr/bin/hello"), already validated with
 * lpm_is_valid_owned_path() (filelist.h) after adding a leading '/'.
 */
#ifndef LPM_SAFEFS_H
#define LPM_SAFEFS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "lpm.h"
#include "metadata.h"   /* lpm_meta_error */

/* What an operation created, so a failure can be undone in reverse. */
typedef struct {
    char **paths;   /* relative paths */
    bool *is_dir;
    size_t count, capacity;
} lpm_path_log;

void lpm_path_log_init(lpm_path_log *log);
void lpm_path_log_free(lpm_path_log *log);
lpm_status lpm_path_log_add(lpm_path_log *log, const char *path, bool is_dir,
                            lpm_meta_error *err);

/*
 * Open directory `rel` below base_fd ("" means base_fd itself). With
 * create, missing components are made with `mode` and appended to
 * `created` (may be NULL). Fails with LPM_ERR_INVALID
 * (LPM_META_ERR_UNSAFE_ENTRY) if a component is a symlink or not a
 * directory, LPM_ERR_NOT_FOUND if missing and !create.
 */
lpm_status lpm_safe_open_dir(int base_fd, const char *rel, bool create,
                             mode_t mode, lpm_path_log *created, int *out_fd,
                             lpm_meta_error *err);

/*
 * Milestone 6: like lpm_safe_open_dir(), for security-sensitive
 * directories (the trusted-key store). Every component must also be
 * owned by the current user or root and not be writable by group or
 * others, otherwise LPM_ERR_INVALID (LPM_META_ERR_UNTRUSTED).
 */
lpm_status lpm_safe_open_trusted_dir(int base_fd, const char *rel, bool create,
                                     mode_t mode, int *out_fd, lpm_meta_error *err);

/*
 * Split "a/b/c" into parent "a/b" (written to parent, "" for a top-level
 * name) and base "c" (a pointer into rel). LPM_ERR_INVALID if the
 * parent does not fit.
 */
lpm_status lpm_safe_split(const char *rel, char *parent, size_t size,
                          const char **base, lpm_meta_error *err);

/*
 * Undo a log in reverse order: unlink files/symlinks, rmdir directories
 * (only if empty; a directory that gained other content is left). Best
 * effort; never follows symlinks. Clears the log.
 */
void lpm_safe_rollback(int base_fd, lpm_path_log *log);

/* write() everything, coping with short writes and EINTR. -1 + errno. */
int lpm_write_all(int fd, const void *data, size_t len);

/* fsync, retrying only EINTR. -1 + errno. */
int lpm_fsync_retry(int fd);

/* Symlink targets LPM accepts: relative, no ".." or empty component,
 * printable ASCII, at most LPM_FILES_MAX_PATH bytes. Such a target can
 * only point at or below the directory containing the link. */
bool lpm_is_safe_symlink_target(const char *target);

#endif /* LPM_SAFEFS_H */
