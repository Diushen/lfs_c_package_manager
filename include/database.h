/*
 * database.h - The installed-package database.
 *
 * Layout (relative to the target root):
 *
 *   var/lib/lpm/installed/<name>.meta   metadata record (INSTALLED profile)
 *   var/lib/lpm/files/<name>.list       files owned by that package
 *   var/lib/lpm/lock                    flock() target for writers
 *
 * IMPORTANT: everything in this module is bookkeeping. Registering a
 * package writes database records only: it installs no files, and
 * unregistering deletes database records only, never the package's
 * files. A registered record is NOT authenticated: registration says
 * nothing about signatures or checksums, which the future installer
 * must verify independently before it installs anything.
 *
 * Reading (lpm_db_load_package, lpm_db_list_installed) needs no handle.
 * Everything else goes through an lpm_db handle from lpm_db_open(),
 * which holds the database lock until lpm_db_close().
 */
#ifndef LPM_DATABASE_H
#define LPM_DATABASE_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "filelist.h"
#include "metadata.h"

/* Prefix of in-progress temporary files; never a valid package name,
 * and ignored by `lpm list` because it starts with '.'. */
#define LPM_DB_TEMP_PREFIX ".lpm-tmp."

/* One installed package as shown by `lpm list`. Owns its strings. */
typedef struct {
    char *name;
    char *version;   /* "?" if the record could not be parsed */
} lpm_db_entry;

/* Growable array of entries. Free with lpm_db_list_free(). */
typedef struct {
    lpm_db_entry *items;
    size_t count;
    size_t capacity;
} lpm_db_list;

/* Return malloc'd "<root>/var/lib/lpm/installed". Caller frees. */
char *lpm_db_installed_dir(const lpm_config *cfg);

/*
 * Load the record of one installed package with strict validation.
 * The record's name= must equal the database filename.
 *
 * Returns LPM_OK (out owns the package; free with lpm_package_free),
 * LPM_ERR_NOT_FOUND (not installed), LPM_ERR_INVALID (damaged record or
 * invalid name), LPM_ERR_IO or LPM_ERR_NOMEM. On failure out is empty
 * and *err describes the problem; nothing is printed.
 */
lpm_status lpm_db_load_package(const lpm_config *cfg, const char *name,
                               lpm_package *out, lpm_meta_error *err);

/*
 * Fill *out with all installed packages, sorted by name.
 * *db_exists is set to 0 if the installed/ directory is missing
 * (an uninitialised database is not an error: it just means nothing
 * is installed yet).
 *
 * Damaged records are still listed (the package's files may well be on
 * disk) but with version "?", and a warning explains why.
 * On error, *out is left empty and needs no freeing.
 */
lpm_status lpm_db_list_installed(const lpm_config *cfg, lpm_db_list *out,
                                 int *db_exists);

/* Release every string and the array itself; safe on an empty list. */
void lpm_db_list_free(lpm_db_list *list);

/* ==================================================================== */
/* Milestone 3: locked, atomic database operations                       */
/* ==================================================================== */

typedef enum {
    LPM_DB_READ,    /* shared lock (if a lock file exists); no writes     */
    LPM_DB_WRITE,   /* exclusive lock; database must already exist        */
    LPM_DB_CREATE   /* exclusive lock; creates var/lib/lpm/... if missing */
} lpm_db_mode;

/*
 * An open database. Every file is reached through these directory
 * descriptors with *at() calls and O_NOFOLLOW, so a symlink planted in
 * the database (or swapped in between two calls) cannot redirect a
 * read or write elsewhere. Treat the fields as private.
 */
typedef struct {
    int root_fd;        /* --root directory                 */
    int lpm_fd;         /* var/lib/lpm                      */
    int installed_fd;   /* var/lib/lpm/installed            */
    int files_fd;       /* var/lib/lpm/files (-1 if absent) */
    int lock_fd;        /* var/lib/lpm/lock (-1 if no lock) */
    lpm_db_mode mode;
} lpm_db;

/*
 * Open the database under cfg->root and take the lock: exclusive for
 * WRITE/CREATE, shared for READ. If another process holds a conflicting
 * lock, retry for up to wait_ms milliseconds (0 = fail at once).
 *
 * Every database directory is opened without following symlinks and
 * must be owned by the current user or root and not be writable by
 * group or others; otherwise LPM_ERR_INVALID (LPM_META_ERR_UNTRUSTED).
 *
 * Returns LPM_OK, LPM_ERR_NOT_FOUND (no database; READ/WRITE only),
 * LPM_ERR_BUSY (lock held elsewhere), LPM_ERR_INVALID or LPM_ERR_IO.
 * On failure nothing stays open and lpm_db_close() is still safe.
 */
lpm_status lpm_db_open(const lpm_config *cfg, lpm_db_mode mode,
                       unsigned wait_ms, lpm_db *db, lpm_meta_error *err);

/* Release the lock and close everything. Safe to call twice. */
void lpm_db_close(lpm_db *db);

/* Is <name>.meta present? A non-regular entry is LPM_ERR_INVALID. */
lpm_status lpm_db_package_exists(lpm_db *db, const char *name, bool *exists,
                                 lpm_meta_error *err);

/*
 * Record a package (and the files it claims) in the database. Database
 * bookkeeping only: no package files are touched.
 *
 * pkg is re-validated and serialised with the strict metadata rules;
 * files may be NULL (owns nothing) and must otherwise be finalized.
 *
 * Fails, leaving the database unchanged, with:
 *   LPM_ERR_EXISTS    the package is already registered
 *   LPM_ERR_CONFLICT  a listed path is already owned by another package
 *   LPM_ERR_INVALID   invalid package/file list, or suspicious entries
 *   LPM_ERR_USAGE     handle not opened for writing
 *   LPM_ERR_NOMEM / LPM_ERR_IO
 *
 * Commit protocol (two files, so two atomic steps):
 *   1. files/<name>.list is written atomically (temp file, fsync,
 *      rename, fsync of the directory);
 *   2. installed/<name>.meta is written the same way. Its rename is the
 *      commit point: the package is registered iff the .meta exists.
 * If step 2 fails, step 1 is undone. A crash between the steps leaves
 * only an orphaned .list, which owns nothing (only lists with a .meta
 * count), is reported by lpm_db_check() and is replaced by the next
 * registration of that name.
 * One exception: LPM_ERR_IO with "not flushed" in the message means the
 * rename succeeded but the directory fsync failed, so the package IS
 * registered but may not survive a power cut.
 */
lpm_status lpm_db_register_package(lpm_db *db, const lpm_package *pkg,
                                   const lpm_file_list *files,
                                   lpm_meta_error *err);

/*
 * Remove a package's database records: installed/<name>.meta (the
 * commit point), then files/<name>.list. Does NOT delete any of the
 * package's files. LPM_ERR_NOT_FOUND if not registered. If the .meta is
 * removed but the .list cannot be, LPM_ERR_IO is returned and the
 * leftover orphan list is reported by lpm_db_check().
 */
lpm_status lpm_db_unregister_package(lpm_db *db, const char *name,
                                     lpm_meta_error *err);

/* Read and validate files/<name>.list. NOT_FOUND if there is none. */
lpm_status lpm_db_read_file_list(lpm_db *db, const char *name,
                                 lpm_file_list *out, lpm_meta_error *err);

/* ---- Consistency check ---------------------------------------------- */

typedef enum {
    LPM_CHECK_BAD_RECORD,            /* .meta fails strict parsing/name check */
    LPM_CHECK_UNEXPECTED_ENTRY,      /* symlink, directory, unknown file      */
    LPM_CHECK_STALE_TEMP,            /* abandoned .lpm-tmp.* file             */
    LPM_CHECK_MISSING_FILE_LIST,     /* registered package without a .list    */
    LPM_CHECK_BAD_FILE_LIST,         /* .list fails validation                */
    LPM_CHECK_ORPHAN_FILE_LIST,      /* .list without a .meta                 */
    LPM_CHECK_FILE_CONFLICT,         /* path owned twice / file vs parent     */
    LPM_CHECK_UNSATISFIED_DEPENDENCY /* dependency not registered / too old   */
} lpm_check_kind;

const char *lpm_check_kind_str(lpm_check_kind kind);

/* subject: database-relative name, e.g. "files/hello.list". */
typedef void (*lpm_check_fn)(void *ctx, lpm_check_kind kind,
                             const char *subject, const char *detail);

typedef struct {
    size_t records;       /* regular <name>.meta files examined   */
    size_t packages;      /* records that passed strict parsing   */
    size_t owned_files;   /* paths in valid, non-orphan file lists */
    size_t problems;      /* callbacks made                        */
} lpm_check_summary;

/*
 * Examine the database and report each problem through fn. Read-only:
 * nothing is repaired or deleted. Returns LPM_OK when the check ran to
 * completion (whatever it found; see summary->problems), or
 * LPM_ERR_NOMEM / LPM_ERR_IO if it could not.
 *
 * NOT checked (later milestones): whether owned files exist on disk or
 * match the manifest, and signatures.
 */
lpm_status lpm_db_check(lpm_db *db, lpm_check_fn fn, void *ctx,
                        lpm_check_summary *summary, lpm_meta_error *err);

#endif /* LPM_DATABASE_H */
