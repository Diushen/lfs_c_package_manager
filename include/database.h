/*
 * database.h - Read access to the installed-package database.
 *
 * Layout (relative to the target root):
 *
 *   var/lib/lpm/installed/<name>.meta   metadata of an installed package
 *   var/lib/lpm/files/<name>.list       files owned by that package
 *
 * Records are parsed with the metadata module (LPM_META_INSTALLED
 * profile). Writing to the database arrives in Milestone 3.
 */
#ifndef LPM_DATABASE_H
#define LPM_DATABASE_H

#include <stddef.h>
#include "lpm.h"
#include "metadata.h"

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

#endif /* LPM_DATABASE_H */
