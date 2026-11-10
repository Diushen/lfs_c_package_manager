/*
 * database.h - Read access to the installed-package database.
 *
 * Layout (relative to the target root):
 *
 *   var/lib/lpm/installed/<name>.meta   metadata of an installed package
 *   var/lib/lpm/files/<name>.list       files owned by that package
 *
 * Milestone 1 only needs to enumerate installed packages. Writing to the
 * database arrives in Milestone 3.
 */
#ifndef LPM_DATABASE_H
#define LPM_DATABASE_H

#include <stddef.h>
#include "lpm.h"

/* One installed package as shown by `lpm list`. Owns its strings. */
typedef struct {
    char *name;
    char *version;   /* "?" if the .meta file has no version line */
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
 * Fill *out with all installed packages, sorted by name.
 * *db_exists is set to 0 if the installed/ directory is missing
 * (an uninitialised database is not an error: it just means nothing
 * is installed yet).
 * On error, *out is left empty and needs no freeing.
 */
lpm_status lpm_db_list_installed(const lpm_config *cfg, lpm_db_list *out,
                                 int *db_exists);

/* Release every string and the array itself; safe on an empty list. */
void lpm_db_list_free(lpm_db_list *list);

#endif /* LPM_DATABASE_H */
