/*
 * database.c - Enumerate the installed-package database.
 *
 * The database is plain files so it can be inspected with ls/cat during
 * a demonstration, and needs no database library or server.
 */
#include "database.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char *lpm_db_installed_dir(const lpm_config *cfg)
{
    char *db_dir = lpm_path_join(cfg->root, LPM_DB_SUBDIR);
    char *installed;

    if (db_dir == NULL)
        return NULL;
    installed = lpm_path_join(db_dir, LPM_DB_INSTALLED_DIR);
    free(db_dir);
    return installed;
}

/*
 * TEMPORARY (Milestone 1): pull the value of "version=" out of a .meta
 * file. Milestone 2 replaces this with the real metadata parser.
 * Returns a malloc'd string, or NULL if absent / on error.
 */
static char *read_version_field(const char *meta_path)
{
    FILE *fp;
    char *line = NULL;
    size_t cap = 0;
    char *result = NULL;

    fp = fopen(meta_path, "r");
    if (fp == NULL)
        return NULL;

    while (getline(&line, &cap, fp) != -1) {
        char *trimmed = lpm_trim(line);
        if (strncmp(trimmed, "version=", 8) == 0) {
            result = lpm_strdup(lpm_trim(trimmed + 8));
            break;
        }
    }

    free(line);
    fclose(fp);
    return result;
}

/* Append an entry, doubling capacity as needed. Takes ownership of
 * name/version only on success. */
static lpm_status list_append(lpm_db_list *list, char *name, char *version)
{
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 8;
        lpm_db_entry *grown;

        if (new_cap > SIZE_MAX / sizeof(*grown))
            return LPM_ERR_NOMEM;
        grown = realloc(list->items, new_cap * sizeof(*grown));
        if (grown == NULL)
            return LPM_ERR_NOMEM;
        list->items = grown;
        list->capacity = new_cap;
    }
    list->items[list->count].name = name;
    list->items[list->count].version = version;
    list->count++;
    return LPM_OK;
}

static int compare_entries(const void *a, const void *b)
{
    const lpm_db_entry *ea = a;
    const lpm_db_entry *eb = b;
    return strcmp(ea->name, eb->name);
}

/*
 * Handle one directory entry: accept "<valid-name>.meta" regular files,
 * ignore anything else. Returns LPM_OK for both accepted and skipped
 * entries; only allocation failure is an error.
 */
static lpm_status consider_entry(const char *installed_dir, const char *fname,
                                 lpm_db_list *out)
{
    size_t name_len;
    char *name = NULL, *path = NULL, *version = NULL;
    struct stat st;
    lpm_status rc = LPM_OK;

    if (fname[0] == '.' || !lpm_has_suffix(fname, LPM_META_SUFFIX))
        return LPM_OK;   /* hidden files, temp files, *.list, ... */

    name_len = strlen(fname) - strlen(LPM_META_SUFFIX);
    name = malloc(name_len + 1);
    if (name == NULL)
        return LPM_ERR_NOMEM;
    memcpy(name, fname, name_len);
    name[name_len] = '\0';

    if (!lpm_is_valid_package_name(name)) {
        lpm_warn("ignoring database entry with invalid package name: %s", fname);
        goto out;
    }

    path = lpm_path_join(installed_dir, fname);
    if (path == NULL) {
        rc = LPM_ERR_NOMEM;
        goto out;
    }

    /* lstat: a symlink in the database is suspicious, not followed. */
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        lpm_warn("ignoring database entry that is not a regular file: %s", path);
        goto out;
    }

    version = read_version_field(path);
    if (version == NULL) {
        version = lpm_strdup("?");
        if (version == NULL) {
            rc = LPM_ERR_NOMEM;
            goto out;
        }
    }

    rc = list_append(out, name, version);
    if (rc == LPM_OK) {
        name = NULL;      /* ownership moved into the list */
        version = NULL;
    }

out:
    free(name);
    free(version);
    free(path);
    return rc;
}

lpm_status lpm_db_list_installed(const lpm_config *cfg, lpm_db_list *out,
                                 int *db_exists)
{
    char *installed_dir;
    DIR *dir;
    struct dirent *de;
    lpm_status rc = LPM_OK;

    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    *db_exists = 0;

    installed_dir = lpm_db_installed_dir(cfg);
    if (installed_dir == NULL)
        return LPM_ERR_NOMEM;

    dir = opendir(installed_dir);
    if (dir == NULL) {
        if (errno == ENOENT) {
            free(installed_dir);   /* no database yet: empty, not an error */
            return LPM_OK;
        }
        lpm_error("cannot open package database '%s': %s",
                  installed_dir, strerror(errno));
        free(installed_dir);
        return LPM_ERR_IO;
    }
    *db_exists = 1;

    errno = 0;
    while ((de = readdir(dir)) != NULL) {
        rc = consider_entry(installed_dir, de->d_name, out);
        if (rc != LPM_OK)
            break;
        errno = 0;
    }
    if (rc == LPM_OK && errno != 0) {
        lpm_error("error reading package database '%s': %s",
                  installed_dir, strerror(errno));
        rc = LPM_ERR_IO;
    }

    closedir(dir);
    free(installed_dir);

    if (rc != LPM_OK) {
        lpm_db_list_free(out);
        return rc;
    }

    /* readdir order is arbitrary; sort for stable, readable output. */
    if (out->count > 1)
        qsort(out->items, out->count, sizeof(out->items[0]), compare_entries);
    return LPM_OK;
}

void lpm_db_list_free(lpm_db_list *list)
{
    size_t i;

    if (list == NULL)
        return;
    for (i = 0; i < list->count; i++) {
        free(list->items[i].name);
        free(list->items[i].version);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}
