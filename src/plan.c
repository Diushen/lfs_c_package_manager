/*
 * plan.c - Collect candidates and installed packages, then resolve.
 */
#include "plan.h"
#include "database.h"
#include "pkg.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void lpm_resolution_free(lpm_resolution *r)
{
    if (r == NULL)
        return;
    lpm_plan_free(&r->plan);       /* the plan borrows from the solver */
    lpm_solver_free(r->solver);
    r->solver = NULL;
}

/* Prefix an error with the file it concerns. */
static void blame(lpm_meta_error *err, const char *what, const char *path)
{
    if (err != NULL) {
        lpm_meta_error orig = *err;
        lpm_meta_error_set(err, orig.code, orig.line, orig.field, "%s %.120s: %.200s",
                           what, path, orig.message);
    }
}

/* Read one package's metadata and add it as a candidate. */
static lpm_status add_file(lpm_solver *s, int fd, const char *path, size_t *index,
                           const char *what, lpm_meta_error *err)
{
    lpm_package pkg;
    struct stat st;
    lpm_status rc;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL, "not a regular file");
        blame(err, what, path);
        return LPM_ERR_INVALID;
    }
    rc = lpm_pkg_read_metadata(fd, &pkg, err);
    if (rc != LPM_OK) {
        blame(err, what, path);
        return rc;
    }
    return lpm_solver_add_candidate(s, &pkg, path, index, err);
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/*
 * Every *.lpm in dir, in sorted order (determinism). The requested file
 * itself is skipped if it lives there (same device and inode).
 */
static lpm_status add_directory(lpm_solver *s, const char *dir, const struct stat *root_st,
                                lpm_meta_error *err)
{
    char **names = NULL;
    size_t n = 0, cap = 0, i;
    struct dirent *de;
    lpm_status rc = LPM_OK;
    DIR *d;
    int dfd;

    d = opendir(dir);
    if (d == NULL) {
        int e = errno;
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open package "
                           "directory '%.200s': %s", dir, strerror(e));
        return e == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
    }
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !lpm_has_suffix(de->d_name, ".lpm"))
            continue;
        if (n >= LPM_PKGDIR_MAX_FILES) {
            lpm_meta_error_set(err, LPM_META_ERR_DEP_LIMIT, 0, NULL, "package "
                               "directory has more than %d .lpm files",
                               LPM_PKGDIR_MAX_FILES);
            rc = LPM_ERR_DEPENDENCY;
            goto out;
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 32;
            char **g = realloc(names, nc * sizeof(*g));
            if (g == NULL)
                goto nomem;
            names = g;
            cap = nc;
        }
        names[n] = lpm_strdup(de->d_name);
        if (names[n] == NULL)
            goto nomem;
        n++;
    }
    if (n > 1)
        qsort(names, n, sizeof(*names), cmp_names);

    dfd = dirfd(d);
    for (i = 0; i < n && rc == LPM_OK; i++) {
        char *path = lpm_path_join(dir, names[i]);
        struct stat st;
        int fd;

        if (path == NULL)
            goto nomem;
        fd = openat(dfd, names[i], O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open: %s",
                               strerror(errno));
            blame(err, "candidate", path);
            rc = LPM_ERR_IO;
        } else {
            if (root_st != NULL && fstat(fd, &st) == 0 &&
                st.st_dev == root_st->st_dev && st.st_ino == root_st->st_ino) {
                /* the requested package itself */
            } else {
                rc = add_file(s, fd, path, NULL, "candidate", err);
            }
            close(fd);
        }
        free(path);
    }
    goto out;

nomem:
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    rc = LPM_ERR_NOMEM;
out:
    for (i = 0; i < n; i++)
        free(names[i]);
    free(names);
    closedir(d);
    return rc;
}

static lpm_status add_installed(lpm_solver *s, const lpm_config *cfg, bool db_locked,
                                lpm_meta_error *err)
{
    lpm_db_list list;
    lpm_db db;
    int exists;
    size_t i;
    lpm_status rc;
    bool opened = false;

    if (!db_locked) {
        /* Shared lock: no installer changes the set while we read it. */
        rc = lpm_db_open(cfg, LPM_DB_READ, 5000, &db, err);
        if (rc == LPM_ERR_NOT_FOUND)
            return LPM_OK;   /* no database: nothing installed */
        if (rc != LPM_OK)
            return rc;
        opened = true;
    }
    rc = lpm_db_list_installed(cfg, &list, &exists);
    if (rc != LPM_OK)
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot read the installed-package database");
    for (i = 0; rc == LPM_OK && i < list.count; i++)
        rc = lpm_solver_add_installed(s, list.items[i].name, list.items[i].version, err);
    (void)exists;
    lpm_db_list_free(&list);   /* safe on the empty list left by an error */
    if (opened)
        lpm_db_close(&db);
    return rc;
}

lpm_status lpm_resolve_request(const lpm_config *cfg, const char *pkg_path,
                               const char *package_dir, bool db_locked,
                               lpm_resolution *out, lpm_meta_error *err)
{
    struct stat root_st;
    size_t root = 0;
    lpm_status rc;
    int fd;

    memset(out, 0, sizeof(*out));
    rc = lpm_solver_new(&out->solver, err);
    if (rc != LPM_OK)
        return rc;

    fd = open(pkg_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        int e = errno;
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open package "
                           "'%.200s': %s", pkg_path, strerror(e));
        rc = e == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
        goto fail;
    }
    rc = fstat(fd, &root_st) == 0 ? LPM_OK : LPM_ERR_IO;
    if (rc == LPM_OK)
        rc = add_file(out->solver, fd, pkg_path, &root, "package", err);
    close(fd);
    if (rc == LPM_OK && package_dir != NULL)
        rc = add_directory(out->solver, package_dir, &root_st, err);
    if (rc == LPM_OK)
        rc = add_installed(out->solver, cfg, db_locked, err);
    if (rc == LPM_OK)
        rc = lpm_solver_resolve(out->solver, root, &out->plan, err);
    if (rc == LPM_OK)
        return LPM_OK;

fail:
    lpm_resolution_free(out);
    return rc;
}
