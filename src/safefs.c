/*
 * safefs.c - Directory-relative, symlink-refusing filesystem helpers.
 */
#include "safefs.h"
#include "filelist.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void lpm_path_log_init(lpm_path_log *log)
{
    log->paths = NULL;
    log->is_dir = NULL;
    log->count = log->capacity = 0;
}

void lpm_path_log_free(lpm_path_log *log)
{
    size_t i;

    for (i = 0; i < log->count; i++)
        free(log->paths[i]);
    free(log->paths);
    free(log->is_dir);
    lpm_path_log_init(log);
}

lpm_status lpm_path_log_add(lpm_path_log *log, const char *path, bool is_dir,
                            lpm_meta_error *err)
{
    char *copy;

    if (log->count == log->capacity) {
        size_t new_cap = log->capacity ? log->capacity * 2 : 32;
        char **p;
        bool *d;

        if (new_cap > SIZE_MAX / sizeof(*p))
            goto nomem;
        p = realloc(log->paths, new_cap * sizeof(*p));
        if (p == NULL)
            goto nomem;
        log->paths = p;
        d = realloc(log->is_dir, new_cap * sizeof(*d));
        if (d == NULL)
            goto nomem;
        log->is_dir = d;
        log->capacity = new_cap;
    }
    copy = lpm_strdup(path);
    if (copy == NULL)
        goto nomem;
    log->paths[log->count] = copy;
    log->is_dir[log->count] = is_dir;
    log->count++;
    return LPM_OK;

nomem:
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    return LPM_ERR_NOMEM;
}

lpm_status lpm_safe_split(const char *rel, char *parent, size_t size,
                          const char **base, lpm_meta_error *err)
{
    const char *slash = strrchr(rel, '/');
    size_t plen = slash ? (size_t)(slash - rel) : 0;

    if (plen >= size) {
        lpm_meta_error_set(err, LPM_META_ERR_TOO_LONG, 0, "path",
                           "path is too long");
        return LPM_ERR_INVALID;
    }
    memcpy(parent, rel, plen);
    parent[plen] = '\0';
    *base = slash ? slash + 1 : rel;
    return LPM_OK;
}

lpm_status lpm_safe_open_dir(int base_fd, const char *rel, bool create,
                             mode_t mode, lpm_path_log *created, int *out_fd,
                             lpm_meta_error *err)
{
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    char comp[LPM_FILES_MAX_COMPONENT + 1];
    size_t pos = 0, len = strlen(rel);
    lpm_status rc;
    int fd;

    *out_fd = -1;
    fd = openat(base_fd, ".", flags);   /* a private descriptor to walk with */
    if (fd < 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot open destination directory: %s", strerror(errno));
        return LPM_ERR_IO;
    }

    while (pos < len) {
        size_t clen = strcspn(rel + pos, "/");
        int next;

        if (clen == 0 || clen > LPM_FILES_MAX_COMPONENT) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_PATH, 0, "path",
                               "invalid path '%.200s'", rel);
            close(fd);
            return LPM_ERR_INVALID;
        }
        memcpy(comp, rel + pos, clen);
        comp[clen] = '\0';

        next = openat(fd, comp, flags);
        if (next < 0 && errno == ENOENT && create) {
            if (mkdirat(fd, comp, mode) == 0) {
                if (created != NULL) {
                    char sofar[LPM_FILES_MAX_PATH + 1];
                    snprintf(sofar, sizeof(sofar), "%.*s", (int)(pos + clen), rel);
                    rc = lpm_path_log_add(created, sofar, true, err);
                    if (rc != LPM_OK) {
                        (void)unlinkat(fd, comp, AT_REMOVEDIR);
                        close(fd);
                        return rc;
                    }
                }
            } else if (errno != EEXIST) {
                lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                                   "cannot create directory '%.*s': %s",
                                   (int)(pos + clen), rel, strerror(errno));
                close(fd);
                return LPM_ERR_IO;
            }
            next = openat(fd, comp, flags);
        }
        if (next < 0) {
            int e = errno;
            if (e == ENOENT) {
                lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                                   "'%.*s' does not exist", (int)(pos + clen), rel);
                rc = LPM_ERR_NOT_FOUND;
            } else if (e == ELOOP || e == ENOTDIR) {
                lpm_meta_error_set(err, LPM_META_ERR_UNSAFE_ENTRY, 0, "path",
                                   "'%.*s' is a symbolic link or not a directory; "
                                   "refusing to write through it",
                                   (int)(pos + clen), rel);
                rc = LPM_ERR_INVALID;
            } else {
                lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                                   "cannot open directory '%.*s': %s",
                                   (int)(pos + clen), rel, strerror(e));
                rc = LPM_ERR_IO;
            }
            close(fd);
            return rc;
        }
        close(fd);
        fd = next;
        pos += clen;
        if (rel[pos] == '/')
            pos++;
    }
    *out_fd = fd;
    return LPM_OK;
}

lpm_status lpm_safe_open_trusted_dir(int base_fd, const char *rel, bool create,
                                     mode_t mode, int *out_fd, lpm_meta_error *err)
{
    char comp[LPM_FILES_MAX_COMPONENT + 1];
    size_t pos = 0, len = strlen(rel);
    lpm_status rc;
    int fd;

    *out_fd = -1;
    rc = lpm_safe_open_dir(base_fd, "", false, 0, NULL, &fd, err);
    if (rc != LPM_OK)
        return rc;
    while (pos < len) {
        size_t clen = strcspn(rel + pos, "/");
        struct stat st;
        int next;

        if (clen == 0 || clen > LPM_FILES_MAX_COMPONENT) {
            close(fd);
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_PATH, 0, "path",
                               "invalid path '%.200s'", rel);
            return LPM_ERR_INVALID;
        }
        memcpy(comp, rel + pos, clen);
        comp[clen] = '\0';
        rc = lpm_safe_open_dir(fd, comp, create, mode, NULL, &next, err);
        close(fd);
        if (rc != LPM_OK)
            return rc;
        fd = next;
        if (fstat(fd, &st) != 0 ||
            (st.st_uid != geteuid() && st.st_uid != 0) ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            lpm_meta_error_set(err, LPM_META_ERR_UNTRUSTED, 0, NULL,
                               "'%.*s' is not owned by you or root, or is writable "
                               "by group or others; refusing to trust it",
                               (int)(pos + clen), rel);
            close(fd);
            return LPM_ERR_INVALID;
        }
        pos += clen;
        if (rel[pos] == '/')
            pos++;
    }
    *out_fd = fd;
    return LPM_OK;
}

void lpm_safe_rollback(int base_fd, lpm_path_log *log)
{
    size_t i = log->count;

    while (i-- > 0) {
        char parent[LPM_FILES_MAX_PATH + 1];
        const char *base;
        int dfd;

        if (lpm_safe_split(log->paths[i], parent, sizeof(parent), &base, NULL) != LPM_OK)
            continue;
        if (lpm_safe_open_dir(base_fd, parent, false, 0, NULL, &dfd, NULL) != LPM_OK)
            continue;
        (void)unlinkat(dfd, base, log->is_dir[i] ? AT_REMOVEDIR : 0);
        close(dfd);
    }
    lpm_path_log_free(log);
}

int lpm_write_all(int fd, const void *data, size_t len)
{
    const char *p = data;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int lpm_fsync_retry(int fd)
{
    while (fsync(fd) != 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

bool lpm_is_safe_symlink_target(const char *t)
{
    size_t len, i, start = 0;

    if (t == NULL)
        return false;
    len = strnlen(t, LPM_FILES_MAX_PATH + 1);
    if (len == 0 || len > LPM_FILES_MAX_PATH || t[0] == '/')
        return false;
    for (i = 0; i <= len; i++) {
        unsigned char c = (unsigned char)t[i];
        if (c != '\0' && c != '/') {
            if (c < 0x20 || c > 0x7e)
                return false;
            continue;
        }
        if (i == start)                                    /* empty: "a//b", "a/" */
            return false;
        if (i - start == 2 && t[start] == '.' && t[start + 1] == '.')
            return false;                                  /* ".." */
        start = i + 1;
    }
    return true;
}
