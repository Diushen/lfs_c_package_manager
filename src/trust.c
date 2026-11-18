/*
 * trust.c - The trusted-key store and the authentication decision.
 */
#include "trust.h"
#include "integrity.h"
#include "safefs.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_NAME_MAX (LPM_KEY_ID_HEX_LEN + sizeof(LPM_TRUST_SUFFIX))

static bool valid_key_id(const char *id)
{
    return lpm_is_valid_sha256_hex(id);   /* 64 lowercase hex digits */
}

static void file_name(const char *id, char buf[FILE_NAME_MAX])
{
    snprintf(buf, FILE_NAME_MAX, "%s%s", id, LPM_TRUST_SUFFIX);
}

/* Read and check one stored key: the content must hash to the name. */
static lpm_status load_key(int dir_fd, const char *id, lpm_pubkey *out,
                           lpm_meta_error *err)
{
    char name[FILE_NAME_MAX];
    char *pem;
    size_t len;
    lpm_status rc;

    file_name(id, name);
    rc = lpm_read_bounded_fileat(dir_fd, name, LPM_KEY_PEM_MAX, &pem, &len, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_pubkey_from_pem(pem, len, out, err);
    free(pem);
    if (rc != LPM_OK) {
        lpm_meta_error_set(err, LPM_META_ERR_KEY_MALFORMED, 0, "key",
                           "trusted key file %.80s is damaged", name);
        return LPM_ERR_INVALID;
    }
    if (strcmp(out->id, id) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_KEY_MISMATCH, 0, "key",
                           "trusted key file %.80s contains a different key; "
                           "refusing to use it", name);
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

static int fsync_dir(int fd)
{
    if (lpm_fsync_retry(fd) == 0 || errno == EINVAL || errno == ENOTSUP)
        return 0;
    return -1;
}

lpm_status lpm_trust_add(int root_fd, const lpm_pubkey *key, lpm_meta_error *err)
{
    char name[FILE_NAME_MAX], tmp[FILE_NAME_MAX + 32];
    char *pem = NULL;
    size_t len;
    lpm_status rc;
    int dir = -1, fd = -1;

    rc = lpm_pubkey_to_pem(key, &pem, &len, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_safe_open_trusted_dir(root_fd, LPM_TRUST_DIR, true, 0755, &dir, err);
    if (rc != LPM_OK)
        goto out;
    file_name(key->id, name);
    snprintf(tmp, sizeof(tmp), ".lpm-tmp.%s.%ld", name, (long)getpid());

    /* Write a private temporary, flush it, then link it into place:
     * linkat() never replaces, so an existing key is never overwritten
     * and a reader never sees a half-written key. */
    (void)unlinkat(dir, tmp, 0);
    fd = openat(dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || lpm_write_all(fd, pem, len) != 0 || fchmod(fd, 0644) != 0 ||
        lpm_fsync_retry(fd) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot write the trusted key: %s", strerror(errno));
        rc = LPM_ERR_IO;
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot write the trusted key: %s", strerror(errno));
        rc = LPM_ERR_IO;
        goto out;
    }
    fd = -1;
    if (linkat(dir, tmp, dir, name, 0) != 0) {
        int e = errno;
        if (e == EEXIST) {
            lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, "key",
                               "key %s is already trusted", key->id);
            rc = LPM_ERR_EXISTS;
        } else {
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                               "cannot add the trusted key: %s", strerror(e));
            rc = LPM_ERR_IO;
        }
        goto out;
    }
    if (fsync_dir(dir) != 0) {
        (void)unlinkat(dir, name, 0);   /* not durable: do not half-trust */
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot flush the trust store: %s", strerror(errno));
        rc = LPM_ERR_IO;
    }
out:
    if (fd >= 0)
        close(fd);
    if (dir >= 0) {
        (void)unlinkat(dir, tmp, 0);
        close(dir);
    }
    free(pem);
    return rc;
}

lpm_status lpm_trust_remove(int root_fd, const char *key_id, lpm_meta_error *err)
{
    char name[FILE_NAME_MAX];
    struct stat st;
    lpm_status rc;
    int dir;

    if (key_id == NULL || !valid_key_id(key_id)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "key",
                           "a key ID is 64 lowercase hex digits (see `lpm key list`)");
        return LPM_ERR_INVALID;
    }
    rc = lpm_safe_open_trusted_dir(root_fd, LPM_TRUST_DIR, false, 0, &dir, err);
    if (rc == LPM_ERR_NOT_FOUND)
        goto absent;
    if (rc != LPM_OK)
        return rc;
    file_name(key_id, name);
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        close(dir);
        goto absent;
    }
    if (!S_ISREG(st.st_mode) || unlinkat(dir, name, 0) != 0 || fsync_dir(dir) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL,
                           "cannot remove trusted key %s: %s", key_id,
                           S_ISREG(st.st_mode) ? strerror(errno) : "not a regular file");
        close(dir);
        return S_ISREG(st.st_mode) ? LPM_ERR_IO : LPM_ERR_INVALID;
    }
    close(dir);
    return LPM_OK;
absent:
    lpm_meta_error_set(err, LPM_META_ERR_KEY_UNTRUSTED, 0, "key",
                       "key %s is not in the trust store", key_id);
    return LPM_ERR_NOT_FOUND;
}

static int cmp_keys(const void *a, const void *b)
{
    return strcmp(((const lpm_pubkey *)a)->id, ((const lpm_pubkey *)b)->id);
}

lpm_status lpm_trust_list(int root_fd, lpm_pubkey **keys, size_t *count,
                          lpm_meta_error *err)
{
    lpm_pubkey *v = NULL;
    size_t n = 0;
    struct dirent *de;
    lpm_status rc;
    DIR *d;
    int dir, dup;

    *keys = NULL;
    *count = 0;
    rc = lpm_safe_open_trusted_dir(root_fd, LPM_TRUST_DIR, false, 0, &dir, err);
    if (rc == LPM_ERR_NOT_FOUND)
        return LPM_OK;   /* no store yet: no trusted keys */
    if (rc != LPM_OK)
        return rc;
    dup = fcntl(dir, F_DUPFD_CLOEXEC, 0);
    d = dup >= 0 ? fdopendir(dup) : NULL;
    if (d == NULL) {
        if (dup >= 0)
            close(dup);
        close(dir);
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot read the trust store");
        return LPM_ERR_IO;
    }
    v = malloc(LPM_TRUST_MAX_KEYS * sizeof(*v));
    if (v == NULL) {
        rc = LPM_ERR_NOMEM;
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    }
    while (rc == LPM_OK && (de = readdir(d)) != NULL) {
        char id[LPM_KEY_ID_HEX_LEN + 1];
        size_t len = strlen(de->d_name);

        if (de->d_name[0] == '.')
            continue;   /* ".", "..", temporaries */
        if (len == LPM_KEY_ID_HEX_LEN + strlen(LPM_TRUST_SUFFIX) &&
            lpm_has_suffix(de->d_name, LPM_TRUST_SUFFIX)) {
            memcpy(id, de->d_name, LPM_KEY_ID_HEX_LEN);
            id[LPM_KEY_ID_HEX_LEN] = '\0';
        } else {
            id[0] = '\0';
        }
        if (!valid_key_id(id)) {
            lpm_meta_error_set(err, LPM_META_ERR_KEY_MALFORMED, 0, "key",
                               "unexpected file in the trust store: %.100s", de->d_name);
            rc = LPM_ERR_INVALID;
            break;
        }
        if (n >= LPM_TRUST_MAX_KEYS) {
            lpm_meta_error_set(err, LPM_META_ERR_TOO_MANY_FILES, 0, "key",
                               "more than %d trusted keys", LPM_TRUST_MAX_KEYS);
            rc = LPM_ERR_INVALID;
            break;
        }
        rc = load_key(dir, id, &v[n], err);
        if (rc != LPM_OK)
            break;
        n++;
    }
    closedir(d);
    close(dir);
    if (rc != LPM_OK) {
        free(v);
        return rc;
    }
    if (n > 1)
        qsort(v, n, sizeof(*v), cmp_keys);
    *keys = v;
    *count = n;
    return LPM_OK;
}

lpm_status lpm_trust_lookup(int root_fd, const char *key_id, lpm_pubkey *out,
                            lpm_meta_error *err)
{
    lpm_status rc;
    int dir;

    if (root_fd < 0 || !valid_key_id(key_id))
        goto untrusted;
    rc = lpm_safe_open_trusted_dir(root_fd, LPM_TRUST_DIR, false, 0, &dir, err);
    if (rc == LPM_ERR_NOT_FOUND)
        goto untrusted;
    if (rc != LPM_OK)
        return rc;
    rc = load_key(dir, key_id, out, err);
    close(dir);
    if (rc == LPM_ERR_NOT_FOUND)
        goto untrusted;
    return rc;
untrusted:
    lpm_meta_error_set(err, LPM_META_ERR_KEY_UNTRUSTED, 0, "key",
                       "signing key %.64s is not trusted (add it with `lpm key add` "
                       "only if you trust its owner)", key_id ? key_id : "?");
    return LPM_ERR_UNTRUSTED;
}

/* ---- authentication --------------------------------------------------- */

const char *lpm_auth_status_str(lpm_auth_status s)
{
    switch (s) {
    case LPM_AUTH_UNSIGNED:   return "unsigned";
    case LPM_AUTH_BAD_RECORD: return "malformed signature";
    case LPM_AUTH_INVALID:    return "invalid signature";
    case LPM_AUTH_UNTRUSTED:  return "valid signature, untrusted signer";
    case LPM_AUTH_TRUSTED:    return "trusted";
    }
    return "unknown";
}

lpm_status lpm_authenticate(int root_fd, const char *metadata, size_t metadata_len,
                            const char *sig_raw, size_t sig_len,
                            lpm_auth_result *res, lpm_meta_error *err)
{
    lpm_pubkey trusted;
    lpm_sigrec rec;
    char *msg = NULL;
    size_t msg_len;
    lpm_status rc;

    memset(res, 0, sizeof(*res));
    res->status = LPM_AUTH_UNSIGNED;
    if (sig_raw == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_SIG_MISSING, 0, "signature",
                           "the package is not signed (no signature.txt)");
        return LPM_ERR_SIGNATURE;
    }
    rc = lpm_sigrec_parse(sig_raw, sig_len, &rec, err);
    if (rc != LPM_OK) {
        res->status = LPM_AUTH_BAD_RECORD;
        return rc == LPM_ERR_INVALID ? LPM_ERR_SIGNATURE : rc;
    }
    memcpy(res->key_id, rec.signer.id, sizeof(res->key_id));

    rc = lpm_signed_message(metadata, metadata_len, &msg, &msg_len, err);
    if (rc != LPM_OK)
        return rc;

    /* 1. Mathematically valid with the embedded key? (reporting only) */
    rc = lpm_ed25519_verify(&rec.signer, msg, msg_len, rec.sig, err);
    if (rc == LPM_ERR_CRYPTO)
        goto out;
    res->signature_valid = rc == LPM_OK;
    if (!res->signature_valid) {
        res->status = LPM_AUTH_INVALID;
        lpm_meta_error_set(err, LPM_META_ERR_SIG_INVALID, 0, "signature",
                           "invalid signature: metadata.txt was not signed by key "
                           "%.16s... (or it was altered after signing)", rec.signer.id);
        rc = LPM_ERR_SIGNATURE;
        goto out;
    }

    /* 2. Is the signer trusted? Only the store decides. */
    rc = lpm_trust_lookup(root_fd, rec.signer.id, &trusted, err);
    if (rc == LPM_ERR_UNTRUSTED) {
        res->status = LPM_AUTH_UNTRUSTED;
        goto out;
    }
    if (rc != LPM_OK)
        goto out;
    res->key_trusted = true;
    if (memcmp(trusted.raw, rec.signer.raw, LPM_ED25519_KEY_LEN) != 0) {
        /* Unreachable unless SHA-256 collides: IDs are key hashes. */
        lpm_meta_error_set(err, LPM_META_ERR_KEY_MISMATCH, 0, "key",
                           "embedded key differs from the trusted key with its ID");
        res->status = LPM_AUTH_INVALID;
        rc = LPM_ERR_SIGNATURE;
        goto out;
    }
    /* 3. The authoritative check, with the trusted copy of the key. */
    rc = lpm_ed25519_verify(&trusted, msg, msg_len, rec.sig, err);
    if (rc == LPM_OK)
        res->status = LPM_AUTH_TRUSTED;
    else
        res->status = LPM_AUTH_INVALID;
out:
    free(msg);
    return rc;
}
