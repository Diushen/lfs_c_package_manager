/*
 * integrity.c - SHA-256 through OpenSSL's EVP interface.
 *
 * This is the only module that includes OpenSSL headers.
 */
#include "integrity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

/* Read size for streaming; files of any size use only this much. */
#define HASH_CHUNK (64 * 1024)

static lpm_status crypto_fail(lpm_meta_error *err, const char *what)
{
    lpm_meta_error_set(err, LPM_META_ERR_CRYPTO, 0, NULL,
                       "SHA-256 computation failed in OpenSSL (%s)", what);
    return LPM_ERR_CRYPTO;
}

void lpm_sha256_abort(lpm_sha256_ctx *ctx)
{
    if (ctx != NULL && ctx->ctx != NULL) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

lpm_status lpm_sha256_begin(lpm_sha256_ctx *ctx, lpm_meta_error *err)
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();

    ctx->ctx = NULL;
    if (c == NULL)
        return crypto_fail(err, "EVP_MD_CTX_new");
    if (EVP_DigestInit_ex(c, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(c);
        return crypto_fail(err, "EVP_DigestInit_ex");
    }
    ctx->ctx = c;
    return LPM_OK;
}

lpm_status lpm_sha256_update(lpm_sha256_ctx *ctx, const void *data, size_t len,
                             lpm_meta_error *err)
{
    if (ctx->ctx == NULL)
        return crypto_fail(err, "hash not started");
    if (len > 0 && EVP_DigestUpdate(ctx->ctx, data, len) != 1) {
        lpm_sha256_abort(ctx);
        return crypto_fail(err, "EVP_DigestUpdate");
    }
    return LPM_OK;
}

lpm_status lpm_sha256_finish(lpm_sha256_ctx *ctx,
                             char hex[LPM_SHA256_HEX_LEN + 1], lpm_meta_error *err)
{
    static const char digits[] = "0123456789abcdef";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0, i;
    int ok;

    hex[0] = '\0';
    if (ctx->ctx == NULL)
        return crypto_fail(err, "hash not started");
    ok = EVP_DigestFinal_ex(ctx->ctx, md, &n);
    lpm_sha256_abort(ctx);
    if (ok != 1 || n != LPM_SHA256_HEX_LEN / 2)
        return crypto_fail(err, "EVP_DigestFinal_ex");
    for (i = 0; i < n; i++) {
        hex[2 * i] = digits[md[i] >> 4];
        hex[2 * i + 1] = digits[md[i] & 0x0f];
    }
    hex[2 * n] = '\0';
    return LPM_OK;
}

lpm_status lpm_sha256_buffer(const void *data, size_t len,
                             char hex[LPM_SHA256_HEX_LEN + 1], lpm_meta_error *err)
{
    lpm_sha256_ctx ctx;
    lpm_status rc = lpm_sha256_begin(&ctx, err);

    if (rc == LPM_OK)
        rc = lpm_sha256_update(&ctx, data, len, err);
    if (rc == LPM_OK)
        rc = lpm_sha256_finish(&ctx, hex, err);
    return rc;
}

lpm_status lpm_sha256_fd(int fd, char hex[LPM_SHA256_HEX_LEN + 1],
                         uint64_t *bytes, lpm_meta_error *err)
{
    unsigned char buf[HASH_CHUNK];
    lpm_sha256_ctx ctx;
    uint64_t total = 0;
    lpm_status rc;

    hex[0] = '\0';
    rc = lpm_sha256_begin(&ctx, err);
    if (rc != LPM_OK)
        return rc;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "read failed: %s",
                               strerror(errno));
            lpm_sha256_abort(&ctx);
            return LPM_ERR_IO;
        }
        if (n == 0)
            break;
        rc = lpm_sha256_update(&ctx, buf, (size_t)n, err);
        if (rc != LPM_OK)
            return rc;
        total += (uint64_t)n;
    }
    if (bytes != NULL)
        *bytes = total;
    return lpm_sha256_finish(&ctx, hex, err);
}

lpm_status lpm_sha256_file(const char *path, char hex[LPM_SHA256_HEX_LEN + 1],
                           lpm_meta_error *err)
{
    struct stat st;
    lpm_status rc;
    int fd;

    hex[0] = '\0';
    /* O_NONBLOCK: opening a FIFO must not hang; fstat rejects it next. */
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        int e = errno;
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot open '%.200s': %s",
                           path, strerror(e));
        return e == ENOENT ? LPM_ERR_NOT_FOUND : LPM_ERR_IO;
    }
    if (fstat(fd, &st) != 0) {
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot stat '%.200s': %s",
                           path, strerror(errno));
        close(fd);
        return LPM_ERR_IO;
    }
    if (!S_ISREG(st.st_mode)) {
        lpm_meta_error_set(err, LPM_META_ERR_NOT_REGULAR, 0, NULL,
                           "'%.200s' is not a regular file", path);
        close(fd);
        return LPM_ERR_INVALID;
    }
    rc = lpm_sha256_fd(fd, hex, NULL, err);
    if (rc == LPM_ERR_IO) {
        char why[sizeof(err->message)];
        snprintf(why, sizeof(why), "%s", err ? err->message : "");
        lpm_meta_error_set(err, LPM_META_ERR_IO, 0, NULL, "cannot read '%.200s': %s",
                           path, why);
    }
    close(fd);
    return rc;
}

lpm_status lpm_sha256_normalize(const char *in, char out[LPM_SHA256_HEX_LEN + 1],
                                lpm_meta_error *err)
{
    size_t i;

    out[0] = '\0';
    if (in == NULL || strnlen(in, LPM_SHA256_HEX_LEN + 1) != LPM_SHA256_HEX_LEN) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "sha256",
                           "a SHA-256 digest must be exactly %d hexadecimal digits",
                           LPM_SHA256_HEX_LEN);
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < LPM_SHA256_HEX_LEN; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'F')
            c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "sha256",
                               "a SHA-256 digest may contain only hexadecimal "
                               "digits (bad character at position %zu)", i + 1);
            out[0] = '\0';
            return LPM_ERR_INVALID;
        }
        out[i] = c;
    }
    out[LPM_SHA256_HEX_LEN] = '\0';
    return LPM_OK;
}

bool lpm_sha256_equal(const char *a, const char *b)
{
    /* Digests are not secret, but a constant-time compare costs nothing
     * and is the right habit for anything security-related. */
    /* Check lengths first: never read past a shorter string. */
    return a != NULL && b != NULL &&
           strnlen(a, LPM_SHA256_HEX_LEN + 1) == LPM_SHA256_HEX_LEN &&
           strnlen(b, LPM_SHA256_HEX_LEN + 1) == LPM_SHA256_HEX_LEN &&
           CRYPTO_memcmp(a, b, LPM_SHA256_HEX_LEN) == 0;
}

lpm_status lpm_sha256_verify_file(const char *path, const char *expected,
                                  lpm_meta_error *err)
{
    char want[LPM_SHA256_HEX_LEN + 1], got[LPM_SHA256_HEX_LEN + 1];
    lpm_status rc;

    /* Validate the expectation first: a typo is not a "mismatch". */
    rc = lpm_sha256_normalize(expected, want, err);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_sha256_file(path, got, err);
    if (rc != LPM_OK)
        return rc;
    if (!lpm_sha256_equal(want, got)) {
        lpm_meta_error_set(err, LPM_META_ERR_HASH_MISMATCH, 0, "sha256",
                           "SHA-256 mismatch for '%.60s': expected %s, got %s",
                           path, want, got);
        return LPM_ERR_INTEGRITY;
    }
    return LPM_OK;
}
