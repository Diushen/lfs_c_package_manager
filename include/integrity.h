/*
 * integrity.h - SHA-256 hashing and verification (Milestone 4).
 *
 * The hash is computed by OpenSSL (libcrypto, part of base LFS) through
 * its EVP interface, which is the non-deprecated API in both OpenSSL 1.1
 * and 3.x. LPM never implements SHA-256 itself.
 *
 * Files are hashed as a stream in fixed-size chunks, so memory use does
 * not depend on the file size.
 *
 * Digest spelling: LPM always produces and stores 64 lowercase hex
 * digits. Metadata must already use that spelling (Milestone 2 rule: a
 * signed file has exactly one meaning). A digest typed by a person, e.g.
 * on the command line, may use either case and is normalised first.
 *
 * Errors are distinct:
 *   LPM_ERR_NOT_FOUND  the file does not exist
 *   LPM_ERR_IO         it cannot be opened or read
 *   LPM_ERR_INVALID    not a regular file, or a malformed expected digest
 *   LPM_ERR_CRYPTO     OpenSSL failed to compute the hash
 *   LPM_ERR_INTEGRITY  the digests differ (LPM_META_ERR_HASH_MISMATCH)
 */
#ifndef LPM_INTEGRITY_H
#define LPM_INTEGRITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lpm.h"
#include "metadata.h"   /* lpm_meta_error, LPM_SHA256_HEX_LEN */

/* An incremental hash. Treat the field as private. */
typedef struct {
    void *ctx;   /* EVP_MD_CTX *, NULL when not active */
} lpm_sha256_ctx;

/* Start a hash. On failure ctx is inactive and needs no cleanup. */
lpm_status lpm_sha256_begin(lpm_sha256_ctx *ctx, lpm_meta_error *err);

/* Add len bytes. On failure the context is released. */
lpm_status lpm_sha256_update(lpm_sha256_ctx *ctx, const void *data, size_t len,
                             lpm_meta_error *err);

/* Finish into hex (64 lowercase digits + NUL). Always releases ctx. */
lpm_status lpm_sha256_finish(lpm_sha256_ctx *ctx,
                             char hex[LPM_SHA256_HEX_LEN + 1], lpm_meta_error *err);

/* Release without a result. Safe on an inactive context. */
void lpm_sha256_abort(lpm_sha256_ctx *ctx);

/* One-shot hash of a buffer. */
lpm_status lpm_sha256_buffer(const void *data, size_t len,
                             char hex[LPM_SHA256_HEX_LEN + 1], lpm_meta_error *err);

/*
 * Hash an open file descriptor from its current offset to the end. The
 * descriptor is not closed. *bytes (optional) receives the length.
 */
lpm_status lpm_sha256_fd(int fd, char hex[LPM_SHA256_HEX_LEN + 1],
                         uint64_t *bytes, lpm_meta_error *err);

/* Hash a regular file given by path (symlinks are followed, as for any
 * path a user types). */
lpm_status lpm_sha256_file(const char *path, char hex[LPM_SHA256_HEX_LEN + 1],
                           lpm_meta_error *err);

/*
 * Copy a digest into canonical form: exactly 64 hex digits, either case
 * accepted, written lowercase. Anything else is LPM_ERR_INVALID.
 */
lpm_status lpm_sha256_normalize(const char *in, char out[LPM_SHA256_HEX_LEN + 1],
                                lpm_meta_error *err);

/* Compare two canonical digests (constant time). */
bool lpm_sha256_equal(const char *a, const char *b);

/*
 * Hash path and compare with expected (any case). LPM_OK only when they
 * are equal; LPM_ERR_INTEGRITY on a mismatch, with both digests in the
 * message.
 */
lpm_status lpm_sha256_verify_file(const char *path, const char *expected,
                                  lpm_meta_error *err);

#endif /* LPM_INTEGRITY_H */
