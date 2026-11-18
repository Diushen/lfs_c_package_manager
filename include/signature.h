/*
 * signature.h - Ed25519 keys, signatures and the signature record
 * (Milestone 6). Pure cryptography: no files, no trust decisions.
 *
 * OpenSSL EVP does the mathematics (EVP_PKEY_ED25519, one-shot
 * EVP_DigestSign / EVP_DigestVerify with no separate digest, as Ed25519
 * requires). Works with OpenSSL 1.1.1 and 3.x. LPM implements no
 * cryptographic primitive itself.
 *
 * WHAT IS SIGNED (exactly):
 *
 *     "LPM-SIGNED-METADATA-V1\n"  ||  the raw bytes of metadata.txt
 *
 * The fixed prefix (domain separation) means a signature made for LPM
 * metadata can never be mistaken for a signature over anything else,
 * and a future format can use a different prefix. metadata.txt is signed
 * exactly as stored: never re-serialised. It contains the package name,
 * version, dependencies and manifest_sha256, so the signature covers the
 * package's identity and, through the manifest's hashes, every payload
 * byte. The signature does not cover itself (it lives in its own file).
 *
 * KEY ID: lowercase hex SHA-256 of the 32 raw public-key bytes. A key ID
 * is a consequence of the key, so nobody can choose one that names
 * somebody else's key.
 *
 * SIGNATURE RECORD (signature.txt in a package): exactly five lines, in
 * this order, LF-terminated, lowercase hex, nothing else:
 *
 *     format=lpm-signature-v1
 *     algorithm=ed25519
 *     public_key=<64 hex digits: the signer's raw public key>
 *     key_id=<64 hex digits: SHA-256 of that key>
 *     signature=<128 hex digits: the 64-byte Ed25519 signature>
 *
 * The embedded public key is NEVER trusted by itself: it only lets
 * `lpm verify` say whether the signature is mathematically valid. Trust
 * comes from the trust store (trust.h), and installation verifies the
 * signature with the trusted copy of the key.
 */
#ifndef LPM_SIGNATURE_H
#define LPM_SIGNATURE_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "metadata.h"

#define LPM_ED25519_KEY_LEN   32
#define LPM_ED25519_SIG_LEN   64
#define LPM_KEY_ID_HEX_LEN    64
#define LPM_SIG_DOMAIN        "LPM-SIGNED-METADATA-V1\n"
#define LPM_SIG_FORMAT        "lpm-signature-v1"
#define LPM_SIG_RECORD_MAX    1024    /* bytes of signature.txt */
#define LPM_KEY_PEM_MAX       8192    /* bytes of a PEM key file */

/* An Ed25519 public key and its ID. */
typedef struct {
    unsigned char raw[LPM_ED25519_KEY_LEN];
    char id[LPM_KEY_ID_HEX_LEN + 1];
} lpm_pubkey;

/* A parsed signature record. */
typedef struct {
    lpm_pubkey signer;                         /* as embedded: NOT trusted */
    unsigned char sig[LPM_ED25519_SIG_LEN];
} lpm_sigrec;

/* Key ID of 32 raw key bytes. */
lpm_status lpm_key_id(const unsigned char raw[LPM_ED25519_KEY_LEN],
                      char id[LPM_KEY_ID_HEX_LEN + 1], lpm_meta_error *err);

/* Public key from raw bytes (computes the ID). */
lpm_status lpm_pubkey_from_raw(const unsigned char *raw, size_t len,
                               lpm_pubkey *out, lpm_meta_error *err);

/*
 * Public key from PEM ("-----BEGIN PUBLIC KEY-----", as written by
 * `openssl pkey -pubout`). Anything that is not exactly one Ed25519
 * public key (RSA, EC, a private key, garbage, > LPM_KEY_PEM_MAX) is
 * LPM_ERR_INVALID with LPM_META_ERR_KEY_MALFORMED.
 */
lpm_status lpm_pubkey_from_pem(const char *pem, size_t len, lpm_pubkey *out,
                               lpm_meta_error *err);

/* Canonical PEM encoding of a public key. Caller frees *pem. */
lpm_status lpm_pubkey_to_pem(const lpm_pubkey *key, char **pem, size_t *len,
                             lpm_meta_error *err);

/*
 * Verify sig over msg with key. LPM_OK only for a valid signature;
 * LPM_ERR_SIGNATURE (LPM_META_ERR_SIG_INVALID) if it does not verify;
 * LPM_ERR_CRYPTO if OpenSSL itself failed.
 */
lpm_status lpm_ed25519_verify(const lpm_pubkey *key, const void *msg, size_t len,
                              const unsigned char sig[LPM_ED25519_SIG_LEN],
                              lpm_meta_error *err);

/* LPM_SIG_DOMAIN || metadata, in a new buffer (caller frees). */
lpm_status lpm_signed_message(const char *metadata, size_t len, char **msg,
                              size_t *msg_len, lpm_meta_error *err);

/*
 * Parse signature.txt strictly (format above). LPM_ERR_SIGNATURE with
 *   LPM_META_ERR_SIG_UNSUPPORTED  other format or algorithm
 *   LPM_META_ERR_SIG_MALFORMED    anything else wrong with the layout
 *   LPM_META_ERR_KEY_MISMATCH     key_id is not SHA-256(public_key)
 */
lpm_status lpm_sigrec_parse(const char *data, size_t len, lpm_sigrec *out,
                            lpm_meta_error *err);

/* Write the canonical record; buf needs at least LPM_SIG_RECORD_MAX. */
lpm_status lpm_sigrec_format(const lpm_sigrec *rec, char *buf, size_t size,
                             size_t *len);

/* ---- signing (lpm-sign and the tests; never used by the installer) --- */

typedef struct lpm_privkey lpm_privkey;   /* opaque; holds secret material */

/* Unencrypted PEM private key ("openssl genpkey -algorithm ED25519"). */
lpm_status lpm_privkey_from_pem(const char *pem, size_t len, lpm_privkey **out,
                                lpm_meta_error *err);
/* From a 32-byte seed (RFC 8032 test vectors). */
lpm_status lpm_privkey_from_seed(const unsigned char seed[32], lpm_privkey **out,
                                 lpm_meta_error *err);
/* A fresh random key (tests only). */
lpm_status lpm_privkey_generate(lpm_privkey **out, lpm_meta_error *err);
void lpm_privkey_free(lpm_privkey *key);   /* safe on NULL */

lpm_status lpm_privkey_public(const lpm_privkey *key, lpm_pubkey *out,
                              lpm_meta_error *err);
lpm_status lpm_ed25519_sign(const lpm_privkey *key, const void *msg, size_t len,
                            unsigned char sig[LPM_ED25519_SIG_LEN], lpm_meta_error *err);

/* Lowercase hex of n bytes into out (2n + 1 bytes). */
void lpm_hex_encode(const unsigned char *in, size_t n, char *out);

#endif /* LPM_SIGNATURE_H */
