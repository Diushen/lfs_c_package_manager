/*
 * signature.c - Ed25519 through OpenSSL EVP (see signature.h).
 *
 * Every OpenSSL return value is checked, every object is freed on every
 * path, and OpenSSL's error queue is cleared after a failure so stale
 * errors never leak into a later call. Private-key bytes are never
 * printed or copied out of OpenSSL.
 */
#include "signature.h"
#include "integrity.h"
#include "util.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct lpm_privkey {
    EVP_PKEY *pkey;
};

static lpm_status crypto_fail(lpm_meta_error *err, const char *what)
{
    ERR_clear_error();
    lpm_meta_error_set(err, LPM_META_ERR_CRYPTO, 0, NULL,
                       "OpenSSL Ed25519 operation failed (%s)", what);
    return LPM_ERR_CRYPTO;
}

static lpm_status bad_key(lpm_meta_error *err, const char *why)
{
    ERR_clear_error();
    lpm_meta_error_set(err, LPM_META_ERR_KEY_MALFORMED, 0, "key", "%s", why);
    return LPM_ERR_INVALID;
}

void lpm_hex_encode(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

/* Exactly 2n lowercase hex digits -> n bytes. */
static bool hex_decode(const char *s, size_t slen, unsigned char *out, size_t n)
{
    size_t i;

    if (slen != 2 * n)
        return false;
    for (i = 0; i < 2 * n; i++) {
        char c = s[i];
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (v < 0)
            return false;
        if (i % 2 == 0)
            out[i / 2] = (unsigned char)(v << 4);
        else
            out[i / 2] |= (unsigned char)v;
    }
    return true;
}

lpm_status lpm_key_id(const unsigned char raw[LPM_ED25519_KEY_LEN],
                      char id[LPM_KEY_ID_HEX_LEN + 1], lpm_meta_error *err)
{
    return lpm_sha256_buffer(raw, LPM_ED25519_KEY_LEN, id, err);
}

lpm_status lpm_pubkey_from_raw(const unsigned char *raw, size_t len,
                               lpm_pubkey *out, lpm_meta_error *err)
{
    if (raw == NULL || len != LPM_ED25519_KEY_LEN)
        return bad_key(err, "an Ed25519 public key is exactly 32 bytes");
    memcpy(out->raw, raw, LPM_ED25519_KEY_LEN);
    return lpm_key_id(out->raw, out->id, err);
}

/* Extract and check the raw public key of an EVP_PKEY. */
static lpm_status from_evp(EVP_PKEY *pkey, lpm_pubkey *out, lpm_meta_error *err)
{
    unsigned char raw[LPM_ED25519_KEY_LEN];
    size_t len = sizeof(raw);

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519)
        return bad_key(err, "not an Ed25519 key (only Ed25519 is supported)");
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &len) != 1 || len != sizeof(raw))
        return bad_key(err, "cannot read the raw Ed25519 public key");
    return lpm_pubkey_from_raw(raw, len, out, err);
}

/* Does data[0..len) contain the string s? (memmem is not POSIX.) */
static bool contains(const char *data, size_t len, const char *s)
{
    size_t n = strlen(s), i;

    for (i = 0; i + n <= len; i++)
        if (memcmp(data + i, s, n) == 0)
            return true;
    return false;
}

static BIO *mem_bio(const char *data, size_t len)
{
    if (len == 0 || len > LPM_KEY_PEM_MAX || len > INT_MAX)
        return NULL;
    return BIO_new_mem_buf(data, (int)len);
}

/* Refuse encrypted keys instead of prompting for a passphrase. */
static int no_password(char *buf, int size, int rwflag, void *u)
{
    (void)buf; (void)size; (void)rwflag; (void)u;
    return 0;
}

lpm_status lpm_pubkey_from_pem(const char *pem, size_t len, lpm_pubkey *out,
                               lpm_meta_error *err)
{
    EVP_PKEY *pkey;
    BIO *bio;
    lpm_status rc;

    if (pem == NULL || len > LPM_KEY_PEM_MAX)
        return bad_key(err, "public key file is empty or too large");
    /* A private key must never be "imported" as a public one by mistake. */
    if (contains(pem, len, "PRIVATE KEY"))
        return bad_key(err, "this is a PRIVATE key; import the public key "
                            "(openssl pkey -in private.pem -pubout)");
    bio = mem_bio(pem, len);
    if (bio == NULL)
        return bad_key(err, "public key file is empty or too large");
    pkey = PEM_read_bio_PUBKEY(bio, NULL, no_password, NULL);
    if (pkey == NULL) {
        BIO_free(bio);
        return bad_key(err, "not a PEM public key (expected -----BEGIN PUBLIC KEY-----)");
    }
    /* Exactly one key: anything after it is suspicious. */
    {
        EVP_PKEY *extra = PEM_read_bio_PUBKEY(bio, NULL, no_password, NULL);
        if (extra != NULL) {
            EVP_PKEY_free(extra);
            EVP_PKEY_free(pkey);
            BIO_free(bio);
            return bad_key(err, "the file contains more than one key");
        }
    }
    rc = from_evp(pkey, out, err);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    ERR_clear_error();   /* the end-of-file probe above leaves an error */
    return rc;
}

lpm_status lpm_pubkey_to_pem(const lpm_pubkey *key, char **pem, size_t *len,
                             lpm_meta_error *err)
{
    EVP_PKEY *pkey;
    BIO *bio = NULL;
    BUF_MEM *mem = NULL;
    lpm_status rc = LPM_OK;

    *pem = NULL;
    *len = 0;
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->raw,
                                       LPM_ED25519_KEY_LEN);
    if (pkey == NULL)
        return crypto_fail(err, "EVP_PKEY_new_raw_public_key");
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        rc = crypto_fail(err, "PEM_write_bio_PUBKEY");
        goto out;
    }
    BIO_get_mem_ptr(bio, &mem);
    if (mem == NULL || mem->length == 0) {
        rc = crypto_fail(err, "BIO_get_mem_ptr");
        goto out;
    }
    *pem = malloc(mem->length + 1);
    if (*pem == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        rc = LPM_ERR_NOMEM;
        goto out;
    }
    memcpy(*pem, mem->data, mem->length);
    (*pem)[mem->length] = '\0';
    *len = mem->length;
out:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return rc;
}

lpm_status lpm_ed25519_verify(const lpm_pubkey *key, const void *msg, size_t len,
                              const unsigned char sig[LPM_ED25519_SIG_LEN],
                              lpm_meta_error *err)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    int r;

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->raw,
                                       LPM_ED25519_KEY_LEN);
    if (pkey == NULL)
        return crypto_fail(err, "EVP_PKEY_new_raw_public_key");
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return crypto_fail(err, "EVP_DigestVerifyInit");
    }
    /* One-shot: Ed25519 hashes the message itself (no separate digest). */
    r = EVP_DigestVerify(ctx, sig, LPM_ED25519_SIG_LEN, msg, len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    if (r == 1)
        return LPM_OK;
    /* 0 = wrong signature; < 0 = malformed input (e.g. a non-canonical
     * point). Both mean "does not verify". */
    lpm_meta_error_set(err, LPM_META_ERR_SIG_INVALID, 0, "signature",
                       "the Ed25519 signature does not match");
    return LPM_ERR_SIGNATURE;
}

lpm_status lpm_signed_message(const char *metadata, size_t len, char **msg,
                              size_t *msg_len, lpm_meta_error *err)
{
    const size_t plen = strlen(LPM_SIG_DOMAIN);

    *msg = NULL;
    *msg_len = 0;
    if (len > LPM_META_MAX_FILE_SIZE) {   /* bounded, so no overflow below */
        lpm_meta_error_set(err, LPM_META_ERR_FILE_TOO_LARGE, 0, NULL,
                           "metadata too large to sign");
        return LPM_ERR_INVALID;
    }
    *msg = malloc(plen + len + 1);
    if (*msg == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    memcpy(*msg, LPM_SIG_DOMAIN, plen);
    if (len > 0)
        memcpy(*msg + plen, metadata, len);
    *msg_len = plen + len;
    return LPM_OK;
}

/* ---- signature record ------------------------------------------------ */

static lpm_status rec_error(lpm_meta_error *err, lpm_meta_error_code code, size_t line,
                            const char *msg)
{
    lpm_meta_error_set(err, code, line, "signature", "signature.txt: %s", msg);
    return LPM_ERR_SIGNATURE;
}

lpm_status lpm_sigrec_parse(const char *data, size_t len, lpm_sigrec *out,
                            lpm_meta_error *err)
{
    static const char *const keys[5] = { "format", "algorithm", "public_key",
                                         "key_id", "signature" };
    const char *val[5];
    size_t vlen[5], pos = 0, i;
    unsigned char raw[LPM_ED25519_KEY_LEN];
    char id_given[LPM_KEY_ID_HEX_LEN + 1];
    lpm_status rc;

    memset(out, 0, sizeof(*out));
    if (len > LPM_SIG_RECORD_MAX)
        return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 0, "record is too large");
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c != '\n' && (c < 0x20 || c > 0x7e))
            return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 0,
                             "record contains a byte that is not printable ASCII");
    }
    /* Exactly five "key=value\n" lines in the fixed order: duplicates,
     * missing or extra lines are all layout errors. */
    for (i = 0; i < 5; i++) {
        const char *line = data + pos, *nl;
        size_t klen = strlen(keys[i]);

        nl = memchr(line, '\n', len - pos);
        if (pos >= len || nl == NULL)
            return rec_error(err, LPM_META_ERR_SIG_MALFORMED, i + 1,
                             "expected five lines: format, algorithm, public_key, "
                             "key_id, signature");
        if ((size_t)(nl - line) <= klen || memcmp(line, keys[i], klen) != 0 ||
            line[klen] != '=')
            return rec_error(err, LPM_META_ERR_SIG_MALFORMED, i + 1,
                             "unexpected line (wrong field, order or a duplicate)");
        val[i] = line + klen + 1;
        vlen[i] = (size_t)(nl - val[i]);
        pos = (size_t)(nl - data) + 1;
    }
    if (pos != len)
        return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 6,
                         "unexpected data after the signature line");
    if (vlen[0] != strlen(LPM_SIG_FORMAT) || memcmp(val[0], LPM_SIG_FORMAT, vlen[0]) != 0)
        return rec_error(err, LPM_META_ERR_SIG_UNSUPPORTED, 1,
                         "unsupported signature format (expected lpm-signature-v1)");
    if (vlen[1] != 7 || memcmp(val[1], "ed25519", 7) != 0)
        return rec_error(err, LPM_META_ERR_SIG_UNSUPPORTED, 2,
                         "unsupported algorithm (only ed25519)");
    if (!hex_decode(val[2], vlen[2], raw, sizeof(raw)))
        return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 3,
                         "public_key must be 64 lowercase hex digits");
    if (vlen[3] != LPM_KEY_ID_HEX_LEN)
        return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 4,
                         "key_id must be 64 lowercase hex digits");
    memcpy(id_given, val[3], LPM_KEY_ID_HEX_LEN);
    id_given[LPM_KEY_ID_HEX_LEN] = '\0';
    if (!hex_decode(val[4], vlen[4], out->sig, sizeof(out->sig)))
        return rec_error(err, LPM_META_ERR_SIG_MALFORMED, 5,
                         "signature must be 128 lowercase hex digits (64 bytes)");
    rc = lpm_pubkey_from_raw(raw, sizeof(raw), &out->signer, err);
    if (rc != LPM_OK)
        return rc;
    /* The ID must be the key's own fingerprint: no borrowed identities. */
    if (!lpm_sha256_equal(id_given, out->signer.id))
        return rec_error(err, LPM_META_ERR_KEY_MISMATCH, 4,
                         "key_id is not the SHA-256 of public_key");
    return LPM_OK;
}

lpm_status lpm_sigrec_format(const lpm_sigrec *rec, char *buf, size_t size,
                             size_t *len)
{
    char pub[2 * LPM_ED25519_KEY_LEN + 1], sig[2 * LPM_ED25519_SIG_LEN + 1];
    int n;

    lpm_hex_encode(rec->signer.raw, LPM_ED25519_KEY_LEN, pub);
    lpm_hex_encode(rec->sig, LPM_ED25519_SIG_LEN, sig);
    n = snprintf(buf, size, "format=%s\nalgorithm=ed25519\npublic_key=%s\nkey_id=%s\n"
                 "signature=%s\n", LPM_SIG_FORMAT, pub, rec->signer.id, sig);
    if (n < 0 || (size_t)n >= size)
        return LPM_ERR_INVALID;
    *len = (size_t)n;
    return LPM_OK;
}

/* ---- signing ---------------------------------------------------------- */

static lpm_status wrap_private(EVP_PKEY *pkey, lpm_privkey **out, lpm_meta_error *err)
{
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        return bad_key(err, "not an Ed25519 private key");
    }
    *out = calloc(1, sizeof(**out));
    if (*out == NULL) {
        EVP_PKEY_free(pkey);
        lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
        return LPM_ERR_NOMEM;
    }
    (*out)->pkey = pkey;
    return LPM_OK;
}

lpm_status lpm_privkey_from_pem(const char *pem, size_t len, lpm_privkey **out,
                                lpm_meta_error *err)
{
    EVP_PKEY *pkey;
    BIO *bio = mem_bio(pem, len);

    *out = NULL;
    if (bio == NULL)
        return bad_key(err, "private key file is empty or too large");
    pkey = PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL);
    BIO_free(bio);
    if (pkey == NULL)
        return bad_key(err, "not an unencrypted PEM private key");
    return wrap_private(pkey, out, err);
}

lpm_status lpm_privkey_from_seed(const unsigned char seed[32], lpm_privkey **out,
                                 lpm_meta_error *err)
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);

    *out = NULL;
    if (pkey == NULL)
        return crypto_fail(err, "EVP_PKEY_new_raw_private_key");
    return wrap_private(pkey, out, err);
}

lpm_status lpm_privkey_generate(lpm_privkey **out, lpm_meta_error *err)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;

    *out = NULL;
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return crypto_fail(err, "EVP_PKEY_keygen");
    }
    EVP_PKEY_CTX_free(pctx);
    return wrap_private(pkey, out, err);
}

void lpm_privkey_free(lpm_privkey *key)
{
    if (key == NULL)
        return;
    EVP_PKEY_free(key->pkey);   /* OpenSSL clears secret key memory */
    free(key);
}

lpm_status lpm_privkey_public(const lpm_privkey *key, lpm_pubkey *out,
                              lpm_meta_error *err)
{
    return from_evp(key->pkey, out, err);
}

lpm_status lpm_ed25519_sign(const lpm_privkey *key, const void *msg, size_t len,
                            unsigned char sig[LPM_ED25519_SIG_LEN], lpm_meta_error *err)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t siglen = LPM_ED25519_SIG_LEN;

    if (ctx == NULL || EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->pkey) != 1 ||
        EVP_DigestSign(ctx, sig, &siglen, msg, len) != 1 ||
        siglen != LPM_ED25519_SIG_LEN) {
        EVP_MD_CTX_free(ctx);
        return crypto_fail(err, "EVP_DigestSign");
    }
    EVP_MD_CTX_free(ctx);
    return LPM_OK;
}
