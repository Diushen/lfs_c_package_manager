/*
 * test_signature.c - Ed25519 primitives and the signature record
 * (Milestone 6). Known-answer tests use the RFC 8032 section 7.1 test
 * vectors, so correctness is checked against the standard rather than
 * against the code itself.
 *
 * Linked with -Wl,--wrap=malloc,calloc,realloc (LPM's own allocations;
 * OpenSSL's are not affected).
 */
#include "signature.h"
#include "integrity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "test_framework.h"

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);
static long alloc_seen, alloc_fail_at = -1;
static int inject(void) { return alloc_fail_at >= 0 && alloc_seen++ == alloc_fail_at; }
void *__wrap_malloc(size_t s) { return inject() ? NULL : __real_malloc(s); }
void *__wrap_calloc(size_t n, size_t s) { return inject() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t s) { return inject() ? NULL : __real_realloc(p, s); }

static lpm_meta_error E;

static void unhex(const char *h, unsigned char *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

/* RFC 8032, 7.1: TEST 1 (empty message), TEST 2 (1 byte), TEST 3 (2 bytes). */
static const struct {
    const char *secret, *public_key, *message, *signature;
} V[] = {
    { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
};

static void test_rfc8032_vectors(void)
{
    size_t i;

    for (i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        unsigned char seed[32], pub[32], msg[8], want[64], got[64];
        size_t mlen = strlen(V[i].message) / 2;
        lpm_privkey *k;
        lpm_pubkey pk, derived;

        unhex(V[i].secret, seed, 32);
        unhex(V[i].public_key, pub, 32);
        unhex(V[i].message, msg, mlen);
        unhex(V[i].signature, want, 64);
        CHECK(lpm_privkey_from_seed(seed, &k, &E) == LPM_OK);
        CHECK(lpm_privkey_public(k, &derived, &E) == LPM_OK);
        CHECK(memcmp(derived.raw, pub, 32) == 0);           /* RFC public key */
        CHECK(lpm_ed25519_sign(k, msg, mlen, got, &E) == LPM_OK);
        CHECK(memcmp(got, want, 64) == 0);                  /* RFC signature  */
        CHECK(lpm_pubkey_from_raw(pub, 32, &pk, &E) == LPM_OK);
        CHECK(lpm_ed25519_verify(&pk, msg, mlen, want, &E) == LPM_OK);
        lpm_privkey_free(k);
    }
}

static void test_wrong_key_message_signature(void)
{
    unsigned char sig[64], bad[64];
    lpm_privkey *a, *b;
    lpm_pubkey pa, pb;
    static const char msg[] = "name=hello\nversion=1.0\n";

    CHECK(lpm_privkey_generate(&a, &E) == LPM_OK);
    CHECK(lpm_privkey_generate(&b, &E) == LPM_OK);
    lpm_privkey_public(a, &pa, &E);
    lpm_privkey_public(b, &pb, &E);
    CHECK(lpm_ed25519_sign(a, msg, strlen(msg), sig, &E) == LPM_OK);
    CHECK(lpm_ed25519_verify(&pa, msg, strlen(msg), sig, &E) == LPM_OK);
    /* correct signature, wrong public key */
    CHECK(lpm_ed25519_verify(&pb, msg, strlen(msg), sig, &E) == LPM_ERR_SIGNATURE);
    CHECK(E.code == LPM_META_ERR_SIG_INVALID);
    /* one changed byte of the message */
    {
        char m2[sizeof(msg)];
        memcpy(m2, msg, sizeof(msg));
        m2[6] = 'j';
        CHECK(lpm_ed25519_verify(&pa, m2, strlen(m2), sig, &E) == LPM_ERR_SIGNATURE);
    }
    /* every single flipped bit of the signature is detected */
    {
        int bit, missed = 0;
        for (bit = 0; bit < 512; bit++) {
            memcpy(bad, sig, 64);
            bad[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            if (lpm_ed25519_verify(&pa, msg, strlen(msg), bad, &E) == LPM_OK)
                missed++;
        }
        CHECK(missed == 0);
    }
    /* an all-zero signature */
    memset(bad, 0, 64);
    CHECK(lpm_ed25519_verify(&pa, msg, strlen(msg), bad, &E) == LPM_ERR_SIGNATURE);
    lpm_privkey_free(a);
    lpm_privkey_free(b);
}

static void test_empty_message(void)
{
    unsigned char sig[64];
    lpm_privkey *k;
    lpm_pubkey p;

    CHECK(lpm_privkey_generate(&k, &E) == LPM_OK);
    lpm_privkey_public(k, &p, &E);
    CHECK(lpm_ed25519_sign(k, "", 0, sig, &E) == LPM_OK);
    CHECK(lpm_ed25519_verify(&p, "", 0, sig, &E) == LPM_OK);
    CHECK(lpm_ed25519_verify(&p, "x", 1, sig, &E) == LPM_ERR_SIGNATURE);
    lpm_privkey_free(k);
}

static void test_domain_separation(void)
{
    static const char meta[] = "name=hello\nversion=1.0\n";
    unsigned char sig[64];
    lpm_privkey *k;
    lpm_pubkey p;
    char *msg;
    size_t len;

    /* A signature over the bare metadata (no "LPM-SIGNED-METADATA-V1\n"
     * prefix) is not a valid LPM signature. */
    CHECK(lpm_privkey_generate(&k, &E) == LPM_OK);
    lpm_privkey_public(k, &p, &E);
    CHECK(lpm_ed25519_sign(k, meta, strlen(meta), sig, &E) == LPM_OK);
    CHECK(lpm_signed_message(meta, strlen(meta), &msg, &len, &E) == LPM_OK);
    CHECK(len == strlen(LPM_SIG_DOMAIN) + strlen(meta));
    CHECK(memcmp(msg, "LPM-SIGNED-METADATA-V1\n", 23) == 0);
    CHECK(memcmp(msg + 23, meta, strlen(meta)) == 0);
    CHECK(lpm_ed25519_verify(&p, msg, len, sig, &E) == LPM_ERR_SIGNATURE);
    free(msg);
    lpm_privkey_free(k);
}

static void test_key_lengths_and_ids(void)
{
    unsigned char raw[40] = { 0 };
    char id[65], expect[65];
    lpm_pubkey p;

    CHECK(lpm_pubkey_from_raw(raw, 31, &p, &E) == LPM_ERR_INVALID);
    CHECK(E.code == LPM_META_ERR_KEY_MALFORMED);
    CHECK(lpm_pubkey_from_raw(raw, 33, &p, &E) == LPM_ERR_INVALID);
    CHECK(lpm_pubkey_from_raw(NULL, 32, &p, &E) == LPM_ERR_INVALID);
    /* Key ID = SHA-256 of the 32 raw bytes, lowercase hex. */
    unhex(V[0].public_key, raw, 32);
    CHECK(lpm_pubkey_from_raw(raw, 32, &p, &E) == LPM_OK);
    CHECK(lpm_sha256_buffer(raw, 32, expect, &E) == LPM_OK);
    CHECK(lpm_key_id(raw, id, &E) == LPM_OK && strcmp(id, expect) == 0);
    CHECK(strcmp(p.id, expect) == 0 && strlen(p.id) == 64);
}

static char *pem_of(EVP_PKEY *k, int private_key)
{
    BIO *b = BIO_new(BIO_s_mem());
    BUF_MEM *m;
    char *s;
    if (private_key)
        PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL);
    else
        PEM_write_bio_PUBKEY(b, k);
    BIO_get_mem_ptr(b, &m);
    s = malloc(m->length + 1);
    memcpy(s, m->data, m->length);
    s[m->length] = '\0';
    BIO_free(b);
    return s;
}

static EVP_PKEY *keygen(int type)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(type, NULL);
    EVP_PKEY *k = NULL;
    EVP_PKEY_keygen_init(c);
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void test_pem_import_and_rejections(void)
{
    EVP_PKEY *ed = keygen(EVP_PKEY_ED25519), *x = keygen(EVP_PKEY_X25519);
    char *pub = pem_of(ed, 0), *priv = pem_of(ed, 1), *xpub = pem_of(x, 0);
    char two[8192], *again;
    size_t alen;
    lpm_pubkey a, b;

    CHECK(lpm_pubkey_from_pem(pub, strlen(pub), &a, &E) == LPM_OK);
    /* round trip through LPM's canonical encoding: same key, same ID */
    CHECK(lpm_pubkey_to_pem(&a, &again, &alen, &E) == LPM_OK);
    CHECK(lpm_pubkey_from_pem(again, alen, &b, &E) == LPM_OK);
    CHECK(memcmp(a.raw, b.raw, 32) == 0 && strcmp(a.id, b.id) == 0);
    free(again);

    CHECK(lpm_pubkey_from_pem(priv, strlen(priv), &b, &E) == LPM_ERR_INVALID);
    CHECK(strstr(E.message, "PRIVATE key") != NULL);
    CHECK(lpm_pubkey_from_pem(xpub, strlen(xpub), &b, &E) == LPM_ERR_INVALID);
    CHECK(strstr(E.message, "not an Ed25519 key") != NULL);   /* X25519 */
    CHECK(lpm_pubkey_from_pem("garbage\n", 8, &b, &E) == LPM_ERR_INVALID);
    CHECK(lpm_pubkey_from_pem("", 0, &b, &E) == LPM_ERR_INVALID);
    {   /* a corrupted base64 body */
        char *c = malloc(strlen(pub) + 1);
        strcpy(c, pub);
        c[40] = c[40] == 'A' ? 'B' : 'A';
        c[41] = '!';
        CHECK(lpm_pubkey_from_pem(c, strlen(c), &b, &E) == LPM_ERR_INVALID);
        free(c);
    }
    snprintf(two, sizeof(two), "%s%s", pub, pub);       /* two keys */
    CHECK(lpm_pubkey_from_pem(two, strlen(two), &b, &E) == LPM_ERR_INVALID);
    CHECK(strstr(E.message, "more than one key") != NULL);
    {
        char big[LPM_KEY_PEM_MAX + 2];
        memset(big, 'A', sizeof(big));
        CHECK(lpm_pubkey_from_pem(big, sizeof(big), &b, &E) == LPM_ERR_INVALID);
    }
    {   /* private-key loading: encrypted keys and public keys are refused */
        lpm_privkey *k;
        CHECK(lpm_privkey_from_pem(priv, strlen(priv), &k, &E) == LPM_OK);
        lpm_privkey_free(k);
        CHECK(lpm_privkey_from_pem(pub, strlen(pub), &k, &E) == LPM_ERR_INVALID);
        CHECK(k == NULL);
    }
    free(pub);
    free(priv);
    free(xpub);
    EVP_PKEY_free(ed);
    EVP_PKEY_free(x);
}

/* ---- the signature record --------------------------------------------- */

static char REC[LPM_SIG_RECORD_MAX];
static size_t REC_LEN;

static void make_record(void)
{
    lpm_sigrec r;
    unsigned char seed[32];
    lpm_privkey *k;

    unhex(V[1].secret, seed, 32);
    lpm_privkey_from_seed(seed, &k, &E);
    lpm_privkey_public(k, &r.signer, &E);
    lpm_ed25519_sign(k, "x", 1, r.sig, &E);
    lpm_sigrec_format(&r, REC, sizeof(REC), &REC_LEN);
    lpm_privkey_free(k);
}

static lpm_status parse_variant(const char *text, lpm_meta_error_code *code)
{
    lpm_sigrec r;
    lpm_status rc = lpm_sigrec_parse(text, strlen(text), &r, &E);
    *code = E.code;
    if (tf_verbose && rc != LPM_OK)
        printf("      %s\n", E.message);
    return rc;
}

/* Replace the first occurrence of from with to in REC. */
static const char *variant(const char *from, const char *to)
{
    static char out[2 * LPM_SIG_RECORD_MAX];
    const char *at = strstr(REC, from);
    size_t pre = (size_t)(at - REC);
    snprintf(out, sizeof(out), "%.*s%s%s", (int)pre, REC, to, at + strlen(from));
    return out;
}

static void test_record_round_trip(void)
{
    lpm_sigrec r;
    char pub_hex[65];

    make_record();
    CHECK(lpm_sigrec_parse(REC, REC_LEN, &r, &E) == LPM_OK);
    lpm_hex_encode(r.signer.raw, 32, pub_hex);
    CHECK(strcmp(pub_hex, V[1].public_key) == 0);
    {
        static const char head[] = "format=lpm-signature-v1\nalgorithm=ed25519\npublic_key=";
        CHECK(strncmp(REC, head, sizeof(head) - 1) == 0);
    }
    CHECK(REC[REC_LEN - 1] == '\n');
}

static void test_record_rejections(void)
{
    lpm_meta_error_code c;
    char buf[2 * LPM_SIG_RECORD_MAX];
    char *sigline;

    make_record();
    /* unsupported format / algorithm */
    CHECK(parse_variant(variant("lpm-signature-v1", "lpm-signature-v2"), &c) == LPM_ERR_SIGNATURE &&
          c == LPM_META_ERR_SIG_UNSUPPORTED);
    CHECK(parse_variant(variant("algorithm=ed25519", "algorithm=ed448"), &c) == LPM_ERR_SIGNATURE &&
          c == LPM_META_ERR_SIG_UNSUPPORTED);
    /* key_id that is not the hash of public_key: a borrowed identity */
    CHECK(parse_variant(variant("key_id=", "key_id=0"), &c) == LPM_ERR_SIGNATURE);
    {
        char *k = strstr(REC, "key_id=") + 7;
        char saved = *k;
        *k = *k == 'a' ? 'b' : 'a';
        CHECK(parse_variant(REC, &c) == LPM_ERR_SIGNATURE && c == LPM_META_ERR_KEY_MISMATCH);
        *k = saved;
    }
    /* truncated and oversized signatures */
    sigline = strstr(REC, "signature=") + 10;
    snprintf(buf, sizeof(buf), "%.*s%.126s\n", (int)(sigline - REC), REC, sigline);
    CHECK(parse_variant(buf, &c) == LPM_ERR_SIGNATURE && c == LPM_META_ERR_SIG_MALFORMED);
    snprintf(buf, sizeof(buf), "%.*s%.128s00\n", (int)(sigline - REC), REC, sigline);
    CHECK(parse_variant(buf, &c) == LPM_ERR_SIGNATURE && c == LPM_META_ERR_SIG_MALFORMED);
    /* uppercase hex, CRLF, missing / duplicate / extra / reordered lines */
    CHECK(parse_variant(variant("signature=", "signature=A"), &c) == LPM_ERR_SIGNATURE);
    CHECK(parse_variant(variant("ed25519\n", "ed25519\r\n"), &c) == LPM_ERR_SIGNATURE);
    CHECK(parse_variant(variant("algorithm=ed25519\n", ""), &c) == LPM_ERR_SIGNATURE &&
          c == LPM_META_ERR_SIG_MALFORMED);
    CHECK(parse_variant(variant("algorithm=ed25519\n", "algorithm=ed25519\nalgorithm=ed25519\n"),
                        &c) == LPM_ERR_SIGNATURE);
    snprintf(buf, sizeof(buf), "%sextra=1\n", REC);
    CHECK(parse_variant(buf, &c) == LPM_ERR_SIGNATURE);
    snprintf(buf, sizeof(buf), "%.*s", (int)(REC_LEN - 1), REC);          /* no final LF */
    CHECK(parse_variant(buf, &c) == LPM_ERR_SIGNATURE);
    CHECK(parse_variant(variant("format=lpm-signature-v1\nalgorithm=ed25519\n",
                                "algorithm=ed25519\nformat=lpm-signature-v1\n"), &c) ==
          LPM_ERR_SIGNATURE);
    CHECK(parse_variant("", &c) == LPM_ERR_SIGNATURE);
    {
        lpm_sigrec r;
        char big[LPM_SIG_RECORD_MAX + 1];
        memset(big, 'a', sizeof(big));
        CHECK(lpm_sigrec_parse(big, sizeof(big), &r, &E) == LPM_ERR_SIGNATURE);
        CHECK(lpm_sigrec_parse("format=lpm\0", 11, &r, &E) == LPM_ERR_SIGNATURE);
    }
}

static void test_allocation_failures(void)
{
    static const char meta[] = "name=a\nversion=1\n";
    long n;
    int done = 0;

    for (n = 0; n < 200 && !done; n++) {
        lpm_privkey *k = NULL;
        lpm_pubkey p;
        unsigned char sig[64];
        char *msg = NULL, *pem = NULL;
        size_t len, plen;
        lpm_status rc;

        alloc_seen = 0;
        alloc_fail_at = n;
        rc = lpm_privkey_generate(&k, &E);
        if (rc == LPM_OK) rc = lpm_privkey_public(k, &p, &E);
        if (rc == LPM_OK) rc = lpm_signed_message(meta, strlen(meta), &msg, &len, &E);
        if (rc == LPM_OK) rc = lpm_ed25519_sign(k, msg, len, sig, &E);
        if (rc == LPM_OK) rc = lpm_ed25519_verify(&p, msg, len, sig, &E);
        if (rc == LPM_OK) rc = lpm_pubkey_to_pem(&p, &pem, &plen, &E);
        alloc_fail_at = -1;
        if (rc == LPM_OK)
            done = 1;
        else
            CHECK(rc == LPM_ERR_NOMEM || rc == LPM_ERR_CRYPTO);
        free(msg);
        free(pem);
        lpm_privkey_free(k);
    }
    CHECK(done);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    printf("Running Ed25519 signature unit tests\n");
    RUN(test_rfc8032_vectors);
    RUN(test_wrong_key_message_signature);
    RUN(test_empty_message);
    RUN(test_domain_separation);
    RUN(test_key_lengths_and_ids);
    RUN(test_pem_import_and_rejections);
    RUN(test_record_round_trip);
    RUN(test_record_rejections);
    RUN(test_allocation_failures);
    return tf_summary();
}
