/*
 * test_signing.h - Ephemeral signing keys for the test programs
 * (Milestone 6). Header-only, like test_framework.h.
 *
 * Every test run generates fresh Ed25519 keys in memory; no private key
 * is ever stored in the repository or on disk. tk_key is "the publisher"
 * whose public key the tests trust in each test root.
 */
#ifndef LPM_TEST_SIGNING_H
#define LPM_TEST_SIGNING_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "signature.h"
#include "trust.h"

static lpm_privkey *tk_key;      /* trusted publisher            */
static lpm_pubkey tk_pub;
static lpm_privkey *tk_other;    /* a stranger nobody trusts     */
static lpm_pubkey tk_other_pub;

static void tk_init(void)
{
    lpm_meta_error e;
    if (tk_key == NULL) {
        if (lpm_privkey_generate(&tk_key, &e) != LPM_OK ||
            lpm_privkey_public(tk_key, &tk_pub, &e) != LPM_OK ||
            lpm_privkey_generate(&tk_other, &e) != LPM_OK ||
            lpm_privkey_public(tk_other, &tk_other_pub, &e) != LPM_OK) {
            fprintf(stderr, "cannot generate test keys: %s\n", e.message);
            exit(1);
        }
    }
}

static void tk_done(void)
{
    lpm_privkey_free(tk_key);
    lpm_privkey_free(tk_other);
    tk_key = tk_other = NULL;
}

/* signature.txt for these metadata bytes, signed by key. */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static size_t tk_sign(const lpm_privkey *key, const char *meta, size_t len,
                      char out[LPM_SIG_RECORD_MAX])
{
    lpm_sigrec rec;
    lpm_meta_error e;
    char *msg = NULL;
    size_t mlen = 0, rlen = 0;

    if (lpm_signed_message(meta, len, &msg, &mlen, &e) != LPM_OK ||
        lpm_ed25519_sign(key, msg, mlen, rec.sig, &e) != LPM_OK ||
        lpm_privkey_public(key, &rec.signer, &e) != LPM_OK ||
        lpm_sigrec_format(&rec, out, LPM_SIG_RECORD_MAX, &rlen) != LPM_OK) {
        fprintf(stderr, "cannot sign test package\n");
        exit(1);
    }
    free(msg);
    return rlen;
}

/* Trust key in the trust store of root (as `lpm --root root key add`). */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static int tk_trust(const char *root, const lpm_pubkey *key)
{
    lpm_meta_error e;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    lpm_status rc;

    if (fd < 0)
        return -1;
    rc = lpm_trust_add(fd, key, &e);
    close(fd);
    return rc == LPM_OK ? 0 : -1;
}

#endif /* LPM_TEST_SIGNING_H */
