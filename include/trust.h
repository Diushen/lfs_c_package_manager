/*
 * trust.h - Trusted public keys and package authentication (Milestone 6).
 *
 * Trust store: <root>/etc/lpm/trusted-keys/<key_id>.pub, one canonical
 * PEM public key per file, named by its own key ID (signature.h). The
 * store belongs to the selected --root: a test root never sees the
 * host's keys, and the host never sees a test root's.
 *
 *   - Keys enter only through lpm_trust_add() (`lpm key add`), an
 *     explicit administrative action. A key embedded in a package is
 *     never added, and package files can never be installed below
 *     /etc/lpm or /var/lib/lpm (install.c refuses such paths).
 *   - Every directory is opened without following symlinks and must be
 *     owned by the current user or root and not group/world-writable.
 *   - A key file whose content does not hash to its file name is
 *     rejected as tampered, never used.
 *   - Removing a key ("revocation" in this design) takes effect for the
 *     next verification; there is no remote revocation list.
 *
 * Writers (add/remove) are expected to hold the database's exclusive
 * lock, which the installer also holds while it reads the store.
 */
#ifndef LPM_TRUST_H
#define LPM_TRUST_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "metadata.h"
#include "signature.h"

#define LPM_TRUST_DIR       "etc/lpm/trusted-keys"
#define LPM_TRUST_SUFFIX    ".pub"
#define LPM_TRUST_MAX_KEYS  256

/* Add a key. LPM_ERR_EXISTS if already trusted. root_fd: the --root. */
lpm_status lpm_trust_add(int root_fd, const lpm_pubkey *key, lpm_meta_error *err);

/* Remove the key with exactly this ID. LPM_ERR_NOT_FOUND if absent. */
lpm_status lpm_trust_remove(int root_fd, const char *key_id, lpm_meta_error *err);

/* All trusted keys, sorted by ID (caller frees *keys). An empty or
 * missing store gives 0 keys. A damaged entry is LPM_ERR_INVALID. */
lpm_status lpm_trust_list(int root_fd, lpm_pubkey **keys, size_t *count,
                          lpm_meta_error *err);

/* The trusted key with this ID: LPM_OK, or LPM_ERR_UNTRUSTED
 * (LPM_META_ERR_KEY_UNTRUSTED) when there is none. */
lpm_status lpm_trust_lookup(int root_fd, const char *key_id, lpm_pubkey *out,
                            lpm_meta_error *err);

/* ---- authentication policy ---------------------------------------- */

typedef enum {
    LPM_AUTH_UNSIGNED,        /* no signature.txt                          */
    LPM_AUTH_BAD_RECORD,      /* signature.txt malformed or unsupported    */
    LPM_AUTH_INVALID,         /* the signature does not verify             */
    LPM_AUTH_UNTRUSTED,       /* valid signature, signer not in the store  */
    LPM_AUTH_TRUSTED          /* valid signature by a trusted key          */
} lpm_auth_status;

typedef struct {
    lpm_auth_status status;
    bool signature_valid;     /* mathematically, with the embedded key   */
    bool key_trusted;         /* the signer's ID is in the trust store   */
    char key_id[LPM_KEY_ID_HEX_LEN + 1];   /* "" if unknown             */
} lpm_auth_result;

const char *lpm_auth_status_str(lpm_auth_status s);

/*
 * Authenticate one package's metadata bytes (exactly as read from the
 * archive) against its signature record. sig_raw == NULL: unsigned.
 * root_fd < 0: no trust store (everything is untrusted).
 *
 * The signature is checked twice for clarity of reporting: with the
 * embedded key (signature_valid) and, if that key is trusted, with the
 * STORED copy of the key, which must be byte-identical. Only the latter
 * makes a package authentic.
 *
 * Returns LPM_OK only for LPM_AUTH_TRUSTED; otherwise LPM_ERR_SIGNATURE
 * (unsigned, malformed, invalid) or LPM_ERR_UNTRUSTED, with *res filled
 * in either way.
 */
lpm_status lpm_authenticate(int root_fd, const char *metadata, size_t metadata_len,
                            const char *sig_raw, size_t sig_len,
                            lpm_auth_result *res, lpm_meta_error *err);

#endif /* LPM_TRUST_H */
