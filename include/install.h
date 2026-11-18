/*
 * install.h - Verify and install a package file (Milestone 4).
 *
 * Order of operations in lpm_install_package():
 *
 *   1. refuse the real root "/" (until Ed25519 signatures exist)
 *   2. open the package file once; optionally check its whole-file
 *      SHA-256 against a digest the user supplied (--sha256), on the
 *      same descriptor that is read afterwards (no swap in between)
 *   3. lock the database (created if missing) for the whole operation
 *   4. read metadata.txt, verify manifest.txt against manifest_sha256,
 *      stream every payload file through SHA-256 into a private staging
 *      directory (pkg.h). A single mismatch stops everything here:
 *      nothing has been written to the root yet.
 *   5. pre-flight: database rules (not yet registered, no file owned by
 *      another package) and filesystem rules (no existing file would be
 *      replaced, no path goes through a symlink)
 *   6. commit: hard-link each verified staged file into place (linkat
 *      never overwrites), create symlinks and directories
 *   7. register the package in the database (Milestone 3, atomic)
 *   8. remove the staging directory
 *
 * If 6 or 7 fails, everything created in 6 is removed again (rollback)
 * and the database is unchanged. Not covered: a crash (power loss, kill
 * -9) during 6-7 can leave files without a record; the leftover staging
 * directory makes `lpm check` report that the install was interrupted.
 */
#ifndef LPM_INSTALL_H
#define LPM_INSTALL_H

#include <stdbool.h>
#include <stdint.h>
#include "lpm.h"
#include "metadata.h"
#include "trust.h"

typedef struct {
    const char *expected_sha256;  /* whole package file; NULL = not given  */
    bool allow_real_root;         /* default false: "/" is refused         */
    unsigned lock_wait_ms;        /* how long to wait for the database lock */
} lpm_install_options;

typedef struct {
    char name[LPM_MAX_NAME_LEN + 1];
    char version[LPM_META_MAX_VERSION_LEN + 1];
    char archive_sha256[LPM_SHA256_HEX_LEN + 1];  /* of the package file */
    char signer[LPM_SHA256_HEX_LEN + 1];          /* key ID; "" if not checked */
    size_t files, symlinks, dirs;
    uint64_t bytes;
} lpm_pkg_summary;

/*
 * Verify a package without installing anything or touching any
 * database: whole-file hash (compared with expected_sha256 if given),
 * metadata, manifest hash, every payload hash, structure and path rules.
 * Returns LPM_OK only if everything holds. Integrity only: an unsigned
 * package can pass.
 */
lpm_status lpm_verify_package(const char *path, const char *expected_sha256,
                              lpm_pkg_summary *out, lpm_meta_error *err);

/*
 * Milestone 6: integrity (as lpm_verify_package) AND authenticity against
 * the trust store of cfg->root. *integrity_ok says whether the hash
 * chain held; *auth reports signature validity and trust separately.
 * Returns LPM_OK only for an intact package signed by a trusted key;
 * otherwise the integrity error, or LPM_ERR_SIGNATURE / LPM_ERR_UNTRUSTED.
 */
lpm_status lpm_verify_authenticated(const lpm_config *cfg, const char *path,
                                    const char *expected_sha256, lpm_pkg_summary *out,
                                    lpm_auth_result *auth, bool *integrity_ok,
                                    lpm_meta_error *err);

/*
 * Install one package whose dependencies must already be installed.
 * Same as lpm_install_packages() without a package directory; *out
 * describes the requested package. opt may be NULL for defaults.
 */
lpm_status lpm_install_package(const lpm_config *cfg, const char *path,
                               const lpm_install_options *opt,
                               lpm_pkg_summary *out, lpm_meta_error *err);

/* What one installation run installed, dependencies first. */
typedef struct {
    lpm_pkg_summary *items;   /* the requested package is the last one */
    size_t count;
    size_t satisfied;         /* dependencies that were already installed */
} lpm_install_report;

void lpm_install_report_free(lpm_install_report *r);

/*
 * Milestone 5: install a package together with any missing dependencies
 * found in package_dir (NULL: dependencies must already be installed).
 *
 *   1. refuse "/"; check the requested file (and --sha256) first
 *   2. lock the database; resolve the dependency plan (plan.h) against
 *      the installed set seen under that lock
 *   3. verify and stage EVERY package of the plan with the full
 *      Milestone 4 checks (steps 2-5 above, per package; --sha256 applies
 *      to the requested file); the verified metadata must equal what the
 *      plan was built from
 *   4. check the packages against each other (no shared file)
 *   5. commit them in dependency order, each: files, then its record
 *   6. if any package fails at 5, every package of THIS run is undone,
 *      newest first: its record is removed and exactly the files and
 *      directories this run created are deleted (nothing else).
 *
 * Unsatisfiable dependencies (LPM_ERR_DEPENDENCY) are found in step 2,
 * before any file is written. A crash (not an ordinary error) during
 * step 5 can still leave a partial state; lpm check reports it through
 * the staging directories left behind.
 */
lpm_status lpm_install_packages(const lpm_config *cfg, const char *path,
                                const char *package_dir,
                                const lpm_install_options *opt,
                                lpm_install_report *report, lpm_meta_error *err);

/* Is root the real "/" (by device and inode, so "//" or a symlink to /
 * count too)? */
bool lpm_is_real_root(const char *root);

#endif /* LPM_INSTALL_H */
