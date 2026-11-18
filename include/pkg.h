/*
 * pkg.h - Reading and verifying an LPM package file (.lpm).
 *
 * A package is a tar archive (plain, gzip or xz) whose entries are, in
 * this order:
 *
 *   metadata.txt        Milestone 2 format, DISTRIBUTABLE profile
 *   manifest.txt        see manifest.h; SHA-256 == metadata's manifest_sha256
 *   payload/...         the files, e.g. payload/usr/bin/hello
 *
 * Integrity chain checked by lpm_pkg_read():
 *
 *   metadata.txt --manifest_sha256--> manifest.txt --sha256 per file--> payload
 *
 * Every payload byte is therefore covered by a hash that metadata.txt
 * commits to. Milestone 6 adds an optional third entry, signature.txt:
 * an Ed25519 signature over the raw bytes of metadata.txt (kept in
 * lpm_pkg.metadata_raw for exactly that purpose), which completes the
 * chain back to a trusted key. This module only reads the record;
 * trust.c decides whether it is valid and trusted.
 *
 * Integrity is NOT authenticity: lpm_pkg_read() alone proves only that
 * the hashes agree; anyone can build such a package.
 */
#ifndef LPM_PKG_H
#define LPM_PKG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lpm.h"
#include "manifest.h"
#include "metadata.h"

#define LPM_PKG_METADATA  "metadata.txt"
#define LPM_PKG_MANIFEST  "manifest.txt"
#define LPM_PKG_PAYLOAD   "payload"
#define LPM_PKG_SIGNATURE "signature.txt"   /* Milestone 6, optional */
#define LPM_PKG_SIGNATURE_MAX 1024

typedef struct {
    lpm_package meta;          /* parsed metadata.txt                     */
    char *metadata_raw;        /* its exact bytes (what the signature covers) */
    size_t metadata_len;
    char *signature_raw;       /* signature.txt bytes, NULL if unsigned */
    size_t signature_len;
    lpm_manifest manifest;     /* parsed, hash-verified manifest.txt      */
    uint64_t payload_bytes;    /* bytes of regular-file content verified  */
} lpm_pkg;

void lpm_pkg_init(lpm_pkg *p);
void lpm_pkg_free(lpm_pkg *p);

/*
 * Read the package from an open descriptor (from its current offset),
 * verifying the whole chain above. Payload files are streamed through
 * SHA-256 in fixed-size chunks; with stage_fd >= 0 each verified file is
 * also written into that directory under lpm_pkg_stage_name(index of
 * its manifest entry), mode set from the manifest. With stage_fd < 0
 * nothing is written anywhere (`lpm verify`).
 *
 * Structural problems (wrong order, unlisted or missing entries, unsafe
 * names, hard links, special files) are LPM_ERR_INVALID; any hash
 * mismatch is LPM_ERR_INTEGRITY. On failure *out is empty; files already
 * staged are left for the caller, who owns the staging directory.
 */
lpm_status lpm_pkg_read(int fd, int stage_fd, lpm_pkg *out, lpm_meta_error *err);

/*
 * Milestone 5: read and strictly parse only metadata.txt (the first
 * entry), for dependency planning. This is NOT verification: nothing
 * else in the archive is looked at. Installation always runs the full
 * lpm_pkg_read() on every package it installs.
 */
lpm_status lpm_pkg_read_metadata(int fd, lpm_package *out, lpm_meta_error *err);

/* "f000042" for manifest entry 42. buf must hold 16 bytes. */
void lpm_pkg_stage_name(size_t index, char buf[16]);

#endif /* LPM_PKG_H */
