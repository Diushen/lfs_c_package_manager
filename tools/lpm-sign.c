/*
 * lpm-sign.c - Sign an LPM package with an Ed25519 private key.
 *
 *   lpm-sign PRIVATE.pem IN.lpm OUT.lpm
 *
 * Reads an unsigned package, checks that its metadata and manifest are
 * valid (a broken package is never signed), signs
 *     "LPM-SIGNED-METADATA-V1\n" || metadata.txt
 * and writes OUT.lpm with the same entries plus signature.txt as the
 * third entry. OUT.lpm must not exist (nothing is overwritten).
 *
 * The private key is read into memory only to hand it to OpenSSL; its
 * buffer is wiped afterwards, and it is never printed or written. Keep
 * private keys out of packages, roots and Git. Development keys made
 * with `openssl genpkey` are for testing, not production trust anchors.
 */
#include "integrity.h"
#include "metadata.h"
#include "signature.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>
#include <openssl/crypto.h>

#define PROG "lpm-sign"
#define BLOCK (64 * 1024)

static int die(const char *what)
{
    lpm_error("%s", what);
    return 1;
}

/* Read an entry's data completely (bounded). */
static char *read_entry(struct archive *a, size_t max, size_t *len)
{
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);

    while (buf != NULL) {
        la_ssize_t r;
        if (n == cap) {
            char *g;
            if (cap >= max) {
                free(buf);
                return NULL;
            }
            cap = cap * 2 > max ? max : cap * 2;
            g = realloc(buf, cap + 1);
            if (g == NULL) {
                free(buf);
                return NULL;
            }
            buf = g;
        }
        r = archive_read_data(a, buf + n, cap - n);
        if (r < 0) {
            free(buf);
            return NULL;
        }
        if (r == 0)
            break;
        n += (size_t)r;
    }
    if (buf != NULL) {
        buf[n] = '\0';
        *len = n;
    }
    return buf;
}

static int add_file(struct archive *w, const char *name, const char *data, size_t len)
{
    struct archive_entry *e = archive_entry_new();
    int ok;

    archive_entry_set_pathname(e, name);
    archive_entry_set_filetype(e, AE_IFREG);
    archive_entry_set_perm(e, 0644);
    archive_entry_set_size(e, (la_int64_t)len);
    ok = archive_write_header(w, e) == ARCHIVE_OK &&
         (len == 0 || archive_write_data(w, data, len) == (la_ssize_t)len);
    archive_entry_free(e);
    return ok;
}

static lpm_privkey *load_key(const char *path)
{
    lpm_privkey *key = NULL;
    lpm_meta_error err;
    struct stat st;
    char *pem;
    size_t len;

    if (stat(path, &st) == 0 && (st.st_mode & 077) != 0)
        fprintf(stderr, PROG ": warning: %s is readable by other users; "
                "use chmod 600\n", path);
    if (lpm_read_bounded_fileat(AT_FDCWD, path, LPM_KEY_PEM_MAX, &pem, &len, &err) != LPM_OK) {
        lpm_error("cannot read private key %s: %s", path, err.message);
        return NULL;
    }
    if (lpm_privkey_from_pem(pem, len, &key, &err) != LPM_OK)
        lpm_error("%s: %s", path, err.message);
    OPENSSL_cleanse(pem, len);   /* never leave key bytes lying around */
    free(pem);
    return key;
}

int main(int argc, char **argv)
{
    struct archive *in = NULL, *out = NULL;
    struct archive_entry *e;
    lpm_privkey *key = NULL;
    lpm_sigrec rec;
    lpm_package pkg;
    lpm_meta_error err;
    char *meta = NULL, *manifest = NULL, *msg = NULL, digest[65], record[LPM_SIG_RECORD_MAX];
    size_t meta_len = 0, manifest_len = 0, msg_len, rec_len;
    int fd = -1, rc = 1, filter;
    bool created = false;

    if (argc != 4) {
        fprintf(stderr, "usage: " PROG " PRIVATE.pem IN.lpm OUT.lpm\n");
        return 2;
    }
    lpm_package_init(&pkg);
    key = load_key(argv[1]);
    if (key == NULL)
        return 1;

    in = archive_read_new();
    if (in == NULL || archive_read_support_format_tar(in) != ARCHIVE_OK ||
        archive_read_support_filter_gzip(in) != ARCHIVE_OK ||
        archive_read_support_filter_xz(in) != ARCHIVE_OK ||
        archive_read_open_filename(in, argv[2], BLOCK) != ARCHIVE_OK) {
        rc = die("cannot open the input package");
        goto out;
    }
    if (archive_read_next_header(in, &e) != ARCHIVE_OK ||
        strcmp(archive_entry_pathname(e), "metadata.txt") != 0 ||
        (meta = read_entry(in, LPM_META_MAX_FILE_SIZE, &meta_len)) == NULL ||
        archive_read_next_header(in, &e) != ARCHIVE_OK ||
        strcmp(archive_entry_pathname(e), "manifest.txt") != 0 ||
        (manifest = read_entry(in, 16 * 1024 * 1024, &manifest_len)) == NULL) {
        rc = die("not an LPM package (expected metadata.txt, then manifest.txt)");
        goto out;
    }
    /* Refuse to sign something LPM would reject anyway. */
    if (lpm_metadata_parse_buffer(meta, meta_len, LPM_META_DISTRIBUTABLE, &pkg, &err) != LPM_OK) {
        lpm_error("metadata.txt: %s", err.message);
        goto out;
    }
    if (lpm_sha256_buffer(manifest, manifest_len, digest, &err) != LPM_OK ||
        !lpm_sha256_equal(digest, pkg.manifest_sha256)) {
        rc = die("manifest.txt does not match manifest_sha256; refusing to sign");
        goto out;
    }

    /* Sign exactly: domain prefix || metadata.txt bytes. */
    if (lpm_signed_message(meta, meta_len, &msg, &msg_len, &err) != LPM_OK ||
        lpm_ed25519_sign(key, msg, msg_len, rec.sig, &err) != LPM_OK ||
        lpm_privkey_public(key, &rec.signer, &err) != LPM_OK ||
        lpm_sigrec_format(&rec, record, sizeof(record), &rec_len) != LPM_OK) {
        lpm_error("signing failed: %s", err.message);
        goto out;
    }

    fd = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        lpm_error("cannot create %s: %s (it must not exist)", argv[3], strerror(errno));
        goto out;
    }
    created = true;
    filter = archive_filter_code(in, 0);
    out = archive_write_new();
    if (out == NULL || archive_write_set_format_pax_restricted(out) != ARCHIVE_OK ||
        (filter == ARCHIVE_FILTER_GZIP && archive_write_add_filter_gzip(out) != ARCHIVE_OK) ||
        (filter == ARCHIVE_FILTER_XZ && archive_write_add_filter_xz(out) != ARCHIVE_OK) ||
        archive_write_open_fd(out, fd) != ARCHIVE_OK ||
        !add_file(out, "metadata.txt", meta, meta_len) ||
        !add_file(out, "manifest.txt", manifest, manifest_len) ||
        !add_file(out, "signature.txt", record, rec_len)) {
        rc = die("cannot write the output package");
        goto out;
    }
    /* Copy the payload unchanged. */
    for (;;) {
        int r = archive_read_next_header(in, &e);
        char buf[BLOCK];
        la_ssize_t n;

        if (r == ARCHIVE_EOF)
            break;
        if (r != ARCHIVE_OK) {
            rc = die("the input package is damaged");
            goto out;
        }
        if (strcmp(archive_entry_pathname(e), "signature.txt") == 0) {
            rc = die("the input package is already signed");
            goto out;
        }
        if (archive_write_header(out, e) != ARCHIVE_OK) {
            rc = die("cannot write the output package");
            goto out;
        }
        while ((n = archive_read_data(in, buf, sizeof(buf))) > 0)
            if (archive_write_data(out, buf, (size_t)n) != n) {
                rc = die("cannot write the output package");
                goto out;
            }
        if (n < 0) {
            rc = die("the input package is damaged");
            goto out;
        }
    }
    if (archive_write_close(out) != ARCHIVE_OK) {
        rc = die("cannot finish the output package");
        goto out;
    }
    printf("Signed %s %s with Ed25519 key %s\nWrote %s\n", pkg.name, pkg.version,
           rec.signer.id, argv[3]);
    rc = 0;

out:
    if (out != NULL)
        archive_write_free(out);
    if (in != NULL)
        archive_read_free(in);
    if (fd >= 0)
        close(fd);
    if (rc != 0 && created)
        unlink(argv[3]);   /* never leave a half-written package */
    lpm_package_free(&pkg);
    lpm_privkey_free(key);
    free(meta);
    free(manifest);
    free(msg);
    return rc;
}
