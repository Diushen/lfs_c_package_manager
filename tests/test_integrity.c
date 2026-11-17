/*
 * test_integrity.c - SHA-256 hashing and verification (Milestone 4).
 *
 * Known-answer tests use the standard FIPS 180-2 / NIST test vectors,
 * so a correct result cannot come from comparing the code with itself.
 */
#include "integrity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_framework.h"

/* FIPS 180-2 vectors. */
#define SHA_EMPTY  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA_ABC    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define SHA_448    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
#define MSG_448    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define SHA_MILLION_A "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

static char dir[512];

static void path_in(char *buf, size_t size, const char *name)
{
    snprintf(buf, size, "%s/%s", dir, name);
}

static void write_file(const char *name, const void *data, size_t len)
{
    char p[600];
    FILE *f;
    path_in(p, sizeof(p), name);
    f = fopen(p, "wb");
    if (f == NULL) {
        perror(p);
        exit(1);
    }
    if (len > 0)
        fwrite(data, 1, len, f);
    fclose(f);
}

static void test_known_vectors_buffer(void)
{
    char hex[65];
    lpm_meta_error err;

    CHECK(lpm_sha256_buffer("", 0, hex, &err) == LPM_OK && strcmp(hex, SHA_EMPTY) == 0);
    CHECK(lpm_sha256_buffer("abc", 3, hex, &err) == LPM_OK && strcmp(hex, SHA_ABC) == 0);
    CHECK(lpm_sha256_buffer(MSG_448, strlen(MSG_448), hex, &err) == LPM_OK &&
          strcmp(hex, SHA_448) == 0);
    CHECK(strlen(hex) == 64);
}

static void test_known_vector_abc_file(void)
{
    char p[600], hex[65];
    lpm_meta_error err;

    write_file("abc", "abc", 3);
    path_in(p, sizeof(p), "abc");
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_OK);
    CHECK(strcmp(hex, SHA_ABC) == 0);
    if (tf_verbose)
        printf("      sha256(abc) = %s\n", hex);
}

static void test_empty_file(void)
{
    char p[600], hex[65];
    lpm_meta_error err;

    write_file("empty", "", 0);
    path_in(p, sizeof(p), "empty");
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_OK && strcmp(hex, SHA_EMPTY) == 0);
    CHECK(lpm_sha256_verify_file(p, SHA_EMPTY, &err) == LPM_OK);
}

static void test_streamed_million_a(void)
{
    /* 1,000,000 bytes: far more than one 64 KiB read, with a known answer,
     * so the chunked streaming path is checked against the standard. */
    char p[600], hex[65];
    char *buf = malloc(1000000);
    lpm_meta_error err;

    memset(buf, 'a', 1000000);
    write_file("million", buf, 1000000);
    free(buf);
    path_in(p, sizeof(p), "million");
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_OK);
    CHECK(strcmp(hex, SHA_MILLION_A) == 0);
}

static void test_incremental_equals_one_shot(void)
{
    /* Odd chunk sizes across block boundaries give the same digest. */
    static const size_t sizes[] = { 1, 3, 63, 64, 65, 127, 1000, 4096 };
    char a[65], b[65];
    unsigned char *data = malloc(100000);
    lpm_meta_error err;
    size_t i, k;

    for (i = 0; i < 100000; i++)
        data[i] = (unsigned char)tf_rand();
    CHECK(lpm_sha256_buffer(data, 100000, a, &err) == LPM_OK);
    for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        lpm_sha256_ctx c;
        size_t off = 0;
        CHECK(lpm_sha256_begin(&c, &err) == LPM_OK);
        while (off < 100000) {
            size_t n = sizes[k] < 100000 - off ? sizes[k] : 100000 - off;
            CHECK(lpm_sha256_update(&c, data + off, n, &err) == LPM_OK);
            off += n;
        }
        CHECK(lpm_sha256_finish(&c, b, &err) == LPM_OK);
        CHECK(strcmp(a, b) == 0);
    }
    free(data);
}

static void test_large_file_streamed(void)
{
    /* 96 MiB, hashed with a fixed 64 KiB buffer (memory does not grow
     * with the file). Compared with an incremental hash of the same
     * bytes, which the vector tests above tie to the standard. */
    const size_t chunk = 1024 * 1024, chunks = 96;
    unsigned char *block = malloc(chunk);
    char p[600], expect[65], got[65];
    lpm_sha256_ctx c;
    lpm_meta_error err;
    size_t i, j;
    FILE *f;

    path_in(p, sizeof(p), "large");
    f = fopen(p, "wb");
    CHECK(lpm_sha256_begin(&c, &err) == LPM_OK);
    for (i = 0; i < chunks; i++) {
        for (j = 0; j < chunk; j++)
            block[j] = (unsigned char)(i * 31 + j * 7);
        fwrite(block, 1, chunk, f);
        CHECK(lpm_sha256_update(&c, block, chunk, &err) == LPM_OK);
    }
    fclose(f);
    free(block);
    CHECK(lpm_sha256_finish(&c, expect, &err) == LPM_OK);
    CHECK(lpm_sha256_file(p, got, &err) == LPM_OK);
    CHECK(strcmp(expect, got) == 0);
    CHECK(lpm_sha256_verify_file(p, expect, &err) == LPM_OK);
    unlink(p);
}

static void test_verify_correct_and_incorrect(void)
{
    char p[600];
    lpm_meta_error err;

    write_file("abc2", "abc", 3);
    path_in(p, sizeof(p), "abc2");
    CHECK(lpm_sha256_verify_file(p, SHA_ABC, &err) == LPM_OK);             /* PASS */

    /* One digit changed: verification failure, both digests reported. */
    CHECK(lpm_sha256_verify_file(p, SHA_EMPTY, &err) == LPM_ERR_INTEGRITY);
    CHECK(err.code == LPM_META_ERR_HASH_MISMATCH);
    CHECK(strstr(err.message, "expected " SHA_EMPTY) != NULL);
    CHECK(strstr(err.message, "got " SHA_ABC) != NULL);
    {
        char near[65];
        strcpy(near, SHA_ABC);
        near[63] = near[63] == '0' ? '1' : '0';
        CHECK(lpm_sha256_verify_file(p, near, &err) == LPM_ERR_INTEGRITY);
    }
    /* A file that changed by one byte no longer verifies. */
    write_file("abc2", "abd", 3);
    CHECK(lpm_sha256_verify_file(p, SHA_ABC, &err) == LPM_ERR_INTEGRITY);
}

static void test_uppercase_expected_is_normalised(void)
{
    char p[600], upper[65], out[65];
    lpm_meta_error err;
    size_t i;

    for (i = 0; i < 64; i++)
        upper[i] = (char)((SHA_ABC[i] >= 'a') ? SHA_ABC[i] - 'a' + 'A' : SHA_ABC[i]);
    upper[64] = '\0';
    write_file("abc3", "abc", 3);
    path_in(p, sizeof(p), "abc3");
    CHECK(lpm_sha256_verify_file(p, upper, &err) == LPM_OK);
    CHECK(lpm_sha256_normalize(upper, out, &err) == LPM_OK && strcmp(out, SHA_ABC) == 0);
}

static void test_malformed_expected(void)
{
    static const char *const bad[] = {
        "", "abc", SHA_ABC "0",                         /* lengths */
        "ga7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        " a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a\n",
    };
    char p[600], out[65];
    lpm_meta_error err;
    size_t i;

    write_file("abc4", "abc", 3);
    path_in(p, sizeof(p), "abc4");
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(lpm_sha256_verify_file(p, bad[i], &err) == LPM_ERR_INVALID);
        CHECK(err.code == LPM_META_ERR_INVALID_VALUE);   /* not a "mismatch" */
        CHECK(lpm_sha256_normalize(bad[i], out, &err) == LPM_ERR_INVALID);
        CHECK(out[0] == '\0');
    }
    CHECK(lpm_sha256_verify_file(p, NULL, &err) == LPM_ERR_INVALID);
}

static void test_missing_and_unreadable(void)
{
    char p[600], hex[65];
    lpm_meta_error err;

    path_in(p, sizeof(p), "does-not-exist");
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_ERR_NOT_FOUND);
    CHECK(lpm_sha256_verify_file(p, SHA_ABC, &err) == LPM_ERR_NOT_FOUND);
    CHECK(strstr(err.message, "does-not-exist") != NULL);   /* names the path */

    path_in(p, sizeof(p), "");                              /* a directory */
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_ERR_INVALID);
    CHECK(err.code == LPM_META_ERR_NOT_REGULAR);

    if (geteuid() != 0) {
        write_file("secret", "abc", 3);
        path_in(p, sizeof(p), "secret");
        chmod(p, 0);
        CHECK(lpm_sha256_file(p, hex, &err) == LPM_ERR_IO);
        CHECK(strstr(err.message, "Permission denied") != NULL);
        chmod(p, 0600);
    }
}

static void test_fifo_does_not_hang(void)
{
    char p[600], hex[65];
    lpm_meta_error err;

    path_in(p, sizeof(p), "fifo");
    CHECK(mkfifo(p, 0600) == 0);
    CHECK(lpm_sha256_file(p, hex, &err) == LPM_ERR_INVALID);   /* returns at once */
    unlink(p);
}

static void test_hash_fd_reports_length(void)
{
    char p[600], hex[65];
    lpm_meta_error err;
    uint64_t n = 0;
    int fd;

    write_file("len", MSG_448, strlen(MSG_448));
    path_in(p, sizeof(p), "len");
    fd = open(p, O_RDONLY);
    CHECK(lpm_sha256_fd(fd, hex, &n, &err) == LPM_OK);
    CHECK(n == strlen(MSG_448) && strcmp(hex, SHA_448) == 0);
    close(fd);
}

static void test_equal_and_abort(void)
{
    lpm_sha256_ctx c;
    lpm_meta_error err;
    char hex[65];

    CHECK(lpm_sha256_equal(SHA_ABC, SHA_ABC));
    CHECK(!lpm_sha256_equal(SHA_ABC, SHA_EMPTY));
    CHECK(!lpm_sha256_equal(SHA_ABC, NULL));
    CHECK(!lpm_sha256_equal("short", SHA_ABC + 59));
    /* abort releases; finishing an aborted hash is an error, not a crash */
    CHECK(lpm_sha256_begin(&c, &err) == LPM_OK);
    lpm_sha256_abort(&c);
    lpm_sha256_abort(&c);   /* twice is safe */
    CHECK(lpm_sha256_finish(&c, hex, &err) == LPM_ERR_CRYPTO);
    CHECK(lpm_sha256_update(&c, "x", 1, &err) == LPM_ERR_CRYPTO);
}

static void remove_dir(void)
{
    static const char *const names[] = { "abc", "empty", "million", "abc2", "abc3",
                                         "abc4", "secret", "len", "large", "fifo" };
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[600];
        path_in(p, sizeof(p), names[i]);
        unlink(p);
    }
    rmdir(dir);
}

int main(int argc, char **argv)
{
    const char *t = getenv("TMPDIR");
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;
    snprintf(dir, sizeof(dir), "%s/lpm-shatest-XXXXXX", (t && *t) ? t : "/tmp");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    printf("Running SHA-256 integrity unit tests\n");
    RUN(test_known_vectors_buffer);
    RUN(test_known_vector_abc_file);
    RUN(test_empty_file);
    RUN(test_streamed_million_a);
    RUN(test_incremental_equals_one_shot);
    RUN(test_large_file_streamed);
    RUN(test_verify_correct_and_incorrect);
    RUN(test_uppercase_expected_is_normalised);
    RUN(test_malformed_expected);
    RUN(test_missing_and_unreadable);
    RUN(test_fifo_does_not_hang);
    RUN(test_hash_fd_reports_length);
    RUN(test_equal_and_abort);
    remove_dir();
    return tf_summary();
}
