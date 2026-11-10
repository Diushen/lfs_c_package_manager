/*
 * lpm-db-demo.c - Demonstration driver for the Milestone 3 database API.
 *
 * This is NOT a package installer and is never installed by `make
 * install`. It exercises the public database and version APIs against a
 * disposable --root, so registration, duplicate rejection, removal,
 * locking and version comparison can be shown without touching the
 * real system. `lpm install` / `lpm remove` stay unimplemented until
 * they can manage real files and verify signatures.
 *
 *   lpm-db-demo --root DIR init
 *   lpm-db-demo --root DIR register FILE.meta [FILE.list]
 *   lpm-db-demo --root DIR unregister NAME
 *   lpm-db-demo --root DIR exists NAME
 *   lpm-db-demo --root DIR files NAME
 *   lpm-db-demo --root DIR hold-lock SECONDS
 *   lpm-db-demo compare V1 V2
 *   lpm-db-demo satisfies VERSION OP REQUIRED     (OP is = or >=)
 */
#include "database.h"
#include "filelist.h"
#include "metadata.h"
#include "util.h"
#include "version.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define PROG "lpm-db-demo"

static void usage(void)
{
    fprintf(stderr,
        "Usage: " PROG " --root DIR [--wait SECONDS] <command> [args]\n"
        "       " PROG " compare V1 V2\n"
        "       " PROG " satisfies VERSION OP REQUIRED   (OP is = or >=)\n"
        "\n"
        "Database commands (records only: nothing is installed or deleted):\n"
        "  init                         create an empty database under DIR\n"
        "  register FILE.meta [FILE.list]  record a package and the files it claims\n"
        "  unregister NAME              remove a package's records\n"
        "  exists NAME                  is NAME registered?\n"
        "  files NAME                   print NAME's recorded file list\n"
        "  hold-lock SECONDS            hold the database lock (locking demo)\n");
}

/*
 * The demo refuses the real root, even when asked explicitly. Comparing
 * device and inode numbers catches every spelling of it ("/", "//",
 * "/usr/..", a symlink to /).
 */
static int is_real_root(const char *root)
{
    struct stat a, b;

    if (stat(root, &a) != 0 || stat("/", &b) != 0)
        return 0;   /* lpm_db_open() reports the real problem */
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int fail(lpm_status rc, const char *what, const lpm_meta_error *err)
{
    lpm_error("%s: %s", what, err->message[0] ? err->message : lpm_status_str(rc));
    return lpm_status_to_exit(rc);
}

static int open_db(const lpm_config *cfg, lpm_db_mode mode, unsigned wait_ms,
                   lpm_db *db)
{
    lpm_meta_error err;
    lpm_status rc = lpm_db_open(cfg, mode, wait_ms, db, &err);

    if (rc != LPM_OK)
        return fail(rc, "cannot open the package database", &err);
    return 0;
}

static int cmd_register(const lpm_config *cfg, unsigned wait_ms,
                        const char *meta_path, const char *list_path)
{
    lpm_package pkg;
    lpm_file_list files;
    lpm_meta_error err;
    lpm_status rc;
    lpm_db db;
    int code;

    lpm_file_list_init(&files);
    rc = lpm_metadata_parse_file(meta_path, LPM_META_INSTALLED, &pkg, &err);
    if (rc != LPM_OK) {
        char msg[512];
        lpm_meta_error_format(&err, meta_path, msg, sizeof(msg));
        lpm_error("rejected metadata %s", msg);
        return lpm_status_to_exit(rc);
    }
    if (list_path != NULL) {
        char *data;
        size_t len;

        rc = lpm_read_bounded_fileat(AT_FDCWD, list_path, LPM_FILES_MAX_SIZE,
                                     &data, &len, &err);
        if (rc == LPM_OK) {
            rc = lpm_file_list_parse_buffer(data, len, &files, &err);
            free(data);
        }
        if (rc != LPM_OK) {
            char msg[512];
            lpm_meta_error_format(&err, list_path, msg, sizeof(msg));
            lpm_error("rejected file list %s", msg);
            lpm_package_free(&pkg);
            return lpm_status_to_exit(rc);
        }
    }

    code = open_db(cfg, LPM_DB_WRITE, wait_ms, &db);
    if (code == 0) {
        rc = lpm_db_register_package(&db, &pkg, &files, &err);
        lpm_db_close(&db);
        if (rc != LPM_OK) {
            code = fail(rc, "registration failed", &err);
        } else {
            printf("Registered %s %s in the database (%zu owned path%s recorded).\n"
                   "No files were installed: this is a database record only.\n",
                   pkg.name, pkg.version, files.count, files.count == 1 ? "" : "s");
        }
    }
    lpm_package_free(&pkg);
    lpm_file_list_free(&files);
    return code;
}

static int cmd_unregister(const lpm_config *cfg, unsigned wait_ms, const char *name)
{
    lpm_meta_error err;
    lpm_status rc;
    lpm_db db;
    int code = open_db(cfg, LPM_DB_WRITE, wait_ms, &db);

    if (code != 0)
        return code;
    rc = lpm_db_unregister_package(&db, name, &err);
    lpm_db_close(&db);
    if (rc != LPM_OK)
        return fail(rc, "unregistration failed", &err);
    printf("Removed the database records of %s.\n"
           "No package files were deleted: this removes database records only.\n",
           name);
    return 0;
}

static int cmd_exists(const lpm_config *cfg, unsigned wait_ms, const char *name)
{
    lpm_meta_error err;
    lpm_status rc;
    bool exists = false;
    lpm_db db;
    int code = open_db(cfg, LPM_DB_READ, wait_ms, &db);

    if (code != 0)
        return code;
    rc = lpm_db_package_exists(&db, name, &exists, &err);
    lpm_db_close(&db);
    if (rc != LPM_OK)
        return fail(rc, "lookup failed", &err);
    printf("%s is %sregistered\n", name, exists ? "" : "not ");
    return exists ? 0 : 1;
}

static int cmd_files(const lpm_config *cfg, unsigned wait_ms, const char *name)
{
    lpm_file_list files;
    lpm_meta_error err;
    lpm_status rc;
    lpm_db db;
    size_t i;
    int code = open_db(cfg, LPM_DB_READ, wait_ms, &db);

    if (code != 0)
        return code;
    rc = lpm_db_read_file_list(&db, name, &files, &err);
    lpm_db_close(&db);
    if (rc != LPM_OK)
        return fail(rc, "cannot read file list", &err);
    for (i = 0; i < files.count; i++)
        printf("%s\n", files.paths[i]);
    lpm_file_list_free(&files);
    return 0;
}

static int cmd_hold_lock(const lpm_config *cfg, const char *secs)
{
    char *end;
    long n = strtol(secs, &end, 10);
    struct timespec ts;
    lpm_db db;
    int code;

    if (*secs == '\0' || *end != '\0' || n < 0 || n > 3600) {
        lpm_error("hold-lock needs a number of seconds between 0 and 3600");
        return 2;
    }
    code = open_db(cfg, LPM_DB_WRITE, 0, &db);
    if (code != 0)
        return code;
    printf("Holding the exclusive database lock for %ld second%s...\n",
           n, n == 1 ? "" : "s");
    fflush(stdout);
    ts.tv_sec = (time_t)n;
    ts.tv_nsec = 0;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
    lpm_db_close(&db);
    printf("Lock released.\n");
    return 0;
}

static int cmd_compare(const char *a, const char *b)
{
    int c;

    if (lpm_version_compare(a, b, &c) != LPM_OK) {
        lpm_error("invalid version: '%s' or '%s' (expected e.g. 1.2.3, no leading "
                  "zeros)", a, b);
        return 1;
    }
    printf("%s %s %s\n", a, c < 0 ? "<" : c > 0 ? ">" : "==", b);
    return 0;
}

static int cmd_satisfies(const char *installed, const char *op, const char *req)
{
    lpm_dependency dep;
    bool ok;

    if (strcmp(op, ">=") == 0) {
        dep.op = LPM_DEP_MINIMUM;
    } else if (strcmp(op, "=") == 0) {
        dep.op = LPM_DEP_EXACT;
    } else {
        lpm_error("unsupported operator '%s' (use = or >=)", op);
        return 2;
    }
    dep.name = (char *)"demo";
    dep.version = (char *)req;
    if (lpm_version_satisfies(installed, &dep, &ok) != LPM_OK) {
        lpm_error("invalid version: '%s' or '%s'", installed, req);
        return 1;
    }
    printf("%s %s %s %s\n", installed, ok ? "satisfies" : "does not satisfy", op, req);
    return 0;
}

int main(int argc, char **argv)
{
    lpm_config cfg = { NULL };
    unsigned wait_ms = 0;
    const char *cmd;
    int i = 1, nargs;

    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            cfg.root = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            char *end;
            long s = strtol(argv[i + 1], &end, 10);
            if (*end != '\0' || s < 0 || s > 3600) {
                lpm_error("--wait needs a number of seconds between 0 and 3600");
                return 2;
            }
            wait_ms = (unsigned)s * 1000u;
            i += 2;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else {
            lpm_error("unknown option '%s'", argv[i]);
            usage();
            return 2;
        }
    }
    if (i >= argc) {
        usage();
        return 2;
    }
    cmd = argv[i];
    nargs = argc - i - 1;

    if (strcmp(cmd, "compare") == 0 && nargs == 2)
        return cmd_compare(argv[i + 1], argv[i + 2]);
    if (strcmp(cmd, "satisfies") == 0 && nargs == 3)
        return cmd_satisfies(argv[i + 1], argv[i + 2], argv[i + 3]);

    if (cfg.root == NULL) {
        lpm_error("--root DIR is required: this demo never uses the real "
                  "system database");
        return 2;
    }
    if (is_real_root(cfg.root)) {
        lpm_error("refusing to operate on '/': use a disposable directory");
        return 2;
    }

    if (strcmp(cmd, "init") == 0 && nargs == 0) {
        lpm_db db;
        int code = open_db(&cfg, LPM_DB_CREATE, wait_ms, &db);
        if (code != 0)
            return code;
        lpm_db_close(&db);
        printf("Initialised an empty package database under %s/%s\n",
               cfg.root, LPM_DB_SUBDIR);
        return 0;
    }
    if (strcmp(cmd, "register") == 0 && (nargs == 1 || nargs == 2))
        return cmd_register(&cfg, wait_ms, argv[i + 1], nargs == 2 ? argv[i + 2] : NULL);
    if (strcmp(cmd, "unregister") == 0 && nargs == 1)
        return cmd_unregister(&cfg, wait_ms, argv[i + 1]);
    if (strcmp(cmd, "exists") == 0 && nargs == 1)
        return cmd_exists(&cfg, wait_ms, argv[i + 1]);
    if (strcmp(cmd, "files") == 0 && nargs == 1)
        return cmd_files(&cfg, wait_ms, argv[i + 1]);
    if (strcmp(cmd, "hold-lock") == 0 && nargs == 1)
        return cmd_hold_lock(&cfg, argv[i + 1]);

    lpm_error("unknown command or wrong number of arguments: '%s'", cmd);
    usage();
    return 2;
}
