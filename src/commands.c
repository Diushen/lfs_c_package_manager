/*
 * commands.c - Command table and handlers.
 *
 * Adding a command = writing a handler + adding one row to the table.
 * help output and argument-count checking are driven by the table, so
 * they can never drift out of sync with the real commands.
 */
#include "commands.h"
#include "database.h"
#include "install.h"
#include "metadata.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lpm_status cmd_help(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_version(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_list(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_info(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_check(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_verify(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_install(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_not_implemented(const lpm_config *cfg, int argc, char **argv);

static const lpm_command commands[] = {
    /* name      usage           summary                                 min max impl handler */
    { "help",    "",             "Show this help",                         0, 0, 1, cmd_help },
    { "version", "",             "Show version information",               0, 0, 1, cmd_version },
    { "list",    "",             "List installed packages",                0, 0, 1, cmd_list },
    { "info",    "<package>",    "Show details of an installed package",   1, 1, 1, cmd_info },
    { "verify",  "<file.lpm> [--sha256 HEX]", "Verify a package's SHA-256 integrity", 1, 3, 1, cmd_verify },
    { "install", "<file.lpm> [--sha256 HEX]", "Install a local package (not into / yet)", 1, 3, 1, cmd_install },
    { "remove",  "<package>",    "Remove an installed package",            1, 1, 0, cmd_not_implemented },
    { "check",   "",             "Check database consistency",             0, 0, 1, cmd_check },
};

#define COMMAND_COUNT (sizeof(commands) / sizeof(commands[0]))

const lpm_command *lpm_find_command(const char *name)
{
    size_t i;
    for (i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(commands[i].name, name) == 0)
            return &commands[i];
    }
    return NULL;
}

void lpm_print_usage_hint(void)
{
    fprintf(stderr, "Usage: %s [--root DIR] <command> [arguments]\n"
                    "Try '%s help' for more information.\n",
            LPM_PROGRAM_NAME, LPM_PROGRAM_NAME);
}

void lpm_print_help(void)
{
    size_t i;

    printf("%s %s - %s\n\n", "LPM", LPM_VERSION, LPM_LONG_NAME);
    printf("Usage: %s [--root DIR] <command> [arguments]\n\n", LPM_PROGRAM_NAME);

    printf("Global options:\n");
    printf("  --root DIR      Operate on DIR instead of /\n");
    printf("                  (database: DIR/%s)\n", LPM_DB_SUBDIR);
    printf("  -h, --help      Show this help\n");
    printf("  -V, --version   Show version information\n\n");

    printf("Commands:\n");
    for (i = 0; i < COMMAND_COUNT; i++) {
        char synopsis[80];
        snprintf(synopsis, sizeof(synopsis), "%s %s",
                 commands[i].name, commands[i].usage);
        printf("  %-34s %s%s\n", synopsis, commands[i].summary,
               commands[i].implemented ? "" : " (planned)");
    }
}

lpm_status lpm_run_command(const lpm_command *cmd, const lpm_config *cfg,
                           int argc, char **argv)
{
    int nargs = argc - 1;   /* argv[0] is the command name */

    if (nargs < cmd->min_args || nargs > cmd->max_args) {
        if (nargs < cmd->min_args)
            lpm_error("'%s' requires an argument: %s %s",
                      cmd->name, cmd->name, cmd->usage);
        else
            lpm_error("too many arguments for '%s' (usage: %s %s)",
                      cmd->name, cmd->name, cmd->usage);
        lpm_print_usage_hint();
        return LPM_ERR_USAGE;
    }
    return cmd->fn(cfg, argc, argv);
}

/* ------------------------------------------------------------------ */

static lpm_status cmd_help(const lpm_config *cfg, int argc, char **argv)
{
    (void)cfg; (void)argc; (void)argv;
    lpm_print_help();
    return LPM_OK;
}

static lpm_status cmd_version(const lpm_config *cfg, int argc, char **argv)
{
    (void)cfg; (void)argc; (void)argv;
    printf("%s (%s) %s\n", LPM_PROGRAM_NAME, LPM_LONG_NAME, LPM_VERSION);
#if defined(__VERSION__)
    printf("Built with %s, C standard %ld\n", __VERSION__, (long)__STDC_VERSION__);
#endif
    return LPM_OK;
}

static lpm_status cmd_list(const lpm_config *cfg, int argc, char **argv)
{
    lpm_db_list list;
    int db_exists;
    size_t i;
    int width = 4;   /* at least as wide as the "NAME" heading */
    lpm_status rc;

    (void)argc; (void)argv;

    rc = lpm_db_list_installed(cfg, &list, &db_exists);
    if (rc != LPM_OK)
        return rc;

    if (list.count == 0) {
        if (db_exists)
            printf("No packages installed.\n");
        else
            printf("No packages installed (database not initialised under '%s').\n",
                   cfg->root);
        return LPM_OK;
    }

    /* Name length is bounded by LPM_MAX_NAME_LEN, so the cast is safe. */
    for (i = 0; i < list.count; i++) {
        int len = (int)strlen(list.items[i].name);
        if (len > width)
            width = len;
    }

    printf("Installed packages (%zu):\n", list.count);
    printf("  %-*s  %s\n", width, "NAME", "VERSION");
    for (i = 0; i < list.count; i++)
        printf("  %-*s  %s\n", width, list.items[i].name, list.items[i].version);

    lpm_db_list_free(&list);
    return LPM_OK;
}

/*
 * Unlike `list`, `info` is strict: a damaged record is an error, because
 * printing partial details would present unverified data as fact.
 */
static lpm_status cmd_info(const lpm_config *cfg, int argc, char **argv)
{
    const char *name = argv[1];
    lpm_package pkg;
    lpm_meta_error err;
    lpm_status rc;
    size_t i;

    (void)argc;

    if (!lpm_is_valid_package_name(name)) {
        lpm_error("invalid package name '%.*s' (use a-z 0-9 + . _ - and start "
                  "with a letter or digit)", LPM_MAX_NAME_LEN, name);
        return LPM_ERR_INVALID;
    }

    rc = lpm_db_load_package(cfg, name, &pkg, &err);
    if (rc == LPM_ERR_NOT_FOUND) {
        lpm_error("package '%s' is not installed", name);
        return rc;
    }
    if (rc != LPM_OK) {
        char msg[512];
        char *dir = lpm_db_installed_dir(cfg);
        char source[LPM_MAX_NAME_LEN + sizeof(LPM_META_SUFFIX)];

        /* Name the file the way a user would find it on disk. */
        snprintf(source, sizeof(source), "%s%s", name, LPM_META_SUFFIX);
        if (rc == LPM_ERR_NOMEM) {
            lpm_error("out of memory reading package '%s'", name);
        } else {
            char *path = dir ? lpm_path_join(dir, source) : NULL;
            lpm_meta_error_format(&err, path ? path : source, msg, sizeof(msg));
            lpm_error("damaged database record %s", msg);
            free(path);
        }
        free(dir);
        return rc;
    }

    printf("Name:            %s\n", pkg.name);
    printf("Version:         %s\n", pkg.version);
    printf("Description:     %s\n",
           (pkg.description && pkg.description[0]) ? pkg.description : "(none)");
    if (pkg.dependency_count == 0) {
        printf("Dependencies:    (none)\n");
    } else {
        for (i = 0; i < pkg.dependency_count; i++) {
            printf("%-17s%s %s %s\n", i == 0 ? "Dependencies:" : "",
                   pkg.dependencies[i].name,
                   lpm_dep_operator_str(pkg.dependencies[i].op),
                   pkg.dependencies[i].version);
        }
    }
    printf("Manifest SHA256: %s\n",
           pkg.has_manifest_sha256 ? pkg.manifest_sha256 : "(not recorded)");

    lpm_package_free(&pkg);
    return LPM_OK;
}

static void print_check_problem(void *ctx, lpm_check_kind kind,
                                const char *subject, const char *detail)
{
    (void)ctx;
    printf("PROBLEM  [%s] %s: %s\n", lpm_check_kind_str(kind), subject, detail);
}

/*
 * Read-only: reports problems and never repairs or deletes anything, so
 * a suspicious entry stays available for inspection. Exit status 1 when
 * problems are found, so scripts can use it.
 */
static lpm_status cmd_check(const lpm_config *cfg, int argc, char **argv)
{
    lpm_check_summary sum;
    lpm_meta_error err;
    lpm_status rc;
    lpm_db db;

    (void)argc; (void)argv;

    /* Shared lock, so no writer changes the database mid-check; wait a
     * few seconds for a writer that is finishing. */
    rc = lpm_db_open(cfg, LPM_DB_READ, 5000, &db, &err);
    if (rc == LPM_ERR_NOT_FOUND) {
        printf("No package database under '%s': nothing to check.\n", cfg->root);
        return LPM_OK;
    }
    if (rc != LPM_OK) {
        lpm_error("cannot open the package database: %s", err.message);
        return rc;
    }

    printf("Checking package database in '%s' (%s)\n", cfg->root, LPM_DB_SUBDIR);
    rc = lpm_db_check(&db, print_check_problem, NULL, &sum, &err);
    lpm_db_close(&db);
    if (rc != LPM_OK) {
        lpm_error("check did not complete: %s", err.message);
        return rc;
    }

    printf("Checked %zu record%s (%zu valid) owning %zu file%s.\n",
           sum.records, sum.records == 1 ? "" : "s", sum.packages,
           sum.owned_files, sum.owned_files == 1 ? "" : "s");
    if (sum.problems > 0) {
        printf("%zu problem%s found. Nothing was changed; inspect the entries "
               "above.\n", sum.problems, sum.problems == 1 ? "" : "s");
        return LPM_ERR_INVALID;
    }
    printf("No problems found by the implemented checks.\n");
    printf("Not checked yet: whether owned files exist on disk or match their "
           "checksums (later milestones).\n");
    return LPM_OK;
}

/* Parse "<file> [--sha256 HEX]" (argv[0] is the command name). */
static lpm_status package_args(int argc, char **argv, const char **file,
                               const char **sha256)
{
    *file = argv[1];
    *sha256 = NULL;
    if (argc == 2)
        return LPM_OK;
    if (argc == 4 && strcmp(argv[2], "--sha256") == 0) {
        *sha256 = argv[3];
        return LPM_OK;
    }
    lpm_error("usage: %s %s <file.lpm> [--sha256 HEX]", LPM_PROGRAM_NAME, argv[0]);
    lpm_print_usage_hint();
    return LPM_ERR_USAGE;
}

static void report_package_error(const char *what, const char *file,
                                 lpm_status rc, const lpm_meta_error *err)
{
    lpm_error("%s %s: %s%s", what, file,
              rc == LPM_ERR_INTEGRITY ? "INTEGRITY FAILURE: " : "",
              err->message[0] ? err->message : lpm_status_str(rc));
}

static lpm_status cmd_verify(const lpm_config *cfg, int argc, char **argv)
{
    const char *file, *sha256;
    lpm_pkg_summary s;
    lpm_meta_error err;
    lpm_status rc;

    (void)cfg;   /* verification reads only the package file */
    rc = package_args(argc, argv, &file, &sha256);
    if (rc != LPM_OK)
        return rc;
    rc = lpm_verify_package(file, sha256, &s, &err);
    if (rc != LPM_OK) {
        report_package_error("cannot verify", file, rc, &err);
        return rc;
    }
    printf("Package:          %s %s\n", s.name, s.version);
    printf("Package SHA-256:  %s%s\n", s.archive_sha256,
           sha256 ? " (matches --sha256)" : "");
    printf("Manifest:         matches manifest_sha256 in metadata.txt\n");
    printf("Payload:          %zu file%s, %zu symlink%s, %zu director%s, "
           "%ju bytes; every SHA-256 matches\n",
           s.files, s.files == 1 ? "" : "s", s.symlinks, s.symlinks == 1 ? "" : "s",
           s.dirs, s.dirs == 1 ? "y" : "ies", (uintmax_t)s.bytes);
    printf("Result:           INTEGRITY OK (not authenticated: signatures are "
           "checked in a later milestone)\n");
    return LPM_OK;
}

static lpm_status cmd_install(const lpm_config *cfg, int argc, char **argv)
{
    lpm_install_options opt;
    const char *file, *sha256;
    lpm_pkg_summary s;
    lpm_meta_error err;
    lpm_status rc;

    rc = package_args(argc, argv, &file, &sha256);
    if (rc != LPM_OK)
        return rc;
    opt.expected_sha256 = sha256;
    opt.allow_real_root = false;   /* never from the CLI until signatures */
    opt.lock_wait_ms = 5000;
    rc = lpm_install_package(cfg, file, &opt, &s, &err);
    if (rc != LPM_OK) {
        report_package_error("cannot install", file, rc, &err);
        if (rc == LPM_ERR_INTEGRITY || rc == LPM_ERR_INVALID ||
            rc == LPM_ERR_CONFLICT || rc == LPM_ERR_EXISTS)
            fprintf(stderr, "Nothing was installed and the database is unchanged.\n");
        return rc;
    }
    printf("Installed %s %s into '%s': %zu file%s, %zu symlink%s, %zu "
           "director%s (%ju bytes).\n", s.name, s.version, cfg->root,
           s.files, s.files == 1 ? "" : "s", s.symlinks, s.symlinks == 1 ? "" : "s",
           s.dirs, s.dirs == 1 ? "y" : "ies", (uintmax_t)s.bytes);
    printf("Every file matched its SHA-256 before it was placed. The package "
           "is not authenticated (no signature check yet).\n");
    return LPM_OK;
}

static lpm_status cmd_not_implemented(const lpm_config *cfg, int argc, char **argv)
{
    (void)cfg; (void)argc;
    lpm_error("'%s' is not implemented yet in LPM %s", argv[0], LPM_VERSION);
    return LPM_ERR_NOT_IMPLEMENTED;
}
