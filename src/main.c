/*
 * main.c - Entry point: parse global options, dispatch to a command.
 *
 * Kept intentionally small. Global options must come BEFORE the command:
 *
 *   lpm [--root DIR] <command> [arguments]
 */
#include "commands.h"
#include "lpm.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Parse global options into cfg. On success *cmd_index is the argv index
 * of the command name (== argc if none was given). *early_exit is set
 * when an option like --help was fully handled here.
 */
static lpm_status parse_global_options(int argc, char **argv, lpm_config *cfg,
                                       int *cmd_index, int *early_exit)
{
    int i = 1;

    *early_exit = 0;
    while (i < argc && argv[i][0] == '-') {
        const char *arg = argv[i];

        if (strcmp(arg, "--root") == 0) {
            if (i + 1 >= argc) {
                lpm_error("option '--root' requires a directory argument");
                return LPM_ERR_USAGE;
            }
            cfg->root = argv[i + 1];
            i += 2;
        } else if (strncmp(arg, "--root=", 7) == 0) {
            cfg->root = arg + 7;
            i += 1;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            lpm_print_help();
            *early_exit = 1;
            return LPM_OK;
        } else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
            const lpm_command *v = lpm_find_command("version");
            *early_exit = 1;
            return lpm_run_command(v, cfg, 1, &argv[i]);
        } else if (strcmp(arg, "--") == 0) {
            i += 1;
            break;
        } else {
            lpm_error("unknown option '%s'", arg);
            return LPM_ERR_USAGE;
        }
    }

    *cmd_index = i;
    return LPM_OK;
}

/* The target root must be an existing directory. */
static lpm_status validate_root(const char *root)
{
    struct stat st;

    if (root[0] == '\0') {
        lpm_error("root directory must not be empty");
        return LPM_ERR_USAGE;
    }
    if (stat(root, &st) != 0) {
        lpm_error("root directory '%s' is not accessible: %s",
                  root, strerror(errno));
        return LPM_ERR_NOT_FOUND;
    }
    if (!S_ISDIR(st.st_mode)) {
        lpm_error("root '%s' is not a directory", root);
        return LPM_ERR_INVALID;
    }
    return LPM_OK;
}

int main(int argc, char **argv)
{
    lpm_config cfg = { LPM_DEFAULT_ROOT };
    const lpm_command *cmd;
    int cmd_index = 0, early_exit = 0;
    lpm_status rc;

    rc = parse_global_options(argc, argv, &cfg, &cmd_index, &early_exit);
    if (rc != LPM_OK || early_exit) {
        if (rc == LPM_ERR_USAGE)
            lpm_print_usage_hint();
        return lpm_status_to_exit(rc);
    }

    if (cmd_index >= argc) {
        lpm_error("no command given");
        lpm_print_usage_hint();
        return lpm_status_to_exit(LPM_ERR_USAGE);
    }

    cmd = lpm_find_command(argv[cmd_index]);
    if (cmd == NULL) {
        lpm_error("unknown command '%s'", argv[cmd_index]);
        lpm_print_usage_hint();
        return lpm_status_to_exit(LPM_ERR_USAGE);
    }

    rc = validate_root(cfg.root);
    if (rc != LPM_OK)
        return lpm_status_to_exit(rc);

    rc = lpm_run_command(cmd, &cfg, argc - cmd_index, &argv[cmd_index]);
    return lpm_status_to_exit(rc);
}
