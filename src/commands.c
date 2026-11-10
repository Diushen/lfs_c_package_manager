/*
 * commands.c - Command table and handlers.
 *
 * Adding a command = writing a handler + adding one row to the table.
 * help output and argument-count checking are driven by the table, so
 * they can never drift out of sync with the real commands.
 */
#include "commands.h"
#include "database.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static lpm_status cmd_help(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_version(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_list(const lpm_config *cfg, int argc, char **argv);
static lpm_status cmd_not_implemented(const lpm_config *cfg, int argc, char **argv);

static const lpm_command commands[] = {
    /* name      usage           summary                                 min max impl handler */
    { "help",    "",             "Show this help",                         0, 0, 1, cmd_help },
    { "version", "",             "Show version information",               0, 0, 1, cmd_version },
    { "list",    "",             "List installed packages",                0, 0, 1, cmd_list },
    { "info",    "<package>",    "Show details of an installed package",   1, 1, 0, cmd_not_implemented },
    { "verify",  "<file.pkg>",   "Verify a package's checksum/signature",  1, 1, 0, cmd_not_implemented },
    { "install", "<file.pkg>",   "Install a local package archive",        1, 1, 0, cmd_not_implemented },
    { "remove",  "<package>",    "Remove an installed package",            1, 1, 0, cmd_not_implemented },
    { "check",   "",             "Check database consistency",             0, 0, 0, cmd_not_implemented },
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
        char synopsis[64];
        snprintf(synopsis, sizeof(synopsis), "%s %s",
                 commands[i].name, commands[i].usage);
        printf("  %-22s %s%s\n", synopsis, commands[i].summary,
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

static lpm_status cmd_not_implemented(const lpm_config *cfg, int argc, char **argv)
{
    (void)cfg; (void)argc;
    lpm_error("'%s' is not implemented yet in LPM %s", argv[0], LPM_VERSION);
    return LPM_ERR_NOT_IMPLEMENTED;
}
