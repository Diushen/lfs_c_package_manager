/*
 * commands.h - The command table and one handler per CLI command.
 *
 * main.c only parses global options and dispatches; all command
 * behaviour lives behind this interface.
 */
#ifndef LPM_COMMANDS_H
#define LPM_COMMANDS_H

#include "lpm.h"

/*
 * A command handler receives the command's own arguments
 * (argv[0] is the command name, like a tiny main()).
 */
typedef lpm_status (*lpm_cmd_fn)(const lpm_config *cfg, int argc, char **argv);

typedef struct {
    const char *name;       /* e.g. "list"                          */
    const char *usage;      /* argument synopsis, e.g. "<file.pkg>"  */
    const char *summary;    /* one-line description for help         */
    int min_args;           /* arguments after the command name      */
    int max_args;
    int implemented;        /* 0 = planned for a later milestone     */
    lpm_cmd_fn fn;
} lpm_command;

/* Look up a command by name; NULL if unknown. */
const lpm_command *lpm_find_command(const char *name);

/* Print the full help text to stdout. */
void lpm_print_help(void);

/* Print the short usage line to stderr (used on usage errors). */
void lpm_print_usage_hint(void);

/* Validate argument count, then run the handler. */
lpm_status lpm_run_command(const lpm_command *cmd, const lpm_config *cfg,
                           int argc, char **argv);

#endif /* LPM_COMMANDS_H */
