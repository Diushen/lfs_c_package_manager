/*
 * plan.h - Turn a request into a dependency plan (Milestone 5).
 *
 * Gathers the solver's input and runs it:
 *   - installed packages: the database under cfg->root (read only);
 *   - the requested package file;
 *   - optionally every *.lpm file in a local package directory.
 * Only metadata.txt of each candidate is read here (pkg.h); a plan is a
 * proposal, not a verification. Nothing is written anywhere.
 */
#ifndef LPM_PLAN_H
#define LPM_PLAN_H

#include <stdbool.h>
#include "lpm.h"
#include "metadata.h"
#include "solver.h"

#define LPM_PKGDIR_MAX_FILES  LPM_SOLVER_MAX_PACKAGES

/* A plan together with the solver that owns its packages. */
typedef struct {
    lpm_solver *solver;
    lpm_plan plan;
} lpm_resolution;

/*
 * Resolve pkg_path against the installed database and, if package_dir
 * is not NULL, the candidates found there. With db_locked the caller
 * already holds the database lock (the installer); otherwise a shared
 * lock is taken while the installed set is read.
 *
 * Errors: LPM_ERR_DEPENDENCY (see solver.h), and for an unreadable or
 * invalid requested/candidate package the error of reading it, with the
 * file named in the message. On failure *out is empty.
 */
lpm_status lpm_resolve_request(const lpm_config *cfg, const char *pkg_path,
                               const char *package_dir, bool db_locked,
                               lpm_resolution *out, lpm_meta_error *err);

void lpm_resolution_free(lpm_resolution *r);   /* safe on an empty one */

#endif /* LPM_PLAN_H */
