/*
 * solver.h - Dependency resolution on a directed graph (Milestone 5).
 *
 * The solver is pure: it reads no files and writes nothing. It is given
 *   - candidates: packages that could be installed (lpm_package +
 *     the archive they came from), and
 *   - installed packages: name + version from the database,
 * and computes a plan for one requested candidate.
 *
 * 1. Selection (which version of each package?)
 *    Names are processed in discovery order (the requested package, then
 *    its dependencies in declaration order, then theirs, ...). For each
 *    name the options are tried from the highest version down:
 *      - an installed package is the only option for its name (LPM does
 *        not upgrade), so it must satisfy every constraint on it;
 *      - a candidate must satisfy every constraint already placed on its
 *        name, and its own constraints must hold for every name already
 *        chosen.
 *    When a name has no acceptable option, the search goes back to the
 *    previous name and tries its next version (backtracking). So the
 *    result is globally consistent: every constraint in the plan holds
 *    for the one version selected for each name. The search is bounded
 *    by LPM_SOLVER_MAX_STEPS candidate attempts; the policy prefers the
 *    highest compatible version of each name, earliest-discovered first.
 *
 * 2. Graph: one node per selected package, adjacency lists with one
 *    edge per depends= line (edge j of a node corresponds to
 *    pkg->dependencies[j]). Installed nodes are leaves: their own
 *    dependencies were dealt with when they were installed.
 *
 * 3. Cycle detection and topological order: one iterative depth-first
 *    search from the requested package with three colours (WHITE =
 *    unvisited, GRAY = on the current path, BLACK = finished). Meeting a
 *    GRAY node means a cycle, reported as "a -> b -> c -> a". Nodes are
 *    appended to the order when they turn BLACK (post-order), so every
 *    package comes after all of its dependencies. O(V + E) time and
 *    O(V) extra space; iterative, so deep graphs cannot overflow the
 *    C stack.
 *
 * Determinism: the same inputs always give the same plan, because the
 * discovery order, the version order and the DFS edge order are fixed.
 */
#ifndef LPM_SOLVER_H
#define LPM_SOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include "lpm.h"
#include "metadata.h"

#define LPM_SOLVER_MAX_PACKAGES  4096     /* candidates + installed      */
#define LPM_SOLVER_MAX_NODES     1024     /* packages in one plan        */
#define LPM_SOLVER_MAX_STEPS     100000   /* candidate attempts (search) */

typedef struct lpm_solver lpm_solver;   /* opaque */

typedef enum {
    LPM_NODE_INSTALL,     /* will be installed, from node.source   */
    LPM_NODE_INSTALLED    /* already installed: satisfies its edges */
} lpm_node_kind;

typedef struct {
    const lpm_package *pkg;   /* owned by the solver; INSTALLED: no deps */
    const char *source;       /* archive path; NULL for INSTALLED      */
    lpm_node_kind kind;
    size_t depth;             /* shortest path from the request: 0, 1 = direct */
    size_t *edges;            /* edges[j] satisfies pkg->dependencies[j] */
} lpm_plan_node;

/*
 * A resolved plan. nodes[0] is the requested package. Borrows from the
 * solver: free the plan (lpm_plan_free) before the solver.
 */
typedef struct {
    lpm_plan_node *nodes;
    size_t count;
    size_t *order;           /* INSTALL nodes, dependencies first */
    size_t order_count;
    size_t satisfied;        /* INSTALLED nodes the plan relies on */
    size_t steps;            /* candidate attempts the search needed */
} lpm_plan;

lpm_status lpm_solver_new(lpm_solver **out, lpm_meta_error *err);
void lpm_solver_free(lpm_solver *s);   /* safe on NULL */

/*
 * Add a candidate. Takes ownership of *pkg (left empty) whether or not
 * this succeeds; source is copied. *index (optional) identifies it for
 * lpm_solver_resolve(). The name, version and every dependency must be
 * valid (LPM_ERR_INVALID otherwise). LPM_ERR_DEPENDENCY
 * (LPM_META_ERR_DEP_LIMIT) beyond LPM_SOLVER_MAX_PACKAGES.
 */
lpm_status lpm_solver_add_candidate(lpm_solver *s, lpm_package *pkg,
                                    const char *source, size_t *index,
                                    lpm_meta_error *err);

/* Add an installed package. version "?" marks a damaged record (it can
 * satisfy nothing, and depending on it is reported as such). */
lpm_status lpm_solver_add_installed(lpm_solver *s, const char *name,
                                    const char *version, lpm_meta_error *err);

/*
 * Resolve the candidate `root`. LPM_OK: *out is a valid plan.
 * Otherwise LPM_ERR_DEPENDENCY with err->code one of
 *   LPM_META_ERR_DEP_MISSING    nothing provides a required package
 *   LPM_META_ERR_DEP_INSTALLED  the installed version does not fit
 *   LPM_META_ERR_DEP_CONFLICT   no single version satisfies all demands
 *   LPM_META_ERR_DEP_CYCLE      circular dependency (path in message)
 *   LPM_META_ERR_DEP_DUPLICATE  two candidates with the same name+version
 *   LPM_META_ERR_DEP_LIMIT      size or search limit exceeded
 * or LPM_ERR_EXISTS (LPM_META_ERR_DEP_ALREADY) if the requested package
 * is already installed, or LPM_ERR_NOMEM / LPM_ERR_USAGE. *out is empty on failure.
 * Several failures are possible during a search; the first one met in
 * the deterministic search order is reported.
 */
lpm_status lpm_solver_resolve(lpm_solver *s, size_t root, lpm_plan *out,
                              lpm_meta_error *err);

void lpm_plan_free(lpm_plan *p);   /* safe on an empty plan */

#endif /* LPM_SOLVER_H */
