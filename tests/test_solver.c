/*
 * test_solver.c - Dependency resolution unit tests (Milestone 5).
 *
 * The solver is pure, so packages are fed to it directly (parsed from
 * metadata text, or built by hand where the parser would refuse them,
 * e.g. self-dependencies). Every successful plan is also checked against
 * the definition of a topological order: each package comes after
 * everything it depends on, and appears exactly once.
 *
 * Linked with -Wl,--wrap=malloc,calloc,realloc for failure injection.
 */
#include "solver.h"
#include "metadata.h"
#include "util.h"
#include "version.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

/* ---- allocation-failure injection ---------------------------------- */

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

static long alloc_seen, alloc_fail_at = -1;
static int inject(void) { return alloc_fail_at >= 0 && alloc_seen++ == alloc_fail_at; }
void *__wrap_malloc(size_t s) { return inject() ? NULL : __real_malloc(s); }
void *__wrap_calloc(size_t n, size_t s) { return inject() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t s) { return inject() ? NULL : __real_realloc(p, s); }

/* ---- helpers --------------------------------------------------------- */

static lpm_solver *S;
static lpm_meta_error E;

static void fresh(void)
{
    lpm_solver_free(S);
    S = NULL;
    lpm_solver_new(&S, &E);
}

/* Add "name version dep1 dep2 ..." where deps are "lib>=1.0" etc. */
static size_t pkg(const char *name, const char *version, const char *deps)
{
    char text[8192], src[160];
    lpm_package p;
    size_t idx = (size_t)-1;
    int pos;

    pos = snprintf(text, sizeof(text), "name=%s\nversion=%s\n", name, version);
    if (deps != NULL) {
        char copy[4096], *tok, *save = NULL;
        snprintf(copy, sizeof(copy), "%s", deps);
        for (tok = strtok_r(copy, " ", &save); tok; tok = strtok_r(NULL, " ", &save))
            pos += snprintf(text + pos, sizeof(text) - (size_t)pos, "depends=%s\n", tok);
    }
    if (lpm_metadata_parse_buffer(text, strlen(text), LPM_META_INSTALLED, &p, &E) != LPM_OK) {
        fprintf(stderr, "    bad test metadata: %s\n", E.message);
        return idx;
    }
    snprintf(src, sizeof(src), "%s-%s.lpm", name, version);
    if (lpm_solver_add_candidate(S, &p, src, &idx, &E) != LPM_OK && tf_verbose)
        printf("      add refused: %s\n", E.message);   /* expected in limit tests */
    return idx;
}

static void inst(const char *name, const char *version)
{
    CHECK(lpm_solver_add_installed(S, name, version, &E) == LPM_OK);
}

/* Is this a valid topological order of the plan? */
static int topologically_valid(const lpm_plan *p)
{
    size_t *at = malloc(p->count * sizeof(size_t));
    size_t i, j;
    int ok = 1;

    for (i = 0; i < p->count; i++)
        at[i] = SIZE_MAX;
    for (i = 0; i < p->order_count; i++) {
        if (at[p->order[i]] != SIZE_MAX)
            ok = 0;   /* listed twice */
        at[p->order[i]] = i;
    }
    for (i = 0; i < p->count; i++) {
        const lpm_plan_node *n = &p->nodes[i];
        if (n->kind == LPM_NODE_INSTALLED) {
            if (at[i] != SIZE_MAX)
                ok = 0;   /* installed packages are never re-installed */
            continue;
        }
        if (at[i] == SIZE_MAX)
            ok = 0;       /* every package to install is in the order */
        for (j = 0; j < n->pkg->dependency_count; j++) {
            size_t t = n->edges[j];
            if (p->nodes[t].kind == LPM_NODE_INSTALL && at[t] > at[i])
                ok = 0;   /* a dependency after its dependent */
        }
    }
    free(at);
    return ok;
}

/* "c 1.0, a 1.2, app 1.0" */
static const char *order_of(const lpm_plan *p)
{
    static char buf[16384];
    size_t i, pos = 0;

    buf[0] = '\0';
    for (i = 0; i < p->order_count && pos < sizeof(buf) - 200; i++) {
        const lpm_plan_node *n = &p->nodes[p->order[i]];
        pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, "%s%s %s", i ? ", " : "",
                                n->pkg->name, n->pkg->version);
    }
    return buf;
}

static lpm_status solve(size_t root, lpm_plan *p)
{
    lpm_status rc = lpm_solver_resolve(S, root, p, &E);
    if (tf_verbose)
        printf("      -> %s\n", rc == LPM_OK ? order_of(p) : E.message);
    if (rc == LPM_OK)
        CHECK(topologically_valid(p));
    return rc;
}

#define EXPECT_ORDER(root, text)                                     \
    do {                                                             \
        lpm_plan p_;                                                 \
        CHECK(solve(root, &p_) == LPM_OK);                           \
        CHECK(strcmp(order_of(&p_), text) == 0);                     \
        if (strcmp(order_of(&p_), text) != 0)                        \
            fprintf(stderr, "    got: %s\n", order_of(&p_));         \
        lpm_plan_free(&p_);                                          \
    } while (0)

#define EXPECT_FAIL(root, code_, fragment)                           \
    do {                                                             \
        lpm_plan p_;                                                 \
        CHECK(solve(root, &p_) == LPM_ERR_DEPENDENCY);               \
        CHECK(E.code == (code_));                                    \
        CHECK(strstr(E.message, fragment) != NULL);                  \
        if (strstr(E.message, fragment) == NULL)                     \
            fprintf(stderr, "    message: %s\n", E.message);         \
        CHECK(p_.nodes == NULL && p_.order_count == 0);              \
    } while (0)

/* Append a dependency to a candidate the parser would refuse. */
static size_t raw_pkg(const char *name, const char *version, const char *const *dn,
                      const lpm_dep_operator *ops, const char *const *dv, size_t nd)
{
    lpm_package p;
    size_t i, idx = (size_t)-1;

    lpm_package_init(&p);
    p.name = lpm_strdup(name);
    p.version = lpm_strdup(version);
    p.dependencies = nd ? calloc(nd, sizeof(*p.dependencies)) : NULL;
    for (i = 0; i < nd; i++) {
        p.dependencies[i].name = lpm_strdup(dn[i]);
        p.dependencies[i].version = lpm_strdup(dv[i]);
        p.dependencies[i].op = ops[i];
        p.dependency_count++;
    }
    lpm_solver_add_candidate(S, &p, "raw", &idx, &E);
    return idx;
}

/* ==================================================================== */
/* Basic cases                                                           */
/* ==================================================================== */

static void test_no_dependencies(void)
{
    lpm_plan p;
    size_t app;

    fresh();
    app = pkg("app", "1.0", NULL);
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(p.count == 1 && p.order_count == 1 && p.satisfied == 0);
    CHECK(strcmp(order_of(&p), "app 1.0") == 0);
    CHECK(p.nodes[0].depth == 0 && p.nodes[0].kind == LPM_NODE_INSTALL);
    lpm_plan_free(&p);
}

static void test_one_direct_dependency(void)
{
    size_t app;

    fresh();
    pkg("libfoo", "1.5", NULL);
    app = pkg("app", "1.0", "libfoo>=1.2");
    EXPECT_ORDER(app, "libfoo 1.5, app 1.0");
}

static void test_multiple_direct_dependencies(void)
{
    size_t app;

    fresh();
    pkg("zlib", "1.3", NULL);
    pkg("acl", "2.3", NULL);
    pkg("attr", "2.5", NULL);
    app = pkg("app", "1.0", "zlib>=1 acl>=2 attr=2.5");
    /* Independent dependencies keep their declaration order. */
    EXPECT_ORDER(app, "zlib 1.3, acl 2.3, attr 2.5, app 1.0");
}

static void test_transitive_dependencies(void)
{
    lpm_plan p;
    size_t app, i;

    fresh();
    pkg("d", "1", NULL);
    pkg("c", "1", "d>=1");
    pkg("b", "1", "c>=1");
    app = pkg("a", "1", "b>=1");
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(strcmp(order_of(&p), "d 1, c 1, b 1, a 1") == 0);
    for (i = 0; i < p.count; i++)   /* depth = distance: a 0, b 1, c 2, d 3 */
        CHECK(p.nodes[i].depth == (size_t)(p.nodes[i].pkg->name[0] - 'a'));
    lpm_plan_free(&p);
}

static void test_shared_dependency_diamond(void)
{
    lpm_plan p;
    size_t app, i, c_count = 0;

    fresh();
    pkg("libc", "1.0", NULL);
    pkg("liba", "1.0", "libc>=1.0");
    pkg("libb", "1.0", "libc>=1.0");
    app = pkg("app", "1.0", "liba>=1.0 libb>=1.0");
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(strcmp(order_of(&p), "libc 1.0, liba 1.0, libb 1.0, app 1.0") == 0);
    CHECK(p.count == 4);                      /* one node for libc */
    for (i = 0; i < p.order_count; i++)
        c_count += strcmp(p.nodes[p.order[i]].pkg->name, "libc") == 0;
    CHECK(c_count == 1);                      /* installed only once */
    /* Both edges to libc point at the same node. */
    CHECK(p.nodes[1].edges[0] == p.nodes[2].edges[0]);
    lpm_plan_free(&p);
}

static void test_installed_dependency_satisfies(void)
{
    lpm_plan p;
    size_t app;

    fresh();
    inst("library", "2.0");
    pkg("library", "2.5", NULL);              /* available, but no upgrades */
    app = pkg("app", "1.0", "library>=1.5");
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(strcmp(order_of(&p), "app 1.0") == 0);   /* only app is installed */
    CHECK(p.satisfied == 1 && p.count == 2);
    CHECK(p.nodes[1].kind == LPM_NODE_INSTALLED);
    CHECK(strcmp(p.nodes[1].pkg->version, "2.0") == 0 && p.nodes[1].source == NULL);
    lpm_plan_free(&p);
}

static void test_missing_dependency(void)
{
    size_t app;

    fresh();
    pkg("libfoo", "1.5", NULL);
    app = pkg("app", "1.0", "libfoo>=1.2 libbar>=2.0");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_MISSING,
                "missing dependency: libbar >= 2.0 (required by app 1.0)");
}

static void test_installed_version_too_old(void)
{
    size_t app;

    fresh();
    inst("libfoo", "1.5");
    pkg("libfoo", "2.1", NULL);   /* even with a newer candidate: no upgrades */
    app = pkg("app", "1.0", "libfoo>=2.0");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_INSTALLED,
                "required libfoo >= 2.0 (required by app 1.0); installed libfoo 1.5");
}

static void test_damaged_installed_record(void)
{
    size_t app;

    fresh();
    inst("libfoo", "?");
    app = pkg("app", "1.0", "libfoo>=1");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_INSTALLED, "installed record is damaged");
}

static void test_requested_already_installed(void)
{
    lpm_plan p;
    size_t app;

    fresh();
    inst("app", "1.0");
    app = pkg("app", "2.0", NULL);
    CHECK(solve(app, &p) == LPM_ERR_EXISTS);
    CHECK(E.code == LPM_META_ERR_DEP_ALREADY);
    CHECK(strstr(E.message, "already registered") != NULL);
}

/* ==================================================================== */
/* Graph algorithms                                                      */
/* ==================================================================== */

static void test_valid_dag_layers(void)
{
    size_t app;

    fresh();
    /* A layered DAG with edges skipping layers. */
    pkg("base", "1", NULL);
    pkg("util", "1", "base>=1");
    pkg("net", "1", "util>=1 base>=1");
    pkg("crypto", "1", "base>=1");
    pkg("tls", "1", "net>=1 crypto>=1");
    app = pkg("app", "1", "tls>=1 util>=1 base>=1");
    EXPECT_ORDER(app, "base 1, util 1, net 1, crypto 1, tls 1, app 1");
}

static void test_self_cycle(void)
{
    static const char *const dn[] = { "a" };
    static const lpm_dep_operator op[] = { LPM_DEP_MINIMUM };
    static const char *const dv[] = { "1" };
    size_t a;

    fresh();
    /* The parser rejects this (Milestone 2), so build it by hand. */
    a = raw_pkg("a", "1", dn, op, dv, 1);
    EXPECT_FAIL(a, LPM_META_ERR_DEP_CYCLE, "dependency cycle detected: a -> a");
}

static void test_two_package_cycle(void)
{
    size_t a;

    fresh();
    a = pkg("a", "1", "b>=1");
    pkg("b", "1", "a>=1");
    EXPECT_FAIL(a, LPM_META_ERR_DEP_CYCLE, "a -> b -> a");
}

static void test_three_package_cycle(void)
{
    size_t a;

    fresh();
    a = pkg("a", "1", "b>=1");
    pkg("b", "1", "c>=1");
    pkg("c", "1", "a>=1");
    EXPECT_FAIL(a, LPM_META_ERR_DEP_CYCLE, "a -> b -> c -> a");
}

static void test_larger_cycle_not_through_root(void)
{
    size_t app;

    fresh();
    app = pkg("app", "1", "p1>=1 ok>=1");
    pkg("ok", "1", NULL);
    pkg("p1", "1", "p2>=1");
    pkg("p2", "1", "p3>=1");
    pkg("p3", "1", "p4>=1");
    pkg("p4", "1", "p5>=1");
    pkg("p5", "1", "p2>=1");   /* back edge into the middle */
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CYCLE, "p2 -> p3 -> p4 -> p5 -> p2");
}

static void test_deterministic_order(void)
{
    char first[1024];
    lpm_plan p;
    size_t app;
    int round;

    /* Same packages, added in opposite orders: same plan. */
    for (round = 0; round < 2; round++) {
        fresh();
        if (round == 0) {
            pkg("x", "1", NULL); pkg("y", "1", "x>=1"); pkg("z", "1", "x>=1");
            app = pkg("app", "1", "z>=1 y>=1");
        } else {
            app = pkg("app", "1", "z>=1 y>=1");
            pkg("z", "1", "x>=1"); pkg("y", "1", "x>=1"); pkg("x", "1", NULL);
        }
        CHECK(solve(app, &p) == LPM_OK);
        if (round == 0)
            snprintf(first, sizeof(first), "%s", order_of(&p));
        else
            CHECK(strcmp(first, order_of(&p)) == 0);
        lpm_plan_free(&p);
    }
    CHECK(strcmp(first, "x 1, z 1, y 1, app 1") == 0);
}

static void test_duplicate_references(void)
{
    static const char *const dn[] = { "lib", "lib" };
    static const lpm_dep_operator op[] = { LPM_DEP_MINIMUM, LPM_DEP_BELOW };
    static const char *const dv[] = { "1", "3" };
    lpm_plan p;
    size_t app;

    fresh();
    /* Many packages referencing one: a single node. */
    pkg("lib", "2", NULL);
    pkg("m1", "1", "lib>=1");
    pkg("m2", "1", "lib>=2");
    pkg("m3", "1", "lib=2");
    app = pkg("app", "1", "m1>=1 m2>=1 m3>=1 lib<3");
    EXPECT_ORDER(app, "lib 2, m1 1, m2 1, m3 1, app 1");

    /* Two depends= on one name in one package (the parser forbids it;
     * the solver still treats both as constraints on one node). */
    fresh();
    pkg("lib", "4", NULL);
    pkg("lib", "2", NULL);
    app = raw_pkg("app", "1", dn, op, dv, 2);
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(p.count == 2 && strcmp(order_of(&p), "lib 2, app 1") == 0);
    CHECK(p.nodes[0].edges[0] == p.nodes[0].edges[1]);
    lpm_plan_free(&p);
}

/* ==================================================================== */
/* Version constraints                                                   */
/* ==================================================================== */

static void three_libs(void)
{
    pkg("lib", "1.0", NULL);
    pkg("lib", "2.0", NULL);
    pkg("lib", "3.0", NULL);
}

static void test_exact_version(void)
{
    size_t app;
    fresh(); three_libs();
    app = pkg("app", "1", "lib=2.0");
    EXPECT_ORDER(app, "lib 2.0, app 1");
    fresh(); three_libs();
    app = pkg("app", "1", "lib=2");          /* numeric equality: 2 == 2.0 */
    EXPECT_ORDER(app, "lib 2.0, app 1");
    fresh(); three_libs();
    app = pkg("app", "1", "lib=2.5");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CONFLICT, "available versions of lib: 3.0, 2.0, 1.0");
}

static void test_minimum_version_prefers_highest(void)
{
    size_t app;
    fresh(); three_libs();
    app = pkg("app", "1", "lib>=2.0");
    EXPECT_ORDER(app, "lib 3.0, app 1");
}

static void test_maximum_version(void)
{
    size_t app;
    fresh(); three_libs();
    app = pkg("app", "1", "lib<3.0");
    EXPECT_ORDER(app, "lib 2.0, app 1");          /* strict: 3.0 excluded */
    fresh(); three_libs();
    app = pkg("app", "1", "lib<1.0");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CONFLICT, "lib < 1.0");
    fresh(); three_libs();
    app = pkg("app", "1", "lib>=1.5 lib2<9");
    pkg("lib2", "10", NULL);
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CONFLICT, "lib2 < 9");
}

static void test_conflicting_requirements(void)
{
    size_t app;

    /* Scenario D: A needs lib >= 3.0, B needs lib < 2.0. */
    fresh();
    pkg("library", "1.0", NULL);
    pkg("library", "3.1", NULL);
    pkg("a", "1.0", "library>=3.0");
    pkg("b", "1.0", "library<2.0");
    app = pkg("app", "1.0", "a>=1 b>=1");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CONFLICT, "library < 2.0 (required by b 1.0)");
    CHECK(strstr(E.message, "library >= 3.0 (required by a 1.0)") != NULL);
    CHECK(strstr(E.message, "available versions of library: 3.1, 1.0") != NULL);
}

static void test_multiple_versions_combined_constraints(void)
{
    size_t app;

    fresh();
    pkg("lib", "1", NULL); pkg("lib", "2", NULL);
    pkg("lib", "3", NULL); pkg("lib", "4", NULL);
    pkg("a", "1", "lib>=2");
    pkg("b", "1", "lib<4");
    app = pkg("app", "1", "a>=1 b>=1");
    /* Highest version that every requirement accepts. */
    EXPECT_ORDER(app, "lib 3, a 1, b 1, app 1");
}

static void test_backtracking_finds_global_solution(void)
{
    lpm_plan p;
    size_t app;

    /* Greedy "highest version" picks tool 2, which needs core = 1; but
     * plugin needs core = 2. Only tool 1 works with that: the solver
     * must go back and change its earlier choice. */
    fresh();
    pkg("tool", "2", "core=1");
    pkg("tool", "1", "core=2");
    pkg("plugin", "1", "core=2");
    pkg("core", "1", NULL);
    pkg("core", "2", NULL);
    app = pkg("app", "1", "tool>=1 plugin>=1");
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(strcmp(order_of(&p), "core 2, tool 1, plugin 1, app 1") == 0);
    CHECK(p.steps > 4);   /* it really backtracked */
    lpm_plan_free(&p);
}

static void test_globally_incompatible_combination(void)
{
    size_t app;

    /* Every version of tool needs core = 1, plugin needs core = 2: no
     * combination works, and no partial plan may be returned. */
    fresh();
    pkg("tool", "2", "core=1");
    pkg("tool", "1", "core=1");
    pkg("plugin", "1", "core=2");
    pkg("core", "1", NULL);
    pkg("core", "2", NULL);
    app = pkg("app", "1", "tool>=1 plugin>=1");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_CONFLICT, "core");
}

static void test_duplicate_candidates(void)
{
    size_t app;

    fresh();
    pkg("lib", "1.0", NULL);
    pkg("lib", "1.0.0", NULL);   /* numerically the same version */
    app = pkg("app", "1", "lib>=1");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_DUPLICATE, "two candidates for lib");
}

/* ==================================================================== */
/* Resource handling and malformed input                                 */
/* ==================================================================== */

static void test_only_requested_package_available(void)
{
    size_t app;

    fresh();   /* like an empty package directory */
    app = pkg("app", "1", "liba>=1");
    EXPECT_FAIL(app, LPM_META_ERR_DEP_MISSING, "liba >= 1");
}

static void test_malformed_candidates_rejected(void)
{
    static const char *const bad_name[] = { "Bad Name" };
    static const char *const ok_name[] = { "lib" };
    static const char *const bad_ver[] = { "1..0" };
    static const char *const ok_ver[] = { "1" };
    static const lpm_dep_operator ge[] = { LPM_DEP_MINIMUM };
    static const lpm_dep_operator bad_op[] = { (lpm_dep_operator)9 };
    lpm_package p;

    fresh();
    CHECK(raw_pkg("app", "1", bad_name, ge, ok_ver, 1) == (size_t)-1);
    CHECK(E.code == LPM_META_ERR_INVALID_VALUE);
    CHECK(raw_pkg("app", "1", ok_name, ge, bad_ver, 1) == (size_t)-1);
    CHECK(raw_pkg("app", "1", ok_name, bad_op, ok_ver, 1) == (size_t)-1);
    CHECK(raw_pkg("app", "01", NULL, NULL, NULL, 0) == (size_t)-1);
    CHECK(raw_pkg("../x", "1", NULL, NULL, NULL, 0) == (size_t)-1);
    CHECK(lpm_solver_add_installed(S, "bad/name", "1", &E) == LPM_ERR_INVALID);
    /* A failed add still takes (and frees) the package: no leak. */
    lpm_package_init(&p);
    p.name = lpm_strdup("x");
    p.version = lpm_strdup("v1");
    CHECK(lpm_solver_add_candidate(S, &p, "x", NULL, &E) == LPM_ERR_INVALID);
    CHECK(p.name == NULL);
    /* Resolving something that is not a candidate. */
    {
        lpm_plan pl;
        CHECK(lpm_solver_resolve(S, 999, &pl, &E) == LPM_ERR_USAGE);
    }
}

static void test_large_valid_graph(void)
{
    char name[32], dep[48];
    lpm_plan p;
    size_t i, app, n = LPM_SOLVER_MAX_NODES;

    /* A chain of 1024 packages: depth 1023, far deeper than a recursive
     * DFS should be trusted with; the traversal is iterative. */
    fresh();
    for (i = 0; i < n; i++) {   /* p0000 -> p0001 -> ... -> p1023 */
        snprintf(name, sizeof(name), "p%04zu", i);
        snprintf(dep, sizeof(dep), "p%04zu>=1", i + 1);
        pkg(name, "1", i + 1 < n ? dep : NULL);
    }
    app = 0;   /* p0000 was added first */
    CHECK(solve(app, &p) == LPM_OK);
    CHECK(p.count == n && p.order_count == n);
    CHECK(strcmp(p.nodes[p.order[0]].pkg->name, "p1023") == 0);
    CHECK(strcmp(p.nodes[p.order[n - 1]].pkg->name, "p0000") == 0);
    CHECK(p.nodes[p.order[0]].depth == n - 1);
    lpm_plan_free(&p);

    /* A wide graph: 500 leaves, each also needed by a shared hub. */
    fresh();
    {
        char deps[8192] = "";
        for (i = 0; i < 500; i++) {
            snprintf(name, sizeof(name), "leaf%03zu", i);
            pkg(name, "1", NULL);
        }
        for (i = 0; i < 100; i++) {
            snprintf(dep, sizeof(dep), "%sleaf%03zu>=1", i ? " " : "", i);
            strcat(deps, dep);
        }
        pkg("hub", "1", deps);
        deps[0] = '\0';
        for (i = 0; i < 100; i++) {
            snprintf(dep, sizeof(dep), " leaf%03zu>=1", 400 + i);
            strcat(deps, dep);
        }
        {
            char all[8200];   /* "hub>=1" + deps */
            snprintf(all, sizeof(all), "hub>=1%s", deps);
            app = pkg("app", "1", all);
        }
        CHECK(solve(app, &p) == LPM_OK);
        CHECK(p.count == 202 && p.order_count == 202);   /* app, hub, 200 leaves */
        lpm_plan_free(&p);
    }
}

static void test_limits_exceeded(void)
{
    char name[32], dep[48];
    lpm_plan p;
    size_t i, n = LPM_SOLVER_MAX_NODES + 1;

    /* One package more than a plan may hold. */
    fresh();
    for (i = 0; i < n; i++) {
        snprintf(name, sizeof(name), "p%04zu", i);
        snprintf(dep, sizeof(dep), "p%04zu>=1", i + 1);
        pkg(name, "1", i + 1 < n ? dep : NULL);
    }
    CHECK(solve(0, &p) == LPM_ERR_DEPENDENCY);
    CHECK(E.code == LPM_META_ERR_DEP_LIMIT);

    /* More candidates than the solver accepts. */
    fresh();
    for (i = 0; i < LPM_SOLVER_MAX_PACKAGES; i++) {
        snprintf(name, sizeof(name), "c%05zu", i);
        if (pkg(name, "1", NULL) == (size_t)-1)
            break;
    }
    CHECK(i == LPM_SOLVER_MAX_PACKAGES);
    CHECK(pkg("onemore", "1", NULL) == (size_t)-1);
    CHECK(E.code == LPM_META_ERR_DEP_LIMIT);

    /* An exponential search: 20 names with 2 versions each, and a final
     * requirement no combination meets. The step budget stops it. */
    fresh();
    {
        char deps[2048] = "";
        for (i = 0; i < 20; i++) {
            snprintf(name, sizeof(name), "x%02zu", i);
            pkg(name, "1", NULL);
            pkg(name, "2", NULL);
            snprintf(dep, sizeof(dep), "%s>=1 ", name);
            strcat(deps, dep);
        }
        strcat(deps, "z>=1");
        pkg("z", "1", "x00=3");
        CHECK(solve(pkg("app", "1", deps), &p) == LPM_ERR_DEPENDENCY);
        CHECK(E.code == LPM_META_ERR_DEP_LIMIT);
        CHECK(strstr(E.message, "gave up") != NULL);
    }
}

static void test_allocation_failures(void)
{
    long n;
    int completed = 0;

    for (n = 0; n < 2000 && !completed; n++) {
        lpm_plan p;
        lpm_status rc;
        size_t app;

        fresh();
        pkg("libc", "1.0", NULL);
        pkg("liba", "1.0", "libc>=1.0");
        pkg("libb", "1.0", "libc>=1.0");
        app = pkg("app", "1.0", "liba>=1.0 libb>=1.0");
        alloc_seen = 0;
        alloc_fail_at = n;
        rc = lpm_solver_resolve(S, app, &p, &E);
        alloc_fail_at = -1;
        if (rc == LPM_OK) {
            CHECK(strcmp(order_of(&p), "libc 1.0, liba 1.0, libb 1.0, app 1.0") == 0);
            completed = 1;
        } else {
            CHECK(rc == LPM_ERR_NOMEM && E.code == LPM_META_ERR_NOMEM);
            CHECK(p.nodes == NULL && p.order == NULL);
        }
        lpm_plan_free(&p);   /* LeakSanitizer catches anything missed */
    }
    CHECK(completed);
}

static void test_less_than_operator_parses(void)
{
    static const char ok_text[] = "name=a\nversion=1\ndepends=lib<2.0\n";
    static const char le_text[] = "name=a\nversion=1\ndepends=lib<=2\n";
    lpm_package p;
    lpm_dependency d;
    bool ok;

    CHECK(lpm_metadata_parse_buffer(ok_text, strlen(ok_text),
                                    LPM_META_INSTALLED, &p, &E) == LPM_OK);
    CHECK(p.dependency_count == 1 && p.dependencies[0].op == LPM_DEP_BELOW);
    CHECK(strcmp(lpm_dep_operator_str(p.dependencies[0].op), "<") == 0);
    lpm_package_free(&p);
    /* "<=" and ">" stay unsupported */
    CHECK(lpm_metadata_parse_buffer(le_text, strlen(le_text),
                                    LPM_META_INSTALLED, &p, &E) == LPM_ERR_INVALID);
    d.name = (char *)"lib";
    d.op = LPM_DEP_BELOW;
    d.version = (char *)"2.0";
    CHECK(lpm_version_satisfies("1.9.9", &d, &ok) == LPM_OK && ok);
    CHECK(lpm_version_satisfies("2", &d, &ok) == LPM_OK && !ok);   /* 2 == 2.0 */
    CHECK(lpm_version_satisfies("10", &d, &ok) == LPM_OK && !ok);
}

int main(int argc, char **argv)
{
    int rc = tf_parse_args(argc, argv);
    if (rc != 0)
        return rc;

    printf("Running dependency solver unit tests\n");
    RUN(test_no_dependencies);
    RUN(test_one_direct_dependency);
    RUN(test_multiple_direct_dependencies);
    RUN(test_transitive_dependencies);
    RUN(test_shared_dependency_diamond);
    RUN(test_installed_dependency_satisfies);
    RUN(test_missing_dependency);
    RUN(test_installed_version_too_old);
    RUN(test_damaged_installed_record);
    RUN(test_requested_already_installed);
    RUN(test_valid_dag_layers);
    RUN(test_self_cycle);
    RUN(test_two_package_cycle);
    RUN(test_three_package_cycle);
    RUN(test_larger_cycle_not_through_root);
    RUN(test_deterministic_order);
    RUN(test_duplicate_references);
    RUN(test_exact_version);
    RUN(test_minimum_version_prefers_highest);
    RUN(test_maximum_version);
    RUN(test_conflicting_requirements);
    RUN(test_multiple_versions_combined_constraints);
    RUN(test_backtracking_finds_global_solution);
    RUN(test_globally_incompatible_combination);
    RUN(test_duplicate_candidates);
    RUN(test_only_requested_package_available);
    RUN(test_malformed_candidates_rejected);
    RUN(test_large_valid_graph);
    RUN(test_limits_exceeded);
    RUN(test_allocation_failures);
    RUN(test_less_than_operator_parses);
    lpm_solver_free(S);
    return tf_summary();
}
