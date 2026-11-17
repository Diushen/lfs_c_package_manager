/*
 * solver.c - Candidate selection, dependency graph, cycle detection and
 * topological sort (algorithms described in solver.h).
 *
 * Memory: the solver owns every package added to it. lpm_solver_resolve()
 * allocates only working arrays (all freed before it returns) plus the
 * plan's node, edge and order arrays (freed by lpm_plan_free()).
 */
#include "solver.h"
#include "util.h"
#include "version.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NONE SIZE_MAX

typedef struct {
    lpm_package pkg;      /* installed: name + version, no dependencies */
    char *source;         /* NULL for installed                          */
    bool installed;
    bool damaged;         /* installed record without a usable version   */
    size_t name;          /* index into the name table (set by resolve)  */
} entry;

struct lpm_solver {
    entry *e;
    size_t n, cap;
};

static lpm_status nomem(lpm_meta_error *err)
{
    lpm_meta_error_set(err, LPM_META_ERR_NOMEM, 0, NULL, "out of memory");
    return LPM_ERR_NOMEM;
}

lpm_status lpm_solver_new(lpm_solver **out, lpm_meta_error *err)
{
    *out = calloc(1, sizeof(**out));
    return *out ? LPM_OK : nomem(err);
}

void lpm_solver_free(lpm_solver *s)
{
    size_t i;

    if (s == NULL)
        return;
    for (i = 0; i < s->n; i++) {
        lpm_package_free(&s->e[i].pkg);
        free(s->e[i].source);
    }
    free(s->e);
    free(s);
}

static lpm_status grow(lpm_solver *s, lpm_meta_error *err)
{
    entry *g;
    size_t cap;

    if (s->n >= LPM_SOLVER_MAX_PACKAGES) {
        lpm_meta_error_set(err, LPM_META_ERR_DEP_LIMIT, 0, NULL,
                           "more than %d packages to consider", LPM_SOLVER_MAX_PACKAGES);
        return LPM_ERR_DEPENDENCY;
    }
    if (s->n < s->cap)
        return LPM_OK;
    cap = s->cap ? s->cap * 2 : 16;
    g = realloc(s->e, cap * sizeof(*g));   /* cap <= 2 * 4096: no overflow */
    if (g == NULL)
        return nomem(err);
    s->e = g;
    s->cap = cap;
    return LPM_OK;
}

lpm_status lpm_solver_add_candidate(lpm_solver *s, lpm_package *pkg,
                                    const char *source, size_t *index,
                                    lpm_meta_error *err)
{
    entry *e;
    char *src;
    size_t i;
    lpm_status rc;

    if (!lpm_is_valid_package_name(pkg->name) || !lpm_is_valid_version(pkg->version)) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, NULL,
                           "candidate has an invalid name or version");
        lpm_package_free(pkg);
        return LPM_ERR_INVALID;
    }
    for (i = 0; i < pkg->dependency_count; i++) {
        const lpm_dependency *d = &pkg->dependencies[i];
        if (!lpm_is_valid_package_name(d->name) || !lpm_is_valid_version(d->version) ||
            (d->op != LPM_DEP_EXACT && d->op != LPM_DEP_MINIMUM && d->op != LPM_DEP_BELOW)) {
            lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, "depends",
                               "candidate %s %s has a malformed dependency",
                               pkg->name, pkg->version);
            lpm_package_free(pkg);
            return LPM_ERR_INVALID;
        }
    }
    rc = grow(s, err);
    src = rc == LPM_OK ? lpm_strdup(source ? source : "") : NULL;
    if (rc == LPM_OK && src == NULL)
        rc = nomem(err);
    if (rc != LPM_OK) {
        lpm_package_free(pkg);
        return rc;
    }
    e = &s->e[s->n];
    e->pkg = *pkg;
    lpm_package_init(pkg);
    e->source = src;
    e->installed = false;
    e->damaged = false;
    e->name = NONE;
    if (index != NULL)
        *index = s->n;
    s->n++;
    return LPM_OK;
}

lpm_status lpm_solver_add_installed(lpm_solver *s, const char *name,
                                    const char *version, lpm_meta_error *err)
{
    entry *e;
    lpm_status rc;

    if (!lpm_is_valid_package_name(name) || version == NULL) {
        lpm_meta_error_set(err, LPM_META_ERR_INVALID_VALUE, 0, NULL,
                           "installed package has an invalid name");
        return LPM_ERR_INVALID;
    }
    rc = grow(s, err);
    if (rc != LPM_OK)
        return rc;
    e = &s->e[s->n];
    lpm_package_init(&e->pkg);
    e->pkg.name = lpm_strdup(name);
    e->pkg.version = lpm_strdup(version);
    if (e->pkg.name == NULL || e->pkg.version == NULL) {
        lpm_package_free(&e->pkg);
        return nomem(err);
    }
    e->source = NULL;
    e->installed = true;
    e->damaged = !lpm_is_valid_version(version);
    e->name = NONE;
    s->n++;
    return LPM_OK;
}

/* ==================================================================== */
/* Resolution working state                                              */
/* ==================================================================== */

/* One constraint placed on a name by a selected package. */
typedef struct {
    size_t from;          /* entry that declares it          */
    size_t dep;           /* index into its dependencies     */
    size_t prev;          /* previous constraint on the name */
    size_t name;          /* the name it constrains          */
} constraint;

typedef struct {
    size_t next;          /* next option to try for this agenda slot */
    size_t agenda_before; /* agenda length before this choice        */
    size_t cons_before;   /* constraint stack height before it       */
} frame;

typedef struct {
    lpm_solver *s;
    const char **names;   /* sorted, unique                          */
    size_t nnames;
    size_t *installed;    /* per name: installed entry or NONE       */
    size_t *opt_start, *opt_count, *opts;   /* candidates, newest first */
    size_t *chosen;       /* per name: selected entry or NONE        */
    size_t *in_agenda;    /* per name: agenda position or NONE       */
    size_t *head;         /* per name: newest constraint or NONE     */
    size_t *agenda;       /* name ids, discovery order               */
    size_t alen;
    frame *frames;
    constraint *cons;
    size_t ncons, cons_cap;
    size_t root, steps;
    lpm_meta_error first;  /* first failure met in search order */
    bool have_first;
    lpm_meta_error *err;
} search;

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static size_t name_id(const search *x, const char *name)
{
    size_t lo = 0, hi = x->nnames;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(x->names[mid], name);
        if (c == 0)
            return mid;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NONE;   /* unreachable: every referenced name is in the table */
}

/* Version comparison for sorting options newest first. */
static const lpm_solver *sort_solver;   /* qsort has no context argument */
static int cmp_newest_first(const void *pa, const void *pb)
{
    const entry *a = &sort_solver->e[*(const size_t *)pa];
    const entry *b = &sort_solver->e[*(const size_t *)pb];
    int c = 0;

    (void)lpm_version_compare(a->pkg.version, b->pkg.version, &c);
    if (c != 0)
        return -c;
    return strcmp(a->source, b->source);   /* only for equal versions */
}

static bool sat(const char *version, const lpm_dependency *d)
{
    bool ok = false;
    return lpm_version_satisfies(version, d, &ok) == LPM_OK && ok;
}

static void dep_text(char *buf, size_t size, const lpm_dependency *d)
{
    snprintf(buf, size, "%s %s %s", d->name, lpm_dep_operator_str(d->op), d->version);
}

/* ---- setting up ------------------------------------------------------- */

static lpm_status build_tables(search *x)
{
    lpm_solver *s = x->s;
    size_t total = 0, i, j, k, u;
    const char **all;

    for (i = 0; i < s->n; i++)
        total += 1 + s->e[i].pkg.dependency_count;   /* <= 4096 * 129 */
    all = malloc(total * sizeof(*all));
    if (all == NULL)
        return nomem(x->err);
    k = 0;
    for (i = 0; i < s->n; i++) {
        all[k++] = s->e[i].pkg.name;
        for (j = 0; j < s->e[i].pkg.dependency_count; j++)
            all[k++] = s->e[i].pkg.dependencies[j].name;
    }
    qsort(all, total, sizeof(*all), cmp_str);
    for (i = 0, u = 0; i < total; i++)
        if (u == 0 || strcmp(all[u - 1], all[i]) != 0)
            all[u++] = all[i];
    x->names = all;
    x->nnames = u;

    x->installed = malloc(u * sizeof(size_t));
    x->opt_start = calloc(u, sizeof(size_t));
    x->opt_count = calloc(u, sizeof(size_t));
    x->opts = malloc((s->n ? s->n : 1) * sizeof(size_t));
    x->chosen = malloc(u * sizeof(size_t));
    x->in_agenda = malloc(u * sizeof(size_t));
    x->head = malloc(u * sizeof(size_t));
    x->agenda = malloc(LPM_SOLVER_MAX_NODES * sizeof(size_t));
    x->frames = malloc((LPM_SOLVER_MAX_NODES + 1) * sizeof(frame));
    if (!x->installed || !x->opt_start || !x->opt_count || !x->opts || !x->chosen ||
        !x->in_agenda || !x->head || !x->agenda || !x->frames)
        return nomem(x->err);
    for (i = 0; i < u; i++)
        x->installed[i] = x->chosen[i] = x->in_agenda[i] = x->head[i] = NONE;

    /* Group candidates by name (counting sort), then newest first. */
    for (i = 0; i < s->n; i++) {
        s->e[i].name = name_id(x, s->e[i].pkg.name);
        if (s->e[i].installed) {
            if (x->installed[s->e[i].name] != NONE) {
                lpm_meta_error_set(x->err, LPM_META_ERR_DEP_DUPLICATE, 0, NULL,
                                   "package '%s' is recorded as installed twice",
                                   s->e[i].pkg.name);
                return LPM_ERR_DEPENDENCY;
            }
            x->installed[s->e[i].name] = i;
        } else {
            x->opt_count[s->e[i].name]++;
        }
    }
    for (i = 1; i < u; i++)
        x->opt_start[i] = x->opt_start[i - 1] + x->opt_count[i - 1];
    {
        size_t *fill = calloc(u, sizeof(size_t));
        if (fill == NULL)
            return nomem(x->err);
        for (i = 0; i < s->n; i++)
            if (!s->e[i].installed) {
                size_t n = s->e[i].name;
                x->opts[x->opt_start[n] + fill[n]++] = i;
            }
        free(fill);
    }
    sort_solver = s;
    for (i = 0; i < u; i++) {
        size_t *o = x->opts + x->opt_start[i];
        if (x->opt_count[i] > 1)
            qsort(o, x->opt_count[i], sizeof(*o), cmp_newest_first);
        /* Two candidates for one name+version are ambiguous: which file
         * would be installed? Refuse rather than pick one. */
        for (j = 1; j < x->opt_count[i]; j++) {
            int c = 1;
            (void)lpm_version_compare(s->e[o[j - 1]].pkg.version,
                                      s->e[o[j]].pkg.version, &c);
            if (c == 0) {
                lpm_meta_error_set(x->err, LPM_META_ERR_DEP_DUPLICATE, 0, NULL,
                                   "two candidates for %s %s: %.90s and %.90s",
                                   s->e[o[j]].pkg.name, s->e[o[j]].pkg.version,
                                   s->e[o[j - 1]].source, s->e[o[j]].source);
                return LPM_ERR_DEPENDENCY;
            }
        }
    }
    return LPM_OK;
}

/* ---- the search -------------------------------------------------------- */

static lpm_status push_constraint(search *x, size_t from, size_t dep, size_t name)
{
    if (x->ncons == x->cons_cap) {
        size_t cap = x->cons_cap ? x->cons_cap * 2 : 64;
        constraint *g;
        if (cap > SIZE_MAX / sizeof(*g))
            return nomem(x->err);
        g = realloc(x->cons, cap * sizeof(*g));
        if (g == NULL)
            return nomem(x->err);
        x->cons = g;
        x->cons_cap = cap;
    }
    x->cons[x->ncons].from = from;
    x->cons[x->ncons].dep = dep;
    x->cons[x->ncons].prev = x->head[name];
    x->cons[x->ncons].name = name;
    x->head[name] = x->ncons++;
    return LPM_OK;
}

static const lpm_dependency *cons_dep(const search *x, size_t c)
{
    return &x->s->e[x->cons[c].from].pkg.dependencies[x->cons[c].dep];
}

/* Does entry c fit name n, given everything chosen so far? */
static bool acceptable(const search *x, size_t c, size_t n)
{
    const entry *e = &x->s->e[c];
    size_t k, j;

    if (e->damaged)
        return false;
    for (k = x->head[n]; k != NONE; k = x->cons[k].prev)
        if (!sat(e->pkg.version, cons_dep(x, k)))
            return false;
    for (j = 0; j < e->pkg.dependency_count; j++) {
        const lpm_dependency *d = &e->pkg.dependencies[j];
        size_t t = name_id(x, d->name);
        if (t == n) {
            if (!sat(e->pkg.version, d))      /* self-dependency */
                return false;
        } else if (x->chosen[t] != NONE &&
                   !sat(x->s->e[x->chosen[t]].pkg.version, d)) {
            return false;
        }
    }
    return true;
}

/* Record why name n has no acceptable option (first failure only). */
static void explain(search *x, size_t n)
{
    char req[720] = "", one[340];
    const char *pname = x->names[n];
    lpm_meta_error *m = &x->first;
    size_t k, shown = 0;

    if (x->have_first)
        return;
    x->have_first = true;

    /* "lib >= 3.0 (required by a 1.0); lib < 2.0 (required by b 1.0)" */
    for (k = x->head[n]; k != NONE && shown < 2; k = x->cons[k].prev, shown++) {
        const entry *from = &x->s->e[x->cons[k].from];
        char dt[160];   /* name(64) op(2) version(64) */
        dep_text(dt, sizeof(dt), cons_dep(x, k));
        snprintf(one, sizeof(one), "%s%s (required by %s %s)", shown ? "; " : "", dt,
                 from->pkg.name, from->pkg.version);
        strncat(req, one, sizeof(req) - strlen(req) - 1);
    }

    if (x->installed[n] != NONE) {
        const entry *in = &x->s->e[x->installed[n]];
        if (in->damaged)
            lpm_meta_error_set(m, LPM_META_ERR_DEP_INSTALLED, 0, pname,
                               "%s is required (%s), but its installed record is "
                               "damaged; run 'lpm check'", pname, req);
        else
            lpm_meta_error_set(m, LPM_META_ERR_DEP_INSTALLED, 0, pname,
                               "version conflict: required %s; installed %s %s "
                               "(installed packages are not upgraded)",
                               req, pname, in->pkg.version);
        return;
    }
    if (x->opt_count[n] == 0) {
        lpm_meta_error_set(m, LPM_META_ERR_DEP_MISSING, 0, pname,
                           "missing dependency: %s; it is neither installed nor "
                           "available", req);
        return;
    }
    /* Candidates exist: does any satisfy the constraints on n itself? If
     * so, it was refused because of its own requirements. */
    for (k = 0; k < x->opt_count[n]; k++) {
        const entry *c = &x->s->e[x->opts[x->opt_start[n] + k]];
        size_t q;
        bool fits = true;
        for (q = x->head[n]; q != NONE; q = x->cons[q].prev)
            if (!sat(c->pkg.version, cons_dep(x, q)))
                fits = false;
        if (fits) {
            lpm_meta_error_set(m, LPM_META_ERR_DEP_CONFLICT, 0, pname,
                               "conflict: %s %s fits (%s), but its own requirements "
                               "clash with the versions selected for other packages",
                               pname, c->pkg.version, req[0] ? req : "requested");
            return;
        }
    }
    {
        char avail[420] = "";   /* up to 6 versions of 64 */
        for (k = 0; k < x->opt_count[n] && k < 6; k++) {
            snprintf(one, sizeof(one), "%s%s", k ? ", " : "",
                     x->s->e[x->opts[x->opt_start[n] + k]].pkg.version);
            strncat(avail, one, sizeof(avail) - strlen(avail) - 1);
        }
        lpm_meta_error_set(m, LPM_META_ERR_DEP_CONFLICT, 0, pname,
                           "conflicting requirements: %s; available versions of %s: %s",
                           req, pname, avail);
    }
}

static lpm_status choose(search *x, size_t k, size_t c)
{
    const entry *e = &x->s->e[c];
    size_t n = x->agenda[k], j;
    lpm_status rc;

    x->chosen[n] = c;
    x->frames[k].agenda_before = x->alen;
    x->frames[k].cons_before = x->ncons;
    if (e->installed)
        return LPM_OK;   /* installed packages are leaves */
    for (j = 0; j < e->pkg.dependency_count; j++) {
        size_t t = name_id(x, e->pkg.dependencies[j].name);
        rc = push_constraint(x, c, j, t);
        if (rc != LPM_OK)
            return rc;
        if (x->in_agenda[t] == NONE) {
            if (x->alen >= LPM_SOLVER_MAX_NODES) {
                lpm_meta_error_set(x->err, LPM_META_ERR_DEP_LIMIT, 0, NULL,
                                   "the plan would contain more than %d packages",
                                   LPM_SOLVER_MAX_NODES);
                return LPM_ERR_DEPENDENCY;
            }
            x->in_agenda[t] = x->alen;
            x->agenda[x->alen++] = t;
        }
    }
    return LPM_OK;
}

static void undo(search *x, size_t k)
{
    while (x->ncons > x->frames[k].cons_before) {
        size_t c = --x->ncons;
        x->head[x->cons[c].name] = x->cons[c].prev;
    }
    while (x->alen > x->frames[k].agenda_before)
        x->in_agenda[x->agenda[--x->alen]] = NONE;
    x->chosen[x->agenda[k]] = NONE;
}

/* Option i (0-based) for agenda slot k; NONE past the end. */
static size_t option(const search *x, size_t k, size_t i)
{
    size_t n = x->agenda[k];

    if (k == 0)
        return i == 0 ? x->root : NONE;   /* the request itself, nothing else */
    if (x->installed[n] != NONE)
        return i == 0 ? x->installed[n] : NONE;
    return i < x->opt_count[n] ? x->opts[x->opt_start[n] + i] : NONE;
}

/* Iterative backtracking over the agenda (see solver.h). */
static lpm_status run_search(search *x)
{
    size_t k = 0;
    lpm_status rc;

    x->agenda[0] = x->s->e[x->root].name;
    x->in_agenda[x->agenda[0]] = 0;
    x->alen = 1;
    x->frames[0].next = 0;

    for (;;) {
        size_t c;
        bool found = false;

        if (k == x->alen)
            return LPM_OK;   /* every discovered name has a version */
        while ((c = option(x, k, x->frames[k].next)) != NONE) {
            x->frames[k].next++;
            if (++x->steps > LPM_SOLVER_MAX_STEPS) {
                lpm_meta_error_set(x->err, LPM_META_ERR_DEP_LIMIT, 0, NULL,
                                   "dependency search gave up after %d candidate "
                                   "attempts", LPM_SOLVER_MAX_STEPS);
                return LPM_ERR_DEPENDENCY;
            }
            if (acceptable(x, c, x->agenda[k])) {
                rc = choose(x, k, c);
                if (rc != LPM_OK)
                    return rc;
                found = true;
                break;
            }
        }
        if (found) {
            k++;
            x->frames[k].next = 0;
            continue;
        }
        explain(x, x->agenda[k]);
        if (k == 0)
            break;
        k--;
        undo(x, k);   /* then try agenda[k]'s next option */
    }
    if (x->err != NULL)
        *x->err = x->first;
    return LPM_ERR_DEPENDENCY;
}

/* ---- graph, cycle detection, topological order ------------------------- */

enum { WHITE, GRAY, BLACK };

static lpm_status build_plan(search *x, lpm_plan *p)
{
    const size_t v = x->alen;
    unsigned char *color = NULL;
    size_t *stack = NULL, *next = NULL, *pos = NULL, *queue = NULL;
    size_t i, j, sp = 0;
    lpm_status rc = LPM_OK;

    p->nodes = calloc(v, sizeof(*p->nodes));
    p->order = malloc(v * sizeof(*p->order));
    color = calloc(v, 1);
    stack = malloc(v * sizeof(size_t));
    next = calloc(v, sizeof(size_t));
    pos = malloc(v * sizeof(size_t));
    queue = malloc(v * sizeof(size_t));
    if (!p->nodes || !p->order || !color || !stack || !next || !pos || !queue) {
        rc = nomem(x->err);
        goto out;
    }
    p->count = v;

    /* Nodes in discovery order; adjacency lists parallel to depends=. */
    for (i = 0; i < v; i++) {
        const entry *e = &x->s->e[x->chosen[x->agenda[i]]];
        lpm_plan_node *nd = &p->nodes[i];

        nd->pkg = &e->pkg;
        nd->source = e->installed ? NULL : e->source;
        nd->kind = e->installed ? LPM_NODE_INSTALLED : LPM_NODE_INSTALL;
        nd->depth = NONE;
        if (e->installed) {
            p->satisfied++;
            continue;
        }
        if (e->pkg.dependency_count > 0) {
            nd->edges = malloc(e->pkg.dependency_count * sizeof(size_t));
            if (nd->edges == NULL) {
                rc = nomem(x->err);
                goto out;
            }
        }
        for (j = 0; j < e->pkg.dependency_count; j++)
            nd->edges[j] = x->in_agenda[name_id(x, e->pkg.dependencies[j].name)];
    }

    /* Depth by breadth-first search: 1 = direct, > 1 = transitive. */
    {
        size_t qh = 0, qt = 0;
        p->nodes[0].depth = 0;
        queue[qt++] = 0;
        while (qh < qt) {
            const lpm_plan_node *nd = &p->nodes[queue[qh++]];
            size_t ne = nd->kind == LPM_NODE_INSTALL ? nd->pkg->dependency_count : 0;
            for (j = 0; j < ne; j++)
                if (p->nodes[nd->edges[j]].depth == NONE) {
                    p->nodes[nd->edges[j]].depth = nd->depth + 1;
                    queue[qt++] = nd->edges[j];
                }
        }
    }

    /* Iterative three-colour DFS: cycle detection + post-order. */
    color[0] = GRAY;
    stack[sp++] = 0;
    pos[0] = 0;
    while (sp > 0) {
        size_t u = stack[sp - 1];
        const lpm_plan_node *nd = &p->nodes[u];
        size_t ne = nd->kind == LPM_NODE_INSTALL ? nd->pkg->dependency_count : 0;

        if (next[u] < ne) {
            size_t w = nd->edges[next[u]++];
            if (color[w] == GRAY) {
                /* stack[pos[w]..sp-1] is the path w -> ... -> u; u -> w closes it */
                char path[240] = "";
                size_t q;
                for (q = pos[w]; q < sp; q++) {
                    strncat(path, p->nodes[stack[q]].pkg->name, sizeof(path) - strlen(path) - 1);
                    strncat(path, " -> ", sizeof(path) - strlen(path) - 1);
                }
                strncat(path, p->nodes[w].pkg->name, sizeof(path) - strlen(path) - 1);
                lpm_meta_error_set(x->err, LPM_META_ERR_DEP_CYCLE, 0, NULL,
                                   "dependency cycle detected: %s", path);
                rc = LPM_ERR_DEPENDENCY;
                goto out;
            }
            if (color[w] == WHITE) {
                color[w] = GRAY;
                pos[w] = sp;
                stack[sp++] = w;
            }
            continue;
        }
        color[u] = BLACK;   /* all dependencies done: u can follow them */
        if (nd->kind == LPM_NODE_INSTALL)
            p->order[p->order_count++] = u;
        sp--;
    }
    p->steps = x->steps;

out:
    free(color);
    free(stack);
    free(next);
    free(pos);
    free(queue);
    return rc;
}

void lpm_plan_free(lpm_plan *p)
{
    size_t i;

    if (p == NULL)
        return;
    if (p->nodes != NULL)
        for (i = 0; i < p->count; i++)
            free(p->nodes[i].edges);
    free(p->nodes);
    free(p->order);
    memset(p, 0, sizeof(*p));
}

static void search_free(search *x)
{
    free(x->names);
    free(x->installed);
    free(x->opt_start);
    free(x->opt_count);
    free(x->opts);
    free(x->chosen);
    free(x->in_agenda);
    free(x->head);
    free(x->agenda);
    free(x->frames);
    free(x->cons);
}

lpm_status lpm_solver_resolve(lpm_solver *s, size_t root, lpm_plan *out,
                              lpm_meta_error *err)
{
    search x;
    lpm_status rc;

    memset(out, 0, sizeof(*out));
    memset(&x, 0, sizeof(x));
    if (s == NULL || root >= s->n || s->e[root].installed) {
        lpm_meta_error_set(err, LPM_META_ERR_STATE, 0, NULL, "invalid package to resolve");
        return LPM_ERR_USAGE;
    }
    x.s = s;
    x.root = root;
    x.err = err;

    rc = build_tables(&x);
    if (rc == LPM_OK && x.installed[s->e[root].name] != NONE) {
        /* Same status and wording as Milestone 4 used for this case. */
        lpm_meta_error_set(err, LPM_META_ERR_DEP_ALREADY, 0, NULL,
                           "package '%s' is already registered (installed version %s)",
                           s->e[root].pkg.name,
                           s->e[x.installed[s->e[root].name]].pkg.version);
        rc = LPM_ERR_EXISTS;
    }
    if (rc == LPM_OK)
        rc = run_search(&x);
    if (rc == LPM_OK)
        rc = build_plan(&x, out);
    if (rc != LPM_OK)
        lpm_plan_free(out);
    search_free(&x);
    return rc;
}
