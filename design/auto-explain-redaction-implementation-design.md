# Auto-Explain Log Redaction — Implementation Design

| | |
|---|---|
| **Status** | v1.2 — aligned with [requirements v1.2](auto-explain-redaction-requirements.md). v1.1 incorporated the adversarial security review (D5–D7, FR-28); v1.2 incorporates the source-code leak-path audit: the column/alias pseudonym layer is moved down to the name-assignment functions (FR-46/FR-47), eleven additional choke points are added (FR-90 – FR-99), the generic EXPLAIN plugin hooks are brought under suppression (FR-25/FR-29), and one structural defect in the original proposal is corrected (redaction state must not live *only* in `deparse_context` — FR-64). |
| **Component** | `contrib/auto_explain`, `src/backend/commands/explain*`, `src/backend/utils/adt/ruleutils.c` |
| **Related** | [auto-explain-redaction-requirements.md](auto-explain-redaction-requirements.md) |

> **Note (post-review update):** the original proposal below is kept, with the
> resolution of the design review folded in where marked **[RESOLVED]**. Two
> corrections came out of the review:
>
> 1. The alias-rewriting function is `select_rtable_names_for_explain()`
>    (declared in `src/include/utils/ruleutils.h`, defined in
>    `ruleutils.c`) — it already exists precisely to rewrite RTE alias names
>    for `EXPLAIN`, which is where generated aliases (`t1`, `a1`) should be
>    injected.
> 2. Structured-format (`json`/`xml`/`yaml`) object fields are not a separate
>    concern: `ExplainTargetRel()` emits `Relation Name` / `Schema` / `Alias`
>    via `ExplainPropertyText` (explain.c:4720-4724) from the same
>    `objectname`/`namespace`/`refname` variables the text branch prints, so
>    redacting at `ExplainTargetRel` covers both branches. Likewise trigger
>    names (`Trigger Name`, explain.c:1151) and constraint names are emitted
>    in `report_triggers()` (explain.c:1100-1170) for both branches. The
>    deparse paths feeding `Output` / `Filter` / `Index Cond` /
>    `Function Call` are shared by all four formats via
>    `deparse_expression()` (call sites explain.c:2501, 2526, 2741, 2820,
>    2993, 3060, 3064, 3634).
>
> The one genuinely un-hookable surface remains `ruleutils.c` itself
> (deparse has no plugin hooks — the only explain-side hook is
> `explain_get_index_name_hook`, explain.c:4237), which is why the deparse
> choke points below require in-tree changes.

> **Note (v1.2, code audit):** three claims in the v1.1 note above need
> qualifying, and one was wrong.
>
> 1. *`select_rtable_names_for_explain()` is **not** a sufficient single point
>    for alias consistency.* It delegates to `set_rtable_names()`, which
>    assigns `refname = NULL` for every RTE absent from `rels_used`
>    (ruleutils.c:3950-3956). Two call sites then fall back to the **real**
>    `rte->eref->aliasname`: `ExplainTargetRel()` at explain.c:4610 and
>    `show_result_replacement_info()` at explain.c:5042. Redacting only inside
>    `select_rtable_names_for_explain()` leaves both fallbacks intact (FR-13a).
> 2. *The "same variables, both branches" argument is correct but its
>    corollary was not drawn.* Because it is the *variables* that are shared,
>    redaction must be applied to the variables. It must **not** be applied at
>    `ExplainProperty*` — in text format, trigger/constraint/relation names
>    (explain.c:1134/1138/1140), index names (1715-1716, 4550), the
>    scan-target clause (4710-4718), `Sampling:` (3075) and the bare sub-plan
>    label are appended straight to `es->str` and never reach those functions
>    (FR-63).
> 3. *Storing the redaction handle only in `deparse_context` is unsafe.*
>    `get_range_partbound_string()` builds a fresh context with
>    `memset(&context, 0, sizeof(deparse_context))` (ruleutils.c:3921) and then
>    calls `get_const_expr()`, silently clearing any flag carried there
>    (FR-64).

---

## 1. How auto-explain output is produced today

The log record is assembled in `explain_ExecutorEnd()`
(contrib/auto_explain/auto_explain.c:421-500): an `ExplainState` is created
(`NewExplainState()`), options are set from GUCs, then
`ExplainQueryText` → `ExplainQueryParameters` → `ExplainPrintPlan` →
(`ExplainPrintTriggers`) → (`ExplainPrintJITSummary`) → `ExplainEndOutput`,
and the buffer is emitted with `ereport()` (with `errhidestmt(true)`).

Three classes of sensitive material flow into that buffer:

1. **Query text and parameter values**
   - `ExplainQueryText()` — explain.c:1067 (`Query Text` property)
   - `ExplainQueryParameters()` — explain.c:1082-1093, via
     `BuildParamLogString()` (src/backend/nodes/params.c:333); note
     `maxlen == 0` already suppresses the property entirely.
2. **Object names** (both text and structured branches come from the same
   variables, see note above)
   - `ExplainTargetRel()` — explain.c:4599-4726: `get_rel_name()`,
     `get_namespace_name_or_temp()`, CTE names (`rte->ctename`), ENR names
     (`rte->enrname`), function-scan names (`get_func_name()`), and the
     alias/refname from `es->rtable_names`.
   - `explain_get_index_name()` — explain.c:4233 (has a hook).
   - `report_triggers()` — explain.c:1099-1140: `trig->tgname`,
     `get_constraint_name()`, `RelationGetRelationName()`.
3. **Everything inside expressions** — `Output:`, `Filter:`, `Index Cond:`,
   `Hash Cond:`, `Merge Cond:`, `Recheck Cond:`, `Sort Key:`, `Function
   Call:`, `Table Function Call:` … all produced by `deparse_expression()`
   into **ruleutils.c**:
   - column names: `get_variable()` — ruleutils.c:7641
   - literal values: `get_const_expr()` — ruleutils.c:11529 (incl.
     `get_const_collation()`)
   - relation names in expressions: `generate_relation_name()` —
     ruleutils.c:13396
   - function names: `generate_function_name()` — ruleutils.c:13492
   - operator names: `generate_operator_name()` — ruleutils.c:13599
   - type names in casts: `format_type_with_typemod()` call sites
   - range-table/column alias assignment:
     `select_rtable_names_for_explain()` (ruleutils.h:44)

**Key architectural conclusion:** a string-level scrubber in auto_explain is
unworkable (identifiers nested in quoted SQL expressions, four formats,
escaping). Redaction must happen at the emission choke points above, where
content is still typed nodes and OIDs.

A second architectural fact reinforces this, and is easy to get wrong:
`ExplainState` is **not** a structured capture that is serialized at the end.
`NewExplainState()` allocates a single flat text buffer
(`es->str = makeStringInfo()`, explain_state.c:71) and every `ExplainProperty*`
call formats and appends bytes immediately (`ExplainProperty()`,
explain_format.c:158-205, switches on `es->format` and writes there and then).
The `json`/`xml`/`yaml` "structure" is produced by a streaming serializer whose
entire state is `es->indent` plus `es->grouping_stack` — an integer list
recording whether anything has been emitted at each level, so
`ExplainJSONLineEnding()` knows where to put commas. There is no output node
tree, nothing is deferred, and nothing is ever revisited. Nor does anything
label a value: `ExplainPropertyText("Node Type", "Seq Scan", es)` and
`ExplainPropertyText("Relation Name", objectname, es)` are the same call with
the same types. The input to the pass is richly structured (the `PlanState`
tree and its typed expression nodes); the output is undifferentiated
append-only text. Redaction therefore has to be a transformation applied
*inside* that single pass, and fail-closed decisions have to be made at the
moment of emission — there is no later point at which a bad name could be
noticed and fixed (FR-60, FR-63).

### 1.1 Execution model: how a normal query yields ANALYZE data

auto_explain does **not** run `EXPLAIN ANALYZE`. There is no re-execution, no
second plan, no `DestReceiver` substitution and no discarding of results. It
switches instrumentation counters on for the ordinary execution and then
formats whatever accumulated. Understanding this matters because it is what
makes redaction cheap and side-effect-free.

**The four hooks.** `_PG_init` installs `ExecutorStart` / `ExecutorRun` /
`ExecutorFinish` / `ExecutorEnd` (auto_explain.c:327, 378, 400, 421).
`explain_ExecutorRun` and `explain_ExecutorFinish` do nothing but
`nesting_level++` / `--` inside a `PG_TRY`/`PG_FINALLY`. All the work is at
the two ends.

**Two independent filters, at different times.** Sampling is decided
*before* execution, once per top-level statement (auto_explain.c:340-345):

```c
if (nesting_level == 0)
{
    if (auto_explain_log_min_duration >= 0 && !IsParallelWorker())
        current_query_sampled = (pg_prng_double(&pg_global_prng_state) < auto_explain_sample_rate);
    else
        current_query_sampled = false;
}
```

`current_query_sampled` is a session-static bool (auto_explain.c:102) and
nested statements inherit the draw — either all nested statements of a
sampled statement are explained or none are. Duration is checked *after*
execution (auto_explain.c:423-437). So `sample_rate` is the
instrumentation-overhead knob and `log_min_duration` is the log-volume knob;
they are not alternatives. `sample_rate < 1` with `log_min_duration = 0`
yields a uniform random sample of all queries, rather than the
slow-query-biased sample that a duration threshold alone produces.

**How instrumentation attaches.** `explain_ExecutorStart` sets two distinct
flag fields on the `QueryDesc` and then calls `standard_ExecutorStart`:

```c
queryDesc->query_instr_options |= INSTRUMENT_TIMER;        /* :350 — always, when enabled */

if (auto_explain_log_analyze && (eflags & EXEC_FLAG_EXPLAIN_ONLY) == 0)
{
    queryDesc->instrument_options |= INSTRUMENT_TIMER;     /* :356 (or ROWS at :358) */
    ... |= INSTRUMENT_BUFFERS / INSTRUMENT_IO / INSTRUMENT_WAL;   /* :360-364 */
}
```

These drive different things. `query_instr_options` produces
`queryDesc->query_instr` (allocated execMain.c:259-260, started and stopped
around each run/finish at execMain.c:344, 396, 446, 456); that is the
whole-query timer whose total feeds the duration threshold, and it is on for
every sampled query regardless of `log_analyze`. `instrument_options` becomes
`estate->es_instrument` (execMain.c:250), which is what makes `ExecInitNode`
allocate a per-node `Instrumentation` struct and substitute the instrumented
wrapper:

```c
/* execProcnode.c:416, 465 */
result->instrument = InstrAllocNode(estate->es_instrument, ...);
node->ExecProcNode = ExecProcNodeInstr;
```

Because the flags are set *before* `standard_ExecutorStart`, the per-node
structs exist by the time plan initialization finishes. From then on the
normal execution updates them as tuples flow.

**What is deliberately not happening.** The query runs on the same plan,
through the same `DestReceiver`, and the client receives its result set
exactly as it would with auto_explain unloaded. Contrast a client-issued
`EXPLAIN ANALYZE`, which executes and then throws the rows away — the client
gets plan text *instead of* results. The `EXEC_FLAG_EXPLAIN_ONLY` guard at
auto_explain.c:353 covers the converse: for a plain client `EXPLAIN` nothing
executes, so per-node instrumentation would be pointless.

`explain_ExecutorEnd` then walks the *same, already-executed* `PlanState`
tree with `ExplainPrintPlan()`, reading `planstate->instrument` as it goes.

### 1.2 What ANALYZE adds, and what it does not

**ANALYZE contributes no new redaction targets.** Every `es->analyze`-gated
emission in explain.c is numeric or fixed vocabulary: sort stats (3103),
hash and hashagg (3319, 3777-3827), storage info for material / CTE scan /
tablefunc / recursive union (3500, 3523, 3542, 3561), memoize (3662), index
searches and tidbitmap (3885, 3939), the generic instrumentation counters
(4182), ModifyTable tuple counts (4906, 4928), and the per-worker blocks.
The `Instrumentation` and `SharedSortInfo`-style structs hold no strings and
no OIDs. Every name that has to be redacted originates in the plan tree and
its expressions, which are byte-identical with and without ANALYZE. No part
of the redaction design needs to inspect a counter.

**One exception, and it is load-bearing: the trigger section exists only
under ANALYZE.** auto_explain calls `ExplainPrintTriggers` only when
`es->analyze && auto_explain_log_triggers`, and `report_triggers()` emits
`trig->tgname`, `get_constraint_name()` and `RelationGetRelationName()` — in
text format by direct buffer appends at explain.c:1134, 1138, 1140, and as
`Trigger Name` / `Constraint Name` / `Relation` properties at explain.c:1151,
1153, 1154. Consequence for verification: **FR-17 cannot be exercised at all
unless the test runs with ANALYZE *and* `log_triggers` enabled.** A test
matrix that only covers non-ANALYZE plans will report full coverage while
leaving trigger, constraint and relation names entirely untested.

## 2. Architecture

v1.2 introduces a **three-layer** structure. The v1.1 design had two layers
(explain.c emission points, ruleutils.c deparse points) and tried to make
`get_variable()` carry all column redaction; that cannot work for RTEs with no
relid (FR-46). The fix is a third, lower layer: redact the *name tables* at the
point they are built, so both of the upper layers read already-pseudonymized
names and neither needs to know how a name was derived.

```
                 auto_explain (GUC: auto_explain.log_redact, PGC_SIGHUP)
                                   │  es->redact = true, es->redact_ctx
                                   ▼
        ┌──────────────────── ExplainState ────────────────────────┐
        │  bool redact                                             │
        │  RedactCtx *redact_ctx  (per-record pseudonym maps)      │
        └───────┬──────────────────────────────┬───────────────────┘
                │                              │
   LAYER A: explain.c emission        LAYER B: ruleutils.c deparse
   ─ ExplainTargetRel  tN / drop      ─ get_const_expr        ? (all consts)
     schema / alias (4610 fallback!)  ─ generate_relation_name    tN
   ─ explain_get_index_name  iN       ─ generate_function_name    fN / keep
     (covers Conflict Arbiter too)    ─ generate_operator_name    opN / keep
   ─ report_triggers  trgN/conN/tN    ─ format_type_* (12 sites)  tyN / drop
   ─ Subplan Name  spN   [FR-90]      ─ generate_collation_name   collN
   ─ show_window_def  wN [FR-91]      ─ get_name_for_var_field fldN [FR-93]
   ─ Replaces  refnames  [FR-92]      ─ processIndirection    fldN [FR-93]
   ─ show_sortorder_options           ─ NamedArgExpr         argN [FR-94]
     COLLATE/USING     [FR-98a]       ─ XmlExpr names        xmlN [FR-95]
   ─ CustomName / Custom Plan         ─ tablefunc/Json path labels
     Provider  blanked   [FR-28]        pathN / argN         [FR-96]
   ─ show_tablesample  fN             ─ CurrentOfExpr        curN [FR-97]
   ─ ExplainQueryText   omitted       ─ CollateExpr / InferenceElem
   ─ Query Parameters   omitted [D10]   collN / opcN         [FR-98b,c]
   ─ Query Identifier   omitted [D5]  ─ get_func_sql_syntax raw consts
   ─ Settings section   omitted         → ?                  [FR-98d]
   ─ FDW / custom-scan callbacks      ─ NextValueExpr  tN inside literal
     + explain_per_plan_hook            [FR-99]
     + explain_per_node_hook  skipped
                │                              │
                └──────────────┬───────────────┘
                               ▼
   LAYER C (new in v1.2): ruleutils.c name-assignment
   ─ set_rtable_names()            → relation aliases tN / aN   [FR-13]
     (ruleutils.c:3892; covers the NULL/rels_used case at 3950)
   ─ set_relation_column_names()   → column names t1_cN         [FR-12/46]
     (ruleutils.c:4383; catalog branch 4411-4419 AND the
      eref->colnames / expandRTE branch at 4449)
   ─ ret_old_alias / ret_new_alias  → aN                        [FR-13b]
     (installed by set_deparse_context_plan; read at 7738-7740)
```

All four output formats are covered because layers B and C operate on values,
not on serialized output, and layer A operates on the same variables that both
the text and structured branches print. Redaction is deliberately **never**
applied at `ExplainProperty*` (FR-63).

## 3. Redaction context

```c
/* new: src/include/commands/explain_state.h (or a small explain_redact.h) */
typedef struct RedactCtx RedactCtx;   /* opaque; defined in explain.c */
```

- `RedactCtx` holds one `HTAB` per pseudonym namespace, plus per-namespace
  counters, plus the allowlist state. Allocated in the query memory context
  (auto_explain already switches to `estate->es_query_cxt` before generating
  output), which is what makes FR-45's per-record lifetime automatic rather
  than a matter of discipline.
- **Key domains (revised in v1.2 — FR-46).** A single OID key does not cover
  what has to be named. Three distinct key kinds are required:

  | Pseudonym | Key | Why not an OID |
  |---|---|---|
  | `tN`, `iN`, `fN`, `opN`, `tyN`, `collN`, `opcN`, `trgN`, `conN` | object OID | — |
  | `aN` (relation alias) | range-table index | an RTE may be a subquery, join, `VALUES`, function, CTE, ENR or tablefunc and have no relid at all (ruleutils.c:3973) |
  | `t<n>_cN` (column) | **(range-table index, attribute number)** within the deparse namespace | for every non-`RTE_RELATION` kind the printed name comes from `rte->eref->colnames` or `expandRTE()` (ruleutils.c:4449), so there is neither a relid nor a catalog attno to key on |
  | `cteN`, `enrN`, `spN`, `wN`, `fldN`, `argN`, `xmlN`, `pathN`, `curN` | identity of the node or list element that produced the string | these names have no catalog object behind them at all |

  The `(varno, attno)` choice for columns is what makes FR-12 reachable for
  subquery/CTE/`VALUES`/function/join output names. It also keeps the
  inheritance behavior the v1.1 design wanted: `get_variable()` performs the
  appendrel parent mapping *before* the name lookup (ruleutils.c:7700-7735),
  so by the time layer C's table is consulted the varno is already the mapped
  parent and partition child names never surface.
- API used by choke points — two entry points, not one, because half the
  callers have no OID:

  ```c
  /* OID-keyed objects; returns the real name when exempt (D7) */
  const char *explain_redact_name(RedactCtx *ctx, RedactKind kind, Oid oid);
  /* non-OID names: key is an opaque (kind, scope, ordinal) triple */
  const char *explain_redact_local(RedactCtx *ctx, RedactKind kind,
                                   int scope, int ordinal);
  ```

- **Ordering constraint (FR-47).** Pseudonyms must be assigned *before* the
  name-uniquifying passes run, not after. `set_rtable_names()` appends `_%d`
  suffixes to disambiguate colliding refnames (ruleutils.c:3990-4015) and
  `set_relation_column_names()` does the same for columns via
  `make_colname_unique()`. Substituting pseudonyms afterwards means those
  suffixes are applied to, or fight with, the pseudonym counters — producing
  either collisions (breaking FR-40) or names like `t1_2` that carry no
  meaning. Assigning first also makes the uniquifier a no-op, since generated
  pseudonyms are unique by construction.
- **Reachability constraint (FR-64).** The handle must be reachable
  independently of `deparse_context`, because at least one site constructs a
  zeroed one (`get_range_partbound_string()`, ruleutils.c:3921). Options, in
  preference order: (a) thread the `RedactCtx *` through the affected static
  helpers explicitly; (b) keep a file-scope `static RedactCtx *` in ruleutils.c
  set and cleared by the `deparse_expression_redacted()` wrapper, with a
  `PG_TRY`/`PG_FINALLY` to guarantee it is cleared on error. (b) is the smaller
  diff and is safe because deparse is not re-entrant across records, but it
  must be documented as such. Either way, §4.3 must enumerate every
  `deparse_context` construction site and a test must assert that count
  (§10, FR-64) so a newly added site fails rather than silently leaks.
- Exemption test (D7, namespace-primary): an object is exempt iff its
  namespace ∈ {`pg_catalog`, `information_schema`} ∪
  `auto_explain.redact_allow_schemas`. The OID range
  (`FirstNormalObjectId`, transam.h:198) is deliberately **not** used —
  initdb-time provisioning creates low-OID application objects that must
  still be redacted. Fail closed: unknown namespace / failed lookup →
  redact (substitute the pseudonym; never ERROR the record, FR-60).
- **Lifetime and determinism (FR-42, FR-45, D8).** The `RedactCtx` is
  allocated fresh per record (per `ExplainState` / auto_explain log entry) and
  discarded afterwards — never cached across statements. Two consequences of
  D8 that the implementation must get right, and they pull in opposite
  directions:
  - *Counters must be per-context, never file-scope or session-scope.* A
    `static int` counter in explain.c or ruleutils.c would make numbering
    continue across records, which is exactly what FR-45 forbids: a log reader
    could then order and join pseudonyms across unrelated statements. All
    counters live in the `RedactCtx`.
  - *Assignment order must be a pure function of the plan.* Numbers are handed
    out on first use in traversal order (FR-42), so two records for the same
    plan shape carry the same pseudonyms — deliberately, because that is what
    makes records comparable and makes a self-join legible. This is not a
    weakness to be fixed by randomising; see D8 and the "pattern
    fingerprinting" row of requirements §9. It does mean the implementation
    must not seed numbering from anything session-dependent (a hash of a
    pointer, an OID sort order that varies, or the order of a hash-table scan),
    or the same plan will produce different records on different backends and
    the comparability FR-42 buys is lost.
- Pseudonym namespaces per requirements FR-40: `t`, `i`, `f`, `op`, `ty`,
  `cte`, `enr`, `trg`, `con`, `a`; columns derived as `<relpseudo>_c<seq>`
  where `<seq>` is an opaque per-relation counter keyed internally by attno
  — the attno itself is never printed (FR-12, FR-43).

## 4. Changes by file

### 4.1 `src/include/commands/explain_state.h` + `explain_state.c`
- Add `bool redact;` and `void *redact_ctx;` to `ExplainState` (struct at
  explain_state.h:45-79).
- Allocate/clear `redact_ctx` in `NewExplainState()` lazily on first use.
- `REDACT` option parsing (D3): add to the standard `EXPLAIN` option list
  handling (`ParseExplainOptionList()`), mirroring how `GENERIC`/`SETTINGS`
  booleans are parsed; forbid `REDACT` + `SERIALIZE` (FR-72) with an `ERROR`.

### 4.2 `src/backend/commands/explain.c`

Carried over from v1.1:

- `ExplainQueryText()`: skip when `es->redact` (FR-23).
- `ExplainQueryParameters()`: **omit the property entirely** when redacting
  (FR-22/D10 — changed from v1.1's names-only rendering, which disclosed
  `params->numParams`).
- `ExplainTargetRel()`: route `objectname` / `namespace` through the pseudonym
  map (relation → `tN`, schema → omitted); CTE/ENR names mapped (FR-14,
  FR-15); function-scan `Function Name` → `fN` (FR-18). **Also redact the
  `refname` fallback at explain.c:4610** — `list_nth(es->rtable_names, rti-1)`
  is NULL for any RTE outside `rels_used`, and the fallback reads the real
  `rte->eref->aliasname` (FR-13a). Note `Alias` is emitted unconditionally in
  non-text formats (explain.c:4724) and is *not* `VERBOSE`-gated, so the
  structured formats disclose an alias for every scanned RTE.
- `explain_get_index_name()`: in redact mode, ignore the hook
  (explain.c:4237) and return the `iN` pseudonym (FR-16; also neutralizes
  hypothetical-index plugins). Covers the non-scan sites too:
  `Conflict Arbiter Indexes` (built from `get_rel_name()` at explain.c:4852,
  emitted 4895) and `ExplainIndexScanDetails` (4550, 4569).
- `report_triggers()`: pseudonymize `tgname` → `trgN`, constraint name →
  `conN`, relation name → `tN` (FR-17). Six sites, two branches:
  explain.c:1134, 1138, 1140 (text, direct `es->str` appends) and 1151, 1153,
  1154 (structured). **Reachable only under ANALYZE + `log_triggers`** (§1.2).
- Custom-scan provider name: blank `methods->CustomName` where `pname` is
  built in the `T_CustomScan` arm, and skip the `Custom Plan Provider`
  property (explain.c:1663) (FR-28).
- `show_tablesample()`: pseudonymize `get_func_name(tsc->tsmhandler)`
  (explain.c:3052), printed text-mode at 3075 and structured at 3090
  (FR-18). Parameters and the `REPEATABLE` seed are deparsed constants,
  covered in layer B (FR-21).
- `ExplainPrintSettings()`: skip when redacting (FR-26) — explain.c:646-753.
  Note the qlabel there is a GUC name (explain.c:720), the one place a
  property *name* is not a code constant, and `search_path` does carry
  `GUC_EXPLAIN` (guc_parameters.dat:2612), so the section really does
  disclose schema names.
- `Query Identifier`: skip when redacting (FR-37/D5) — explain.c:825, inside
  `ExplainPrintPlan` and gated on `es->verbose`, so auto_explain reaches it
  whenever `log_verbose` is on.

New in v1.2:

- **`ExplainSubPlans()` — sub-plan labels (FR-90).** `cooked_plan_name` is
  built at explain.c:5152-5156 by prefixing `sp->plan_name`; emitted as
  `Subplan Name` at explain.c:1661 and as a bare text-mode line just above it.
  `SubPlan->plan_name` is seeded from `cte->ctename` (subselect.c:980) and from
  `rte->eref->aliasname` (allpaths.c:2828) via `choose_plan_name()`
  (planner.c:9275). Redact the name part, keep the `CTE `/`InitPlan `/`SubPlan `
  prefix, and use the **same** pseudonym the CTE gets in `ExplainTargetRel` so
  the two lines stay relatable. Second site, layer B:
  `get_parameter()` prints `(hashed SubPlan <plan_name>).colN` at
  ruleutils.c:8798 and must use the same map.
- **`show_window_def()` — window names (FR-91).** explain.c:2912
  (`quote_identifier(wagg->winname)`) → emitted at 2957. `WindowAgg->winname`
  comes from `WindowClause->name` (createplan.c:6686). Not `VERBOSE`-gated.
  Second site, layer B: `get_windowfunc_expr_helper()` at ruleutils.c:11194
  prints `OVER <winname>` and must resolve to the same `wN`.
- **`show_result_replacement_info()` — `Replaces` (FR-92).** explain.c:5036-5069
  builds a comma-separated refname list, with the same
  `rte->eref->aliasname` fallback at explain.c:5042 as `ExplainTargetRel`.
  Route both through layer C.
- **`show_sortorder_options()` — post-deparse decorations (FR-98a).**
  explain.c:2866 appends `COLLATE <get_collation_name(collation)>` and 2881
  appends `USING <get_opname(sortOperator)>` onto the already-deparsed sort-key
  string. These run in explain.c *after* `deparse_expression()` returns, so no
  ruleutils-side change reaches them. `get_opname` also bypasses
  `generate_operator_name`, which is FR-19's hook. Both are `elog(ERROR)` on
  lookup failure today and must become pseudonym substitution (FR-60).
- **Extension output — extend D4 to the generic hooks (FR-25/FR-29).** Skip
  `explain_per_plan_hook` (explain.c:657) and `explain_per_node_hook`
  (explain.c:2335) when redacting, in addition to the FDW callbacks
  (`show_foreignscan_info` at 4210-4218, `ExplainForeignModify` at 4820) and
  the custom-scan callback (`ExplainCustomScan` at 2160). These hooks receive
  the `ExplainState` *and* the `PlanState`, so a plugin can call
  `deparse_expression()` with its own context that carries no `RedactCtx` and
  bypass layers B and C entirely. Demonstration of why this matters: in-tree
  `pg_overexplain` uses `explain_per_plan_hook` to print the whole range table
  — per-RTE `Alias`, `Eref` alias plus every column name, schema-qualified
  `Relation`, `CTE Name`, `ENR Name`, and the sub-plan name
  (pg_overexplain.c:559-601, 740, 755).
- **Reject `REDACT` + extension option (FR-29/FR-72).** Suppressing the hooks
  is not sufficient for the interactive path: the option is parsed into
  `es->extension_state` by `ParseExplainOptionList()` before any hook runs, and
  `EXPLAIN (REDACT, RANGE_TABLE)` would otherwise silently drop output the
  user asked for. Raise an `ERROR` in `ParseExplainOptionList()` /
  `explain_validate_options_hook` when `REDACT` is combined with any
  extension-registered option. auto_explain's path stays as D4 describes:
  ignore the options and emit the FR-73 notice.

### 4.3 `src/backend/utils/adt/ruleutils.c` (the bulk of the work)

#### 4.3.1 Plumbing
- Extend the private `deparse_context` (ruleutils.c:112-128) with
  `RedactCtx *redact;`, **and** provide a reachability path that survives a
  zeroed context (FR-64, §3): either thread the pointer through the affected
  static helpers, or hold it in a file-scope static installed and cleared by
  the wrapper below under `PG_TRY`/`PG_FINALLY`.
- New exported entry points in `ruleutils.h`:
  - `List *select_rtable_names_for_explain_redacted(List *rtable, Bitmapset *rels_used, RedactCtx *ctx)`
    — or a `RedactCtx *` parameter on the existing function.
  - `List *deparse_context_for_plan_tree_redacted(PlannedStmt *pstmt, List *rtable_names, RedactCtx *ctx)`
    — **new in v1.2.** Column pseudonyms are assigned inside
    `set_simple_column_names()` → `set_relation_column_names()`, which runs
    from `deparse_context_for_plan_tree()` (ruleutils.c:3762), so the context
    has to reach *that* call and not only the per-expression one.
  - `deparse_expression_redacted(Node *expr, List *dpcontext, bool forceprefix, bool showimplicit, RedactCtx *ctx)`
    — thin wrapper installing `ctx`.
- `pg_get_indexdef_*`, view-rule deparsing and every other ruleutils caller are
  **unaffected**: they never supply a `RedactCtx`, and the existing ruleutils
  regression suites must stay byte-identical (requirements §10.4).

#### 4.3.2 Layer C — name assignment (new in v1.2, FR-12/FR-13/FR-46/FR-47)

This is the structural change relative to v1.1, and it replaces the claim that
`get_variable()` can carry column redaction on its own.

- **`set_rtable_names()` (ruleutils.c:3892).** Replace the chosen `refname`
  with `aN`/`tN` for every non-exempt RTE. Cover all four branches:
  user-written alias (3959), `get_rel_name(rte->relid)` for `RTE_RELATION`
  (3963), unnamed join → NULL (3967), and `rte->eref->aliasname` for
  everything else (3973). Assign before the `_%d` uniquifier at 3990-4015
  (FR-47), which then becomes a no-op.
- **`set_relation_column_names()` (ruleutils.c:4383).** Replace
  `real_colnames[]` entries with `t<n>_cN`, keyed `(varno, attno)`. Both
  branches matter and only the first has a catalog behind it:
  the `RTE_RELATION` branch reading `attr->attname` (4411-4419), and the
  `expandRTE()` / `rte->eref->colnames` branch (4440-4460) used for subquery,
  join, function, `VALUES`, CTE, ENR and tablefunc RTEs. Redacting here means
  `get_variable()`'s existing read of `colinfo->colnames[attnum - 1]`
  (ruleutils.c:7839) needs **no change at all** — it picks up the pseudonym.
- **`ret_old_alias` / `ret_new_alias` (FR-13b).** Installed by
  `set_deparse_context_plan()` from `ModifyTable->returningOldAlias/NewAlias`
  and used directly as the Var prefix at ruleutils.c:7738-7740, bypassing
  `rtable_names`. Pseudonymize at installation time.
- Two `get_variable()` details that still need attention even with layer C:
  system columns take the `else` branch at ruleutils.c:7854
  (`get_rte_attribute_name`) and print fixed catalog names (`ctid`, `xmin`) —
  leave them, they are exempt by construction; and whole-row Vars print
  `refname.*` plus, when `istoplevel`, `::<type>` (7905-7909), so the type
  label must route through FR-20.
- Note `get_rule_expr_toplevel()` calls `get_variable()` directly
  (ruleutils.c:10693), bypassing the `T_Var` switch case — which is why the
  hook belongs on the function, not on the case label.

#### 4.3.3 Layer B — deparse choke points

Carried over from v1.1, each guarded by the redaction flag:

- `get_const_expr()` (ruleutils.c:11529): **every** constant — including
  `NULL`, `true`, `false` (D6) — becomes `?` plus the existing type-label
  logic (FR-21); type label routed through FR-20. `get_const_collation()`
  (11660-11675): drop or pseudonymize user collations.
- `generate_relation_name()` (13396): `tN`, drop schema qualification
  (FR-10/11).
- `generate_function_name()` (13492): `fN` for user-defined, keep exempt.
  Resolution still runs; only the printed name changes (FR-18).
- `generate_operator_name()` (13599): exempt operators print as today;
  user-defined → `opN` (FR-19).
- `format_type_with_typemod()`: **twelve** reachable sites in the expression
  path, not one — ruleutils.c:7908, 9492, 9937, 9999, 10267, 10754, 11510,
  11547, 11649, 11723, 12124, 12321. Each can emit a schema-qualified user
  type, enum, or **domain** name. FR-20 depends on all twelve; a helper that
  wraps the call and is used uniformly is preferable to twelve edits.

New in v1.2:

| Site | Line | Emits | FR |
|---|---|---|---|
| `get_name_for_var_field()` | 8052; printed at 9712 | composite field name, from four sources: `RowExpr->colnames` (8074), `TupleDescAttr(...)->attname` (8110, 8478), `get_rte_attribute_name(rte, fieldno)` (8214), sub-tlist resnames. **Bypasses `get_variable()` entirely.** | FR-93 |
| `processIndirection()` | `get_attname` 13191, printed 13193 | composite field name in an `INSERT`/`UPDATE` target list EXPLAIN displays; reached from the assignment-`SubscriptingRef` branch at 9404 | FR-93 |
| `T_NamedArgExpr` | 9424 | `name => ` argument label | FR-94 |
| `T_XmlExpr` | 10165, 10186 | `XMLELEMENT`/`XMLPI` name; `XMLATTRIBUTES`/`XMLFOREST` labels — plain node strings, not `Const`s. Appears in `Filter`, which is **not** `VERBOSE`-gated | FR-95 |
| `get_xmltable()` | 12080; column names 12122 | `XMLNAMESPACES` prefix; column names | FR-95/FR-24 |
| `get_json_table()` and helpers | 12393, 12166, 12234, 12418; columns 12319 | root path `AS`, `NESTED PATH AS`, `PLAN` clause names, `PASSING … AS`, column names | FR-96/FR-24 |
| `T_JsonExpr` | 10638 | `PASSING … AS` label | FR-96 |
| `T_CurrentOfExpr` | 10403 | cursor name; reached as a `TID Cond` | FR-97 |
| `T_CollateExpr` | 9841 | `generate_collation_name()` — distinct from `get_const_collation()` | FR-98b |
| `T_InferenceElem` | 10460, 10468 | collation and `get_opclass_name()` (13123/13128, schema-qualified). Not reachable from EXPLAIN today; implement as a guard | FR-98c |
| `get_func_sql_syntax()` | 11284, 11306, 11330 | constants read straight from the datum: `EXTRACT` field, `IS … NORMALIZED` form, `NORMALIZE` form. **Never pass through `get_const_expr()`** | FR-98d |
| `T_NextValueExpr` | 10419 | sequence name via `generate_relation_name()` inside `simple_quote_literal()` — the pseudonym must not break the `nextval('…')` shape | FR-99 |
| `get_parameter()` | 8798 | `(hashed SubPlan <plan_name>).colN` — same map as FR-90 | FR-90 |
| `get_windowfunc_expr_helper()` | 11194 | `OVER <winname>` — same map as FR-91 | FR-91 |
| `get_range_partbound_string()` | 3921 | builds a zeroed `deparse_context` then calls `get_const_expr()`; latent rather than live, since `T_PartitionBoundSpec` does not appear in plan expressions | FR-64 |

#### 4.3.4 Paths confirmed *not* to need changes

Recording these so a later reviewer does not re-litigate them:

- `T_SubLink` → `get_sublink_expr()` → `get_query_def()` (ruleutils.c:12037)
  would print an entire `SELECT`, but plan trees contain `SubPlan`s, not
  `SubLink`s; the `T_SubPlan` case prints only the plan name. Likewise the
  `JSCTOR_JSON_ARRAY_QUERY` `get_query_def()` call is replaced by
  `eval_const_expressions` during planning (documented at
  parse_expr.c:3915-3935). Both are one node tag away from dumping raw SQL —
  add an assertion rather than relying on the invariant.
- `T_Aggref` / `T_GroupingFunc` / `T_RowExpr` / `T_ArrayExpr` /
  `T_ScalarArrayOpExpr` / `T_SQLValueFunction` / `T_MinMaxExpr` /
  `T_CoalesceExpr` / `T_NullTest` / `T_BooleanTest` / `T_SetToDefault` /
  `T_CaseTestExpr` contribute only function names, operator names and type
  labels, all already covered.
- `get_parameter()`'s function-name/argument-name branch (8836-8842) needs
  `dpns->argnames`, which only the SQL-function-body path sets — not reachable
  from explain.c, but it *is* reachable from `deparse_expression()` generally,
  so it is worth a guard.
- `explain_dr.c` materializes real user data (`OutputFunctionCall` at
  explain_dr.c:163, `SendFunctionCall` at 171) but only measures and discards
  the buffer. No leak; this is the mechanical reason FR-72 forbids
  `REDACT` + `SERIALIZE` rather than defining a contract for it.

### 4.4 `contrib/auto_explain/auto_explain.c`
- New GUCs:
  - `auto_explain.log_redact` (bool, `off`, `PGC_SIGHUP`) — FR-1/D9
  - `auto_explain.redact_allow_schemas` (string list, `PGC_SIGHUP`) — FR-51/D7/D9
- In `explain_ExecutorEnd()`: set `es->redact` in the same block that sets
  `es->analyze` (auto_explain.c:440), skip `ExplainQueryText()` (FR-23),
  omit the parameter property entirely (FR-22/D10), skip
  `apply_extension_options()` (auto_explain.c:590) and the
  `explain_per_plan_hook` call that follows it under D4 (FR-25, FR-73). Keep
  `errhidestmt(true)` (FR-70).
- **Placement rule: nothing in `explain_ExecutorStart` changes.** Redaction is
  a print-time property, decided at `ExecutorEnd` alongside `es->analyze`.
  Three properties follow from that, and they are worth stating because they
  are the reason the feature is safe to leave permanently enabled:
  1. Redaction cannot influence the sampling draw (auto_explain.c:340-345),
     cannot influence which instrumentation flags are requested
     (auto_explain.c:350-364), and therefore cannot perturb the numbers being
     measured. Sampling and redaction are fully independent — which is what
     FR-2 asserts.
  2. Redaction cost is incurred **per logged record**, not per sampled query
     (FR-81): an unsampled query pays nothing, a sampled-but-under-threshold
     query pays instrumentation only, and only records that clear
     `log_min_duration` pay for hash lookups and string generation.
     Instrumentation overhead dominates redaction by orders of magnitude.
  3. Because the GUC is read only at `ExecutorEnd`, a `PGC_SIGHUP` reload
     that lands mid-statement cannot produce a half-redacted record: the next
     record simply formats under the new setting.
- One-time-per-session `LOG` notice when `log_statement`,
  `log_min_duration_statement`, or a `%q`-bearing `log_line_prefix` would
  leak unredacted information into the same stream (FR-75).
- auto_explain never sets `es->serialize` (FR-72).
- **Correlation token (FR-76).** `errhidestmt(true)` strips the `STATEMENT:`
  line, and the existing comment in `explain_ExecutorEnd` says the module
  "relies on the existing logging of context or `debug_query_string` to
  identify just which statement is being reported". A redacted record
  therefore has no correlation handle at all, and the operator's natural
  workaround — enabling `log_min_duration_statement` — reintroduces the whole
  disclosure. Emit a per-record random token in the redacted record's
  `errmsg`, e.g. `duration: %.3f ms  ref: %s  plan:\n%s`. Constraints: draw it
  from `pg_prng` per record (not per session), never derive it from
  `queryDesc->sourceText` or from `plannedstmt->queryId` — a queryId-derived
  token would rebuild exactly the offline membership oracle that FR-37/D5
  removes. The companion entry carrying token → statement is emitted at
  `DEBUG` level so an operator can route it to a trusted destination
  separately; auto_explain does not attempt to route it itself.

## 5. Correctness notes and edge cases

- **Custom plans** inline literals as `Const` nodes → covered by FR-21 at
  `get_const_expr`. **Generic plans** print `$N` (already value-free).
  Optional synergy: a redacted record could force generic-plan display;
  not planned for v1.
- **Inheritance/partitioning**: `Append` children deparsed as parent vars —
  pseudonym keyed on mapped parent (see §4.3), so partition child names
  never surface.
- **`Values Scan`**: node alias is auto-generated (`*values*`); the rows are
  `Const`s → redacted; the RTE alias follows the `tN`/`aN` scheme.
- **`InitPlan`/`SubPlan`**: printed as `(returns $N)`; their expressions
  deparse through the same choke points.
- **JSON fix-up** in auto_explain (first byte `{`, last byte `}`) keeps
  working since redaction never changes format structure (FR-61).
- **Parallel workers**: worker records inherit the same `ExplainState` →
  same maps → consistent pseudonyms (FR-40). Two facts make this true, and
  both should be treated as invariants rather than observations:
  - *Workers never produce their own records.* `explain_ExecutorStart` forces
    `current_query_sampled = false` in a parallel worker
    (`!IsParallelWorker()`, auto_explain.c:341). Worker instrumentation
    reaches the leader through DSM (`planstate->worker_instrument`,
    `shared_info`) and is printed by the leader's single `ExplainState`, so
    one `RedactCtx` genuinely covers the whole record including every
    per-worker section.
  - *The worker-buffer swap must not carry redaction state.*
    `ExplainOpenWorker` reassigns `es->str` to a per-worker buffer and
    `ExplainCloseWorker` restores it (explain.c:5215, 5242, 5298). Pseudonym
    consistency across the merge holds **because `redact_ctx` lives on
    `ExplainState` while the swap touches only `es->str`**. If a future
    refactor were to move redaction state onto the buffer, or to allocate a
    fresh context per worker section, the same relation would get different
    pseudonyms inside and outside a worker block — silently, and without
    breaking any existing test. Keep the state on `ExplainState`.
- **A client `EXPLAIN` is also logged, under a separate contract.** A
  client-issued `EXPLAIN (ANALYZE) …` runs through the executor, so
  auto_explain logs its own record for it as well. The two records have
  independent `ExplainState`s: the client's output obeys the client's
  `REDACT` option, the log copy obeys `auto_explain.log_redact`. A user
  legitimately seeing their own unredacted plan while the log copy is
  redacted is correct behavior, not a bug — the user is already entitled to
  their own data; the log reader is not. Tests must not assume the two agree.
- **`Query Identifier`**: omitted (FR-37/D5) — although a hash, it is an
  offline membership oracle for guessed query texts.
- **No OIDs in output** (FR-43): pseudonyms are plain counters; nothing in
  the redaction path prints OIDs.

## 6. Delivery phases

| Phase | Content | Diff shape |
|---|---|---|
| 1 | `redact` flag + `EXPLAIN (REDACT)` option parsing (D3) in explain.c only: suppress expressions entirely (`Filter:`, `Output:`, `Cache Key:`, `Sort Key:`, `Table Function Call:`, …), blank object names — explicitly including **`report_triggers()`** (trigger, constraint *and* relation names, explain.c:1134/1138/1140 text and 1151/1153/1154 structured), `Custom Plan Provider`, sampling methods (FR-28/FR-18/FR-17) — omit query text, the parameter property, `Query Identifier` and settings (FR-23/FR-22/FR-37/FR-26), skip FDW and custom-scan callbacks **and `explain_per_plan_hook` / `explain_per_node_hook`** (D4/FR-25), reject `REDACT` with an extension-registered option (FR-29/FR-72), FR-75 notice. Plan shape + costs + counters remain. | explain.c, explain_state.{h,c}, auto_explain.c — no ruleutils changes |
| 2 | Pseudonymization (D1): ruleutils choke points + `select_rtable_names_for_explain` aliases + index/trigger/CTE maps | ruleutils.c, ruleutils.h, explain.c refinements |
| 3 | Allowlist GUC `auto_explain.redact_allow_schemas` (D2), documentation, optional future: FDW cooperation hook, sanitized query text | small |

Phase 1 aims at "safe but less informative"; phase 2 satisfies the full
requirements contract. Tests from requirements §8 are written against the
phase-2 contract and can be landed per phase with the corresponding FRs.

**Phase 1 is only safe if its object-name blanking is enumerated rather than
assumed.** "Blank object names" is not a single code site: the trigger
section, the sub-plan label, the window definition and the `Replaces`
property each print names through their own path, and three of those write
directly to `es->str` in text mode. The Phase 1 checklist above names
`report_triggers()` for that reason; the remaining three are covered by
FR-90, FR-91 and FR-92 and must be in the Phase 1 diff too, or Phase 1 ships
a record that still carries CTE names, window names and relation aliases.

**Phase 1's test matrix must include an ANALYZE fixture with
`log_triggers` enabled.** `ExplainPrintTriggers` is unreachable otherwise
(§1.2), so a matrix of non-ANALYZE plans will pass while FR-17 is entirely
unexercised.

## 7. Alternatives considered and rejected

- **Post-processing the rendered string in auto_explain** — rejected:
  identifiers are nested inside quoted SQL expressions across four formats
  with escaping; a scrubber is fragile and will leak (fails FR-60, FR-63).
- **Filtering centrally at `ExplainProperty*`** *(added v1.2)* — rejected, and
  worth recording because it is the cheapest-looking option. It fails twice
  over. Too late: by the time a property is emitted, `deparse_expression()` has
  already concatenated identifiers, operators, keywords and literals into one
  opaque string, so telling `zcol_ssn` from `AND` would require re-parsing it.
  Too narrow: in text format a large share of identifier output never reaches
  those functions at all (explain.c:1134/1138/1140, 1715-1716, 3075, 4550,
  4710-4718, and the bare sub-plan label). The result would be clean
  `json`/`xml`/`yaml` and leaky `text` — and `text` is the default format
  (FR-63).
- **Plan-tree mutation before explain (rewrite Consts/Vars into benign
  equivalents)** — rejected: no benign sentinel exists for arbitrary user
  types/names; mutation breaks deparse invariants and extension state.
- **Doing it from outside core via hooks** — rejected: ruleutils deparse has
  no plugin hooks (only `explain_get_index_name_hook` exists), so third-party
  coverage is impossible without in-tree changes. Note the converse is now
  also true and is a *requirement*, not a limitation: the generic
  `explain_per_plan_hook` / `explain_per_node_hook` must be **suppressed**
  under redaction (FR-25/FR-29), because a plugin holding the `ExplainState`
  can call `deparse_expression()` with a context carrying no `RedactCtx`.
- **Keying column pseudonyms on `(relid, attno)`** *(v1.1's plan; rejected in
  v1.2)* — it cannot name the columns of subquery, join, function, `VALUES`,
  CTE, ENR or tablefunc RTEs, which have no relid and whose names come from
  `rte->eref->colnames` / `expandRTE()`. Replaced by `(varno, attno)` plus the
  layer-C approach (FR-46, §4.3.2).

## 8. Risks

- ruleutils.c is a 14k-line file shared by view/rule printing; mitigations:
  redaction only activates via the explicit `RedactCtx` (NULL everywhere
  else), and existing ruleutils test suites must remain byte-identical
  (requirements §10.4).
- **Layer C widens the blast radius relative to v1.1** *(new in v1.2)*.
  `set_rtable_names()` and `set_relation_column_names()` are shared by *every*
  ruleutils caller — `pg_get_viewdef`, `pg_get_ruledef`, `pg_get_expr`,
  `pg_get_constraintdef`, FDW deparse, and every extension that calls
  `deparse_expression()`. v1.1's plan touched only leaf printers, which was a
  smaller diff but could not satisfy FR-12 for relid-less RTEs. The mitigation
  is the same in kind but must be enforced more carefully: the redaction branch
  is reachable only when a `RedactCtx` was supplied through the new
  `*_redacted` entry points, so all existing callers take the unmodified path
  bit-for-bit. This makes the byte-identical ruleutils regression run
  (requirements §10.4) a **gating** test rather than a nice-to-have.
- Third-party extension surface (D4, now extended to the generic hooks by
  FR-25/FR-29) — suppression is fail-closed but loses FDW `Remote SQL` and all
  plugin output; documented per FR-73. The interactive path additionally
  *rejects* the combination rather than silently dropping output (FR-29), which
  is a visible behavior change for anyone scripting
  `EXPLAIN (RANGE_TABLE)` — call it out in the release note.
- **The `deparse_context` reachability workaround needs an owner** (FR-64). If
  the file-scope-static option in §3 is chosen, it must be cleared under
  `PG_FINALLY`, and the assumption "deparse is not re-entrant across records"
  has to be stated where someone changing deparse will see it. This is the one
  place the design trades cleanliness for diff size, and it should be revisited
  if the static ever proves awkward.
- Future upstream rebases: choke points are more numerous than v1.1 assumed
  (roughly thirty across explain.c and ruleutils.c, §4.2-§4.3), but they remain
  individually stable functions. The rebase risk is now concentrated in the
  enumerated tables in §4.3.3 — treat those tables, and the
  `deparse_context` construction-site count asserted per FR-64, as the things
  a rebase must re-verify.
- **This tree reports `PG_VERSION = "20devel"`**, not 19, despite the workspace
  name and the "pg19" shorthand used throughout these documents. Every line
  citation in §1–§8 was read from this tree and is correct for it; treat "PG19"
  in these docs as meaning "this tree" rather than as a released version.
