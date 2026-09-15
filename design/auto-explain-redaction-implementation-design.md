# Auto-Explain Log Redaction — Implementation Design

| | |
|---|---|
| **Status** | v1.1 — aligned with [requirements v1.1](auto-explain-redaction-requirements.md), incorporating the adversarial security review (namespace-primary exemption D7, uniform constant redaction D6, `Query Identifier` omitted D5, custom-scan provider name FR-28, sampling methods, single-record mapping scope FR-45) |
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
>    in `report_triggers()` (explain.c:1099-1140) for both branches. The
>    deparse paths feeding `Output` / `Filter` / `Index Cond` /
>    `Function Call` are shared by all four formats via
>    `deparse_expression()` (call sites explain.c:2501, 2526, 2741, 2820,
>    2993, 3060, 3634).
>
> The one genuinely un-hookable surface remains `ruleutils.c` itself
> (deparse has no plugin hooks — the only explain-side hook is
> `explain_get_index_name_hook`, explain.c:4233), which is why the deparse
> choke points below require in-tree changes.

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

## 2. Architecture

```
                    auto_explain (GUC: auto_explain.log_redact)
                                   │  es->redact = true, es->redact_ctx
                                   ▼
        ┌──────────────────── ExplainState ────────────────────────┐
        │  bool redact                                             │
        │  RedactCtx *redact_ctx  (per-record pseudonym maps)      │
        └───────┬──────────────────────────────┬───────────────────┘
                │                              │
   explain.c emission points          ruleutils.c deparse points
   ─ ExplainTargetRel (tN, drop       ─ select_rtable_names_for_explain
     schema; tN/aN aliases)             (generate aliases t1/a1…)
   ─ explain_get_index_name (iN;      ─ get_variable (t1_c3, opaque
     also covers Conflict Arbiter       sequential counters, not attnos)
     Indexes, explain.c:4849)         ─ get_const_expr (? for every
   ─ report_triggers (trgN/conN,        constant, incl. NULL/true/false)
     relation name tN)                ─ generate_relation_name (tN)
   ─ CustomName / "Custom Plan        ─ generate_function_name (fN /
     Provider" blanked (FR-28,          keep if exempt)
     explain.c:1522,1662)             ─ generate_operator_name (opN /
   ─ show_tablesample method fN         keep exempt)
     (explain.c:3052)                 ─ format_type / collation sites
   ─ ExplainQueryText  → omitted        (tyN / drop)
   ─ ExplainQueryParameters
     → names only
   ─ Query Identifier  → omitted (D5)
   ─ Settings section  → omitted
```

All four output formats are covered automatically because both explain-side
properties and deparse output are format-agnostic until
`ExplainPropertyText/List` serialize them.

## 3. Redaction context

```c
/* new: src/include/commands/explain_state.h (or a small explain_redact.h) */
typedef struct RedactCtx RedactCtx;   /* opaque; defined in explain.c */
```

- `RedactCtx` holds one `HTAB` per pseudonym namespace keyed by OID (or
  `(relid, attno)` for columns), plus per-namespace counters, plus the
  allowlist state. Allocated in the query memory context (auto_explain
  already switches to `estate->es_query_cxt` before generating output).
- API used by choke points:
  `const char *explain_redact_name(RedactCtx *ctx, RedactKind kind, Oid oid)`
  → returns the pseudonym (assigning the next free number on first use), or
  the real name if the object is exempt (built-in / allowlisted).
- Exemption test (D7, namespace-primary): an object is exempt iff its
  namespace ∈ {`pg_catalog`, `information_schema`} ∪
  `auto_explain.redact_allow_schemas`. The OID range
  (`FirstNormalObjectId`, transam.h:198) is deliberately **not** used —
  initdb-time provisioning creates low-OID application objects that must
  still be redacted. Fail closed: unknown namespace / failed lookup →
  redact (substitute the pseudonym; never ERROR the record, FR-60).
- The `RedactCtx` is allocated fresh per record (per `ExplainState` /
  auto_explain log entry) and discarded afterwards (FR-45) — never cached
  across statements.
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
- `ExplainQueryText()`: skip when `es->redact` (FR-23).
- `ExplainQueryParameters()`: when redacting, build a names-only string
  (`$1, $2, …`) from `params->numParams` (FR-22); ignore `maxlen`.
- `ExplainTargetRel()`: route `objectname` / `namespace` through the
  pseudonym map (relation → `tN`, schema → omitted); keep `refname` logic
  but use the alias generated by `select_rtable_names_for_explain` (FR-10,
  FR-11, FR-13). CTE/ENR names mapped via their namespace (FR-14, FR-15).
  Function-scan `Function Name` mapped via `fN` (FR-18).
- `explain_get_index_name()`: in redact mode, ignore the hook and return the
  `iN` pseudonym (FR-16; also neutralizes hypothetical-index plugins). This
  single choke point also covers the non-scan index-name sites found by the
  security review, e.g. `Conflict Arbiter Indexes` (explain.c:4849-4895).
- `report_triggers()`: pseudonymize `tgname` (`trgN`), constraint name
  (`conN`), and the relation name (FR-17).
- Custom-scan provider name: blank `((CustomScan *) plan)->methods->CustomName`
  where the node name is built (explain.c:1522-1524) and skip the
  `Custom Plan Provider` property (explain.c:1662-1663) — core prints these
  directly, outside any suppressed callback (FR-28).
- `show_tablesample()`: pseudonymize the method name from
  `get_func_name(tsc->tsmhandler)` (explain.c:3052) — parameters and the
  `REPEATABLE` seed are deparsed constants, covered in ruleutils (FR-18,
  FR-21).
- `ExplainPrintSettings()` / settings section: skip when redacting (FR-26).
- `Query Identifier` property: skip when redacting (FR-37/D5).
- FDW/custom-scan explain callbacks and
  `apply_extension_options()` path in auto_explain: skip when redacting
  (D4=suppress; FR-25, FR-73).

### 4.3 `src/backend/utils/adt/ruleutils.c` (the bulk of the work)
- Extend the private `deparse_context` (ruleutils.c:112-128) with
  `RedactCtx *redact;`.
- New exported entry point(s) in `ruleutils.h`:
  - `List *select_rtable_names_for_explain_redacted(List *rtable, Bitmapset *rels_used, RedactCtx *ctx)` — or add a
    `RedactCtx *` parameter to the existing function; it generates the
    `tN`/`aN` aliases that every later deparse and `ExplainTargetRel` reuse
    (this is the single point where alias consistency is achieved).
  - `deparse_expression_redacted(Node *expr, List *dpcontext, bool forceprefix, bool showimplicit, RedactCtx *ctx)`
    — thin wrapper that installs `ctx` into the deparse_context.
  (Exact signatures TBD; the constraint is that `deparse_context` stays
  private and no existing caller changes behavior.)
- Choke-point edits, each guarded by `if (context->redact)`:
  - `get_variable()`: substitute column pseudonym (FR-12) — note appendrel
    parent mapping happens before the name lookup, so pseudonyms key on the
    (possibly mapped) parent rel, keeping inheritance output stable.
  - `get_const_expr()`: **every** constant — including `NULL`, `true`,
    `false` (D6: a `NULL` literal asserts real-row nullability, so no value
    class is exempt) — becomes `?` plus the existing type-label logic
    (FR-21). Type label routed through type pseudonymization (FR-20).
    `get_const_collation()`: drop or pseudonymize user collations.
  - `generate_relation_name()`: `tN`, drop schema qualification (FR-10/11).
  - `generate_function_name()`: `fN` for user-defined, keep built-in —
    keep the `func_get_detail()` resolution result in mind (resolution
    still runs; only the printed name changes) (FR-18).
  - `generate_operator_name()`: built-in operators print as today;
    user-defined → `op1` (FR-19).
  - `format_type_with_typemod` sites inside ruleutils deparse paths: route
    through type pseudonymization (FR-20).
- `pg_get_indexdef_*`, view-rule deparsing and other ruleutils callers are
  **unaffected**: they never set a `RedactCtx`.

### 4.4 `contrib/auto_explain/auto_explain.c`
- New GUCs:
  - `auto_explain.log_redact` (bool, `off`, `PGC_SUSET`) — FR-1
  - `auto_explain.redact_allow_schemas` (string list, `PGC_SUSET`) — FR-51/D7
- In `explain_ExecutorEnd()` (auto_explain.c:438-462): set `es->redact`,
  skip `ExplainQueryText()` (FR-23), pass names-only params (FR-22), skip
  `apply_extension_options()` under D4 (FR-73). Keep `errhidestmt(true)`
  (FR-70).
- One-time-per-session `LOG` notice when `log_statement`,
  `log_min_duration_statement`, or a `%q`-bearing `log_line_prefix` would
  leak unredacted information into the same stream (FR-75).
- auto_explain never sets `es->serialize` (FR-72).

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
  same maps → consistent pseudonyms (FR-40).
- **`Query Identifier`**: omitted (FR-37/D5) — although a hash, it is an
  offline membership oracle for guessed query texts.
- **No OIDs in output** (FR-43): pseudonyms are plain counters; nothing in
  the redaction path prints OIDs.

## 6. Delivery phases

| Phase | Content | Diff shape |
|---|---|---|
| 1 | `redact` flag + `EXPLAIN (REDACT)` option parsing (D3) in explain.c only: suppress expressions entirely (`Filter:`, `Output:`, …), blank object names (incl. `Custom Plan Provider`, sampling methods — FR-28/FR-18), omit query text/params/`Query Identifier`/settings (FR-23/FR-22/FR-37/FR-26), skip FDW/custom-scan callbacks (D4), FR-75 notice. Plan shape + costs + counters remain. | explain.c, explain_state.{h,c}, auto_explain.c — no ruleutils changes |
| 2 | Pseudonymization (D1): ruleutils choke points + `select_rtable_names_for_explain` aliases + index/trigger/CTE maps | ruleutils.c, ruleutils.h, explain.c refinements |
| 3 | Allowlist GUC `auto_explain.redact_allow_schemas` (D2), documentation, optional future: FDW cooperation hook, sanitized query text | small |

Phase 1 alone satisfies "safe but less informative"; phase 2 satisfies the
full requirements contract. Tests from requirements §8 are written against
the phase-2 contract and can be landed per phase with the corresponding FRs.

## 7. Alternatives considered and rejected

- **Post-processing the rendered string in auto_explain** — rejected:
  identifiers are nested inside quoted SQL expressions across four formats
  with escaping; a scrubber is fragile and will leak (fails FR-60).
- **Plan-tree mutation before explain (rewrite Consts/Vars into benign
  equivalents)** — rejected: no benign sentinel exists for arbitrary user
  types/names; mutation breaks deparse invariants and extension state.
- **Doing it from outside core via hooks** — rejected: ruleutils deparse has
  no plugin hooks (only `explain_get_index_name_hook` exists), so third-party
  coverage is impossible without in-tree changes.

## 8. Risks

- ruleutils.c is a 14k-line file shared by view/rule printing; mitigations:
  redaction only activates via the explicit `RedactCtx` (NULL everywhere
  else), and existing ruleutils test suites must remain byte-identical
  (requirements §8.4).
- Third-party extension surface (D4) — suppressing callbacks is fail-closed
  but loses FDW insight; documented per FR-73.
- Future upstream rebases: choke points are few and stable
  (`get_variable`, `get_const_expr`, `generate_*_name`,
  `select_rtable_names_for_explain`), keeping the fork delta reviewable.
