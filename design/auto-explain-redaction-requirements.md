# Auto-Explain Log Redaction — Functional Requirements

| | |
|---|---|
| **Status** | v1.2 — incorporates the source-code leak-path audit (2026-09-15); decision points **D1–D10** resolved (§7); leak-path test catalog added (§10) |
| **Component** | `contrib/auto_explain`, `EXPLAIN` (core) |
| **Related** | [auto-explain-redaction-implementation-design.md](auto-explain-redaction-implementation-design.md) |
| **Terminology** | "redacted record" = one auto-explain log entry or one `EXPLAIN (REDACT)` result |

> **v1.2 note.** v1.1 was written from the security review of the *design*. v1.2
> is the result of auditing the *code* (`src/backend/commands/explain.c`,
> `src/backend/utils/adt/ruleutils.c`, `contrib/auto_explain`,
> `contrib/pg_overexplain`) for emission sites the v1.1 contract did not reach.
> Eleven additional sensitive items were found (§5.2.1), one requirement
> triple was mutually unsatisfiable (FR-42/FR-45/§8.7 → D8), and one
> combination promised by FR-4 leaks the entire range table (FR-29). Items
> marked *(rev. code audit)* are new or changed in v1.2. Every finding has a
> corresponding entry in §10 so it becomes a test rather than a memory.

---

## 1. Problem statement

`auto_explain` log records contain, verbatim: the SQL query text, parameter
values, table/column/index/trigger names, and inlined literal values. Any
process that can read the PostgreSQL log (log shippers, aggregators, SaaS
observability backends, ticket systems, support vendors) therefore sees the
application's schema and data. Organizations that must not expose this
information today have no option other than disabling auto_explain entirely,
which forfeits the diagnostic value of the plans.

We need a logging mode in which auto-explain output is **stripped of
user-defined information** — table names, column names, parameter values,
non-core (user-defined) function names, and every other name or value that
originates from user objects or user data — while remaining useful for
performance analysis.

## 2. Goals

1. A redacted auto-explain record must be safe to ship to parties who must
   not learn **schema identifiers** (object names) or **data values**.
   Schema *shape and statistics* (relation/column/index/trigger counts, plan
   widths, cardinalities, timings) are knowingly retained — see the residual
   risk register, §9.
2. A redacted record must retain enough structure to support performance
   diagnosis: plan shape, join algorithms, cost/row estimates, actual rows,
   loops, timings, buffer/WAL/IO usage, worker activity, trigger timings.
3. Identifiers must be replaced with **consistent pseudonyms** so that plan
   structure remains interpretable (e.g. a self-join still reads as two scans
   of the same object).
4. The feature must be cheap enough to leave permanently enabled in
   production.

## 3. Non-goals

- Not a security boundary against administrators with full server access;
  timing/row-count side channels remain. The goal is safe log *sharing*.
- Does not sanitize other logging channels: `log_statement`,
  `log_min_duration_statement`, `log_line_prefix`, `csvlog`/`jsonlog`
  statement fields, `pg_stat_statements` texts, or `debug_query_string`.
  Interactions are documented and surfaced by FR-75 (§7.7), not enforced.
- **Does not sanitize the log-record envelope.** The csvlog/jsonlog/syslog
  record carrying the plan also carries user name, database name,
  `application_name`, client address, and session identifiers. These fields
  are outside auto_explain's control and out of scope (FR-75 mitigates by
  warning). Goal 1 covers the *plan record content* only.
- Redacted output is **not valid SQL** and is not required to re-parse or to
  be re-executable.
- No retroactive redaction of already-written log files.

## 3.1 Deferred candidates

Recorded here rather than dropped, because each was investigated far enough to
establish feasibility and the reasoning is worth keeping.

### 3.1.1 Redacted query text (deferred — technically feasible)

FR-23 omits `Query Text` entirely. A future version could instead log the
statement with its identifiers and literals replaced by the *same* pseudonyms the
plan uses, giving a reader the shape of the statement without its content.

**Feasible, and the machinery already exists.** `get_query_def()`
(`ruleutils.c:5632`) already reverse-compiles a `Query` into SQL text — it is what
`pg_get_viewdef` uses. Re-parsing `queryDesc->sourceText` into a `Query` at log
time and deparsing it with a `RedactCtx` installed would route every name and
constant through the same leaf emitters this design already modifies
(`get_variable`, `get_const_expr`, `generate_relation_name`,
`generate_function_name`), so no new redaction logic would be required.

**The binding constraint is consistency, and it selects the approach.** The text
and the plan must agree: a record where the plan says `t1` and the text says `t7`
is worse than one with no text at all, because it invites a wrong conclusion.
Reverse-compiling from the tree gets this for free, since both passes share one
`RedactCtx` keyed by OID. Two cheaper alternatives were considered and do not
compose:

- *Constant-location splicing*, as `pg_stat_statements` does with
  `jstate->clocations` and `generate_normalized_query()`. Cheap and already proven
  in the tree, but it reaches literals only — every identifier survives.
- *Lexing the original text* and swapping identifier tokens. Preserves the
  author's formatting, and is a genuinely different proposition from the
  string-scrubbing rejected in the implementation design (which concerned the
  *finished plan output*, where names sit inside rendered expressions across four
  formats). It fails on consistency: a lexer has only an identifier's text, while
  pseudonyms are keyed by OID, and text→OID is ambiguous as soon as the same name
  exists in two schemas or an alias shadows a table. Resolving that is name
  resolution, which is the parser's job — so it reduces to the tree approach.

**Costs to weigh when it is picked up.** A parse per logged record, on the
record-emission path. Output is canonicalised SQL rather than the author's
original text, so comments and formatting are lost. And a second consumer of the
`RedactCtx` means its lifetime rules get a second caller to satisfy.

**Why it might be worth it.** The query text is the only place that names objects
the planner optimised away; the plan cannot show those by definition. A reviewer
who needs to know what a statement *asked for*, rather than what was executed,
has no other source.

### 3.1.2 Column numbering discloses the column's position (FR-12 not met)

**Status: known shortfall, landed in T08, needs a decision.**

FR-12 requires the numeric part of a column pseudonym to be an opaque per-relation
counter and explicitly *not* the attribute number — a table whose sensitive column
sits ninth must not surface `_c9` unless that column is the ninth one the plan
touched. That is not what T08 produces. `SELECT c_third FROM t` yields `t1_c3`,
and a reader of a redacted record can therefore infer that the printed column is
the third column of its table.

The cause is structural rather than an oversight.
`set_relation_column_names()` must fill in a name for **every** column of the
range-table entry, because `get_variable()` reads the array by attribute number,
and it runs while the deparse context is being built — before anything knows which
columns the plan will actually reference. Numbering in assignment order therefore
yields the column's position, which for a relation with no dropped columns equals
its attnum.

It is also not fixable by choosing a different deterministic function of the
attnum. Any such mapping is invertible by a reader who knows the scheme, and FR-42
requires the same plan to produce the same pseudonyms, so the permutation cannot be
randomised per record either.

What is disclosed is schema shape, not data: the column's ordinal position, and by
implication that the table has at least that many columns. It sits in the same
category as the plan shape that §9 already accepts, but FR-12 was written
specifically to exclude it, so the gap should be closed or the requirement
amended.

Two ways to close it, neither attempted in T08:

- **Lazy assignment.** Leave `colinfo->colnames[]` entries NULL and issue a name
  on first read, so the counter advances only for columns the plan actually
  prints. Requires every reader of that array to go through an accessor;
  `get_variable()` is the main one but not the only one.
- **Reference-set precomputation.** Walk the plan tree once when building the
  context, collect the set of `(varno, attno)` pairs that appear in any Var, and
  number only those. More contained than lazy assignment, and it makes "distinct
  columns used" literal, at the cost of a second pass over the plan.

Until one is done, FR-12 should be read as "the number is the column's position
within its range-table entry, never its name" rather than as written.

*(rev. T15: **not resolved, and not even partly.** Worth saying explicitly,
because T15 is the first task that puts pseudonyms back into output and a reader
could reasonably assume Stage 4 touched this. It did not. The shortfall is in
`set_relation_column_names()`, which T15 does not go near, and neither remedy
above was attempted. What did change is the shortfall's **observability**, and
only in the negative direction of "still zero": a column pseudonym is printed
only inside an expression property — `Filter`, `Output`, `Index Cond`, `Sort
Key`, `Hash Cond`, `Cache Key` — and every one of those is still suppressed, as
measured across the whole §10.2 fixture catalog. So `t1_c3` cannot be seen in a
redacted record today and the disclosure is latent. **T21 is the task that makes
it real**, which makes T21 the deadline for the decision this section asks for,
not T15.)*

### 3.1.3 Rendering of `Query Parameters` (open question, not yet decided)

D10 and FR-22 omit the property outright. That decision has been challenged and
is not settled. Two objections stand:

- The stated reason — that `$1, $2` discloses `params->numParams` — is weak
  relative to what the design deliberately keeps. Row counts, costs and plan
  shape describe the workload far more precisely than a parameter count, and §9
  already accepts plan-shape disclosure.
- It is inconsistent with FR-21, which renders an inline literal as `?` *plus its
  type label* (`?::text`). The same secret therefore discloses more when written
  into the SQL than when bound as a parameter, and nothing justifies the
  asymmetry.

The sound part of D10 is narrower than it claims: with
`log_parameter_max_length = 0` the property is already suppressed, so printing
`$1, $2` under redaction would disclose more than that configuration discloses
today, and enabling a protection must never increase disclosure. That is
satisfied by respecting `maxlen` rather than by omitting unconditionally — place
the redaction test *after* the existing `maxlen == 0` check.

Resolving this requires amending FR-22 and D10 and is a prerequisite to changing
the code.

## 4. Definitions

- **Exempt object** — an object whose **namespace** is `pg_catalog`,
  `information_schema`, or listed in the allowlist option (FR-51). Names of
  exempt objects may appear in redacted records. *(Revised by security
  review: the primary test is namespace-based; see D7 and FR-50 for why the
  OID range alone is unsafe.)*
- **User-defined object** — any object that is not exempt, regardless of its
  OID. This includes objects created by post-initdb extensions *and*
  application objects created during initdb-time provisioning (which carry
  low OIDs but are not built-in).
- **Pseudonym** — a stable, generated, non-reversible substitute name
  (`t1`, `c3`, `f2`, …) assigned per redacted record.
- **Sensitive item** — any string or value listed in §5.2.

## 5. Functional requirements

Requirement IDs are stable and testable. Each FR is verified by the
acceptance tests in §8. Items marked *(rev. security review)* were added or
changed by the adversarial review of v1.0.

### 5.1 Activation

| ID | Requirement |
|---|---|
| FR-1 | A boolean option `auto_explain.log_redact`, default `off`, context **`PGC_SIGHUP`** *(rev. code audit; was `PGC_SUSET` — see D9)*, controls redacted logging. When `off`, output must be byte-identical to today's behavior. |
| FR-2 | When enabled, redaction applies to every plan auto_explain logs: top-level statements and nested statements, all log formats, all log levels, sampled and unsampled-per-`sample_rate` alike. |
| FR-3 | Core `EXPLAIN` gains an option `REDACT` (`EXPLAIN (REDACT ON)` / `EXPLAIN (REDACT TRUE)`), producing the same redaction contract interactively, primarily so the behavior is regression-testable without loading auto_explain. |
| FR-4 | Redaction is orthogonal to every existing auto_explain option (`log_analyze`, `log_verbose`, `log_buffers`, `log_wal`, `log_io`, `log_timing`, `log_triggers`, `log_settings`, `log_format`, `log_level`, `log_nested_statements`, `log_min_duration`, `log_parameter_max_length`, `sample_rate`) and to every **core** `EXPLAIN` option except where §7 explicitly forbids a combination. Orthogonality **does not extend to extension-registered `EXPLAIN` options or to `auto_explain.log_extension_options`**: those are governed by FR-25 and FR-29 *(rev. code audit: the v1.1 wording promised a combination that leaks — see FR-29)*. |

### 5.2 Items that must be redacted

In every redacted record, the following must not appear in **any** field, in
**any** output format:

| ID | Item | Required treatment |
|---|---|---|
| FR-10 | Table, view, materialized view, foreign table, and partitioned-table names (scan and `INSERT`/`UPDATE`/`DELETE`/`MERGE`/CTAS targets, including the relation names shown in the trigger section) *(rev. T15: landed for every site except the trigger section, which is unreachable until T18. Until T15 this requirement had no coverage at all in the sense that matters: T04 suppressed the whole scan target, so every "clean" verdict in §10.2 was satisfied by an empty line. The scan and DML-target rows now assert a pseudonym is present where the real name was, not that nothing is.)* | pseudonym `t1`, `t2`, … |
| FR-11 | Schema/namespace names of redacted objects | omitted *(rev. T15: landed and verified in all four formats — text qualifies the object name as `schema.table` while json/xml/yaml emit a separate `Schema` property, so the two are separate assertions. Note what is **not** omitted: an exempt relation keeps its schema, and keeps it `VERBOSE`-gated exactly as without redaction, because exemption restores the original code path rather than adding a new one.)* |
| FR-12 | Column names — of **every** range-table-entry kind, not only base relations: subquery output names, join output names, function-scan and `ROWS FROM` column aliases, `VALUES` column names, CTE and ENR column names, tablefunc column names *(rev. code audit: for these RTE kinds the printed name comes from `rte->eref->colnames` / `expandRTE()` and there is **no** relid and no catalog attno to key a pseudonym on — see FR-46)* | pseudonym `t1_c3`, where the numeric part is an **opaque sequential per-RTE counter** *(rev. security review: must never be the physical attno, which leaks ordinal position and column count; see FR-43)* |
| FR-13 | User-visible relation aliases / refnames, including (a) the value used when no alias was assigned because the RTE is absent from the EXPLAIN `rels_used` set, and (b) `RETURNING WITH (OLD AS …, NEW AS …)` aliases *(rev. code audit: both bypass the alias list produced for EXPLAIN)* *(rev. T15: (a) landed and covered. (b) is **not** covered yet and its §10.2 assertion is still vacuous — the `OLD`/`NEW` alias reaches output only as a `Var` prefix inside the `Output` list, which stays suppressed until T21, so there is nothing for the fixture to grep either way. "Derived from the relation pseudonym" is exact and load-bearing: an unaliased relation's reference name is keyed by **OID**, so it equals the object name and EXPLAIN prints one identifier, not two; keying it by range-table index would turn every unaliased scan line into `Seq Scan on t1 a1` and change the shape of the output rather than its content. One exception, measured: two unaliased RTEs of the *same* relation both derive `t1`, collide, and the second takes a `_1` suffix — `Seq Scan on t1 t1_1`. Identical in shape to the unredacted `zsec_customers zsec_customers_1`, so nothing extra is disclosed, but it contradicts FR-47's claim that pseudonyms make the uniquifier a no-op.)* | derived from the relation pseudonym, or `a1`, `a2`, … when a distinct alias must be shown |
| FR-14 | CTE names, in **every** property that can carry one — the scan target, the sub-plan label, and any deparsed sub-plan reference *(rev. code audit: see FR-90)* | `cte1`, `cte2`, … |
| FR-15 | Ephemeral named tuplestore (ENR) names | `enr1`, … *(rev. T15: **not reachable from EXPLAIN.** `ExplainNode()` omits `T_NamedTuplestoreScan` from the node list that calls `ExplainScanTarget()`, so a named tuplestore scan prints no `Tuplestore Name` and no `Alias` in any format, redacted or not — measured from inside a trigger with a `REFERENCING NEW TABLE` transition table, which is the only way to get an ENR into a plan. The `T_NamedTuplestoreScan` case in `ExplainTargetRel()` has no caller. FR-15 therefore joins FR-94 and FR-98c as a **guard** for a printer path EXPLAIN cannot reach, and T17 has nothing to pseudonymize here unless upstream adds the missing case. A negative control is pinned in the regression file so that if it ever does, the change is reported rather than shipped silently.)* |
| FR-16 | Index names in **any** property: index scans (`Index Name`), and non-scan sites such as `Conflict Arbiter Indexes` *(rev. security review)* *(rev. T16: landed, and this is the first entry in the table with coverage on every surface it claims. All four are asserted, separately, because three different code paths feed them: `Index Scan` and `Index Only Scan` share `ExplainIndexScanDetails()`, `Bitmap Index Scan` has its own inline emission in `ExplainNode()`, and `Conflict Arbiter Indexes` is assembled in `show_modifytable_info()` and never went through the shared function. Until T16 the two rows §10.2 holds for this requirement were vacuous — T04 suppressed the name and skipped the arbiter gather entirely, so “clean” meant an absent property rather than a pseudonymized one. Also verified: the arbiter list and an index scan on the same index print the **same** `iN` (see FR-40), and a `pg_catalog` index keeps its real name.)* | `i1`, `i2`, … |
| FR-17 | Trigger names and constraint names (trigger section, `Trigger Name` property) | `trg1`, … / `con1`, … |
| FR-18 | User-defined function, procedure, aggregate, window-function names — in every emission path: deparsed expressions, `Function Name` / `Function Call` properties, Function-Scan targets, **and TABLESAMPLE method names** (`Sampling:`, `Sampling Method`), which core resolves via a direct function-name lookup rather than the expression deparser *(rev. security review)* | `f1(…)`, …; argument expressions redacted recursively |
| FR-19 | User-defined operator names in expressions | `op1`; **exempt** operators (`=`, `<`, `+`, …) kept for readability |
| FR-20 | User-defined **type** names appearing in casts/labels (enums, domains, composite types: `::my_enum`) and user-defined **collation** names (`COLLATE …`) | pseudonym `ty1` / collation omitted or `coll1` |
| FR-21 | **All** constant/literal values in any decompiled expression (`Filter:`, `Index Cond:`, `Output:`, `Hash Cond:`, `VALUES` rows, `One-Time Filter`, `TABLESAMPLE` parameters and `REPEATABLE` seeds, …) — uniformly, including `NULL`, `true`, and `false` *(rev. security review: a `NULL` literal asserts a real row's nullability — data, not structure; uniform redaction is simpler and fail-closed)*. This obligation is on the **value**, not on one code path: constants that are printed by reading the datum directly rather than through the normal constant printer, and constants printed through a freshly-constructed deparse context, are equally in scope *(rev. code audit: see FR-98 and FR-64)* | replaced by `?` plus the existing type label (`?::text`), preserving type information while removing the value |
| FR-22 | Parameter values: the `Query Parameters` property must be **omitted entirely** from redacted records *(rev. code audit; changed by D10 — v1.1's "names only" rendering disclosed `params->numParams`, i.e. the parameter count including parameters the plan never used, in cases where `log_parameter_max_length = 0` suppresses the property today. Redaction must not be net-additive.)* | omitted |
| FR-23 | Query text: the `Query Text` property must be omitted in redacted records | omitted |
| FR-24 | Column definitions **and path/plan strings** of table functions (`json_table` / `xmltable`): column names, and JSON path literals such as `'$.ssn'` which embed user key names and may not flow through the constant path *(rev. security review; fail-closed: if a path string cannot be redacted structurally, the property is omitted)* | column names per FR-12; path strings `?` or property omitted |
| FR-25 | Text emitted by third-party code paths: FDW `Remote SQL` and custom-scan callback output, extension explain options (`log_extension_options` / `apply_extension_options`), **and the generic per-plan and per-node EXPLAIN plugin hooks** *(rev. code audit: these two hooks are not covered by the FDW/custom-scan wording and are the mechanism by which extensions inject arbitrary output; they also receive the `ExplainState` and the `PlanState`, so a plugin can re-enter expression deparsing with its own context and bypass every deparse-side control)* | suppressed: none of these callbacks or hooks are invoked in redacted records *(rev. T16: for `explain_get_index_name_hook` this is now enforced **inside** `explain_get_index_name()` rather than at its call sites. T04 checked `es->redact` at each of the two callers, which skipped the call and therefore the hook, but only for the callers that existed then. The guard was moved into the function so that the hook is unreachable under redaction for every present and future caller — a call-site check cannot make the function safe for the next caller someone adds. Note the direction: this is the opposite of what T14 had to do with `get_opclass_name()`, whose guard went **outward** to its call sites because one caller, `pg_get_indexdef`, must never redact. `explain_get_index_name()` is static and EXPLAIN-only and has no such caller, so inward is correct for it and the two are deliberately inconsistent.)* |
| FR-28 | The extension-defined custom-scan provider name, printed **by core itself** as `Custom Scan (<name>)` and the `Custom Plan Provider` property — this does not come from the suppressed callbacks *(rev. security review)* | blanked/omitted |
| FR-29 | An extension-registered `EXPLAIN` option that has already been parsed into the `ExplainState` before redaction takes effect *(rev. code audit: `EXPLAIN (REDACT, RANGE_TABLE)` with the in-tree `pg_overexplain` loaded emits the complete range table — per-RTE `Alias`, `Eref` alias **and every column name**, schema-qualified `Relation`, `Relation Kind`, `CTE Name`, `ENR Name`, and the sub-plan name — none of which the plan-body contract touches. Suppressing option *application* (FR-25) closes the `log_extension_options` route but not the `EXPLAIN (…)` route, because the option is set by the option parser, not by the extension callback.)* | `REDACT` combined with any extension-registered `EXPLAIN` option is rejected with an `ERROR` (see FR-72); in auto_explain, extension options are ignored (FR-73) |
| FR-26 | The `Settings` section (GUC names/values; `search_path` etc. reveal schemas) | excluded from redacted records |
| FR-37 | `Query Identifier`: the queryId is a deterministic, publicly specified hash of the parse tree — an offline dictionary attack can confirm that a specific guessed query ran *(rev. security review)* | **omitted** from redacted records |
| FR-27 | `xmltable`/`json_table` function names are core keywords | kept |

Exempt objects (per the §4 definition) are **not** sensitive: `pg_catalog`
function names, core operators, core type names (`::integer`), `btree` index
methods, etc. remain visible.

### 5.2.1 Additional sensitive items found by the code audit (v1.2)

Each of these is a name or value that reaches redacted output through a path
the v1.1 contract did not name. They are listed separately from §5.2 so the
v1.2 delta stays reviewable; they carry the same weight as §5.2. Every entry
has a test in §10.

| ID | Item | Required treatment |
|---|---|---|
| FR-90 | Sub-plan labels. The `Subplan Name` property (and its text-mode equivalent) is built by prefixing a planner-assigned plan name with `CTE `/`InitPlan `/`SubPlan `, and that plan name is seeded **verbatim from the CTE name** for CTE sub-plans and **from the subquery's alias** for sub-query sub-plans. The same string is re-emitted inside deparsed expressions as `(hashed SubPlan <name>).colN`. Without this requirement a record reads `CTE Name: cte1` on one line and `Subplan Name: CTE secret_customers_cte` on the line above it. | the label keeps its `CTE `/`InitPlan `/`SubPlan ` prefix; the name part becomes `sp1`, `sp2`, … (and, where the sub-plan corresponds to a CTE, the *same* pseudonym as FR-14 assigns to that CTE, so the two lines remain relatable) |
| FR-91 | Window names. The `Window` property prints the user's `WINDOW w AS (…)` name, and deparsed `Output` prints `OVER <name>` for every window function. Neither is `VERBOSE`-gated. | `w1`, `w2`, …; the same pseudonym in both places |
| FR-92 | The relation reference names listed by the `Replaces` property (emitted when a scan/join/aggregate was replaced by a `Result` node). | per FR-13 *(rev. T15: landed. All three forms T01 found are now pinned in their redacted rendering — `Replaces: Scan on t1`, `Replaces: Join on a1, a2`, and `Replaces: MinMaxAggregate` with no name. The counting loop always ran under T04's suppression because it decides whether the line appears at all; T15 restored the names it was building and withholding.)* |
| FR-93 | Composite-type field names: the field name printed for a field selection (`(col).field`), and the field name printed for composite/array assignment in an `INSERT`/`UPDATE` target list that EXPLAIN displays. These are resolved from the composite type's tuple descriptor, from a row expression's column-name list, or from the RTE's column list — **never** through the ordinary column-name path, so FR-12's treatment does not reach them. | `fld1`, `fld2`, … per record; a field of a redacted composite type is never printed in full |
| FR-94 | Named-argument labels in a function call (`f(argname => …)`). *(Corrected by T01: **not reachable from EXPLAIN.** The parser resolves named notation to positional order and discards the `NamedArgExpr` wrapper, so `f(argname => x)` deparses as `f(x)` — verified with arguments given out of order, the case that forces reordering and so had the best chance of preserving the labels. ruleutils' `T_NamedArgExpr` branch therefore serves raw parse trees, such as a stored default printed by `pg_get_expr()`, not plan trees. Implement as a **guard**, like FR-98c, and keep the negative control pinned so that if labels ever start surviving into plans it fails rather than shipping silently.)* | `arg1`, `arg2`, … — or the `name =>` decoration omitted entirely (positional rendering), which is also acceptable since redacted output need not re-parse (§3) |
| FR-95 | XML construction names: the `XMLELEMENT`/`XMLPI` element name, the `XMLATTRIBUTES`/`XMLFOREST` attribute labels, `XMLNAMESPACES` prefixes, and the `COLUMNS` column names of an `XMLTABLE`. These are plain strings on the expression node, **not** constants, so FR-21 does not reach them. Note these appear in `Filter`, which is not `VERBOSE`-gated — not only in the `VERBOSE`-only table-function property. | the construct is **collapsed**: an `XmlExpr` prints as `XMLEXPR(...)`, an `XMLTABLE` table function as `XMLTABLE(...)`, and nothing inside either is deparsed, so none of these names is printed at all. *(rev. T13: was `xml1`, `xml2`, … Pseudonymizing the names **inside** XML and JSON payloads was abandoned as a corner case that did not pay for itself. It took ten guarded deparse sites, five helpers, a pre-order walk of the path tree to keep a `PLAN` clause agreeing with the path labels it names, and a search of the range table for the node's own `varno` to keep a `COLUMNS` entry agreeing with the `Output` list — and that last one has a failure mode, measured as reachable, where a parameterized `LATERAL` scan copies the `TableFunc`, the pointer search finds nothing, and the two disagree. Collapsing costs three guards and is leak-proof by inspection. The keyword is kept, not blanked: it is SQL vocabulary rather than user data, on the same footing as the `pg_catalog` function and operator names §10.4 pins as still printing, and it tells a reader what kind of thing stood here instead of leaving an unexplained gap. **Given up deliberately:** a `Var` inside a collapsed construct no longer prints its column pseudonym, so the record no longer shows which columns fed the construct.)* |
| FR-96 | JSON/XML path *labels* and `PASSING` labels: the `… AS <name>` given to a `JSON_TABLE` root path, to each `NESTED PATH`, to each name in a `PLAN` clause, and to each `PASSING` argument of `JSON_TABLE`/`JSON_QUERY`/`JSON_VALUE`/`JSON_EXISTS`/`XMLTABLE`, plus a `JSON_TABLE` `COLUMNS` column name. FR-24 covers the path *string* because it is a constant; these labels are raw identifiers. | collapsed exactly as in FR-95: a `JSON_QUERY`/`JSON_VALUE`/`JSON_EXISTS` expression prints as `JSONEXPR(...)` and a `JSON_TABLE` table function as `JSON_TABLE(...)`. *(rev. T13: was `path1`, `path2`, … / `arg1`, …; same rationale and same deliberate loss as FR-95, whose note carries both. `JSON_OBJECT` and `JSON_ARRAY` are **not** collapsed and need no guard — they carry no raw identifier, their keys are `Const`s, and they already print as `JSON_OBJECT(?::unknown : t1_c1 …)` under FR-21.)* |
| FR-97 | Cursor names, printed as `CURRENT OF <name>` inside the `TID Cond` of an `UPDATE`/`DELETE … WHERE CURRENT OF`. Cursor names are application-chosen identifiers. | `cur1`, `cur2`, … |
| FR-98 | Names and values that reach output through a *second*, non-primary code path, and are therefore missed by a fix applied only at the primary path: (a) the `COLLATE` and `USING` decorations appended to sort keys, which are assembled from a raw collation-name and a raw operator-name lookup **after** expression deparsing has finished; (b) collation names attached by an explicit `COLLATE` expression and by an `ON CONFLICT` inference element; (c) operator-class names, including their schema qualification, printed for an inference element; (d) constants read directly out of the node datum by the SQL-syntax function printer — the `EXTRACT(<field> FROM …)` field. ~~`IS <form> NORMALIZED`, `NORMALIZE(…, <form>)`~~ *(rev. T14: the two normalization forms are **deliberately kept**. They read like the same pattern, and they are not: the form is a grammar keyword, so no user-derived string can reach those lines. Measured, both variants are syntax errors. Same footing as the built-in operator names FR-19 exempts.)* | per FR-19 / FR-20 / FR-21 as applicable; `opc1` for operator classes |
| FR-99 | Sequence names. A serial/identity default is printed as `nextval('<sequence>')` in an `INSERT` target list. *(Amends FR-10's object list, which did not name sequences.)* | per FR-10 (`t1`); note the pseudonym is emitted **inside** a quoted literal, so the surrounding `nextval('…')` shape must be preserved (FR-61) |

### 5.3 Items that must be preserved

| ID | Item |
|---|---|
| FR-30 | Complete plan node tree: node types, parent/child relationships, join algorithms, scan types, `Parent Relationship`, subplan structure, `Subplans Removed`, `Inner Unique` |
| FR-31 | Planner estimates: costs, plan rows, plan width, `Rows Removed by Filter/Join Filter` |
| FR-32 | Actual rows, loops, actual time, `Rows Removed by Index Recheck` (when `log_analyze`) |
| FR-33 | Buffer, WAL, I/O usage (`Shared Hit Blocks`, `Temp Read Blocks`, …) |
| FR-34 | Parallel-worker structure and per-worker stats |
| FR-35 | JIT section (timings only) |
| FR-36 | Whole-query timing. *(Corrected by T01: the two channels differ. `EXPLAIN (ANALYZE)` emits `Planning Time` and `Execution Time` properties, because `ExplainOnePlan()` produces them. **auto_explain emits neither** — it calls `ExplainPrintPlan()` directly, and the duration reaches the log through the `ereport` message prefix, `duration: N ms plan:`. So in the auto_explain channel this requirement is about that prefix; the two named properties exist only in the interactive channel. Tests must assert against the right one or they pass vacuously.)* Trigger timing numbers per FR-38. |
| FR-38 | Trigger *timings and counts* (names redacted per FR-17) |

### 5.4 Pseudonym quality

| ID | Requirement |
|---|---|
| FR-40 | Within one redacted record, the same object always maps to the same pseudonym, and different objects map to different pseudonyms (per namespace: `t*`, `i*`, `f*`, `cte*`, `enr*`, `trg*`, `con*`, `ty*`, `op*`, `a*`, and *(rev. code audit)* `sp*`, `w*`, `fld*`, `cur*`, `coll*`, `opc*` *(rev. T13: `arg*`, `xml*` and `path*` dropped from this list. No code assigns them: FR-94's labels never survive into a plan tree, and FR-95/FR-96's names are now collapsed rather than pseudonymized. The matching `RedactKind` enumerators were deleted rather than left advertising coverage that does not exist.)*). |
| FR-41 | Pseudonyms are ASCII, match `[a-z]+[0-9]+`, and never require quoting. |
| FR-42 | Pseudonym assignment is deterministic for a given plan (traversal order), so identical queries produce comparable records. **This is retained deliberately and it does mean that two records for the same query shape carry the same pseudonyms**; the residual correlation is accepted and recorded in §9 *(rev. code audit: resolved against FR-45 by D8)* |
| FR-45 | The pseudonym mapping holds **no state that outlives one record**: it is freshly allocated when record generation starts and discarded afterwards, never persisted, never cached across statements, and never carried from one record to the next. Consequently a *global* or session-lifetime counter is forbidden — pseudonym numbering must restart at 1 for each record, so that pseudonyms in unrelated records cannot be ordered or joined, and so that memory is bounded by one plan. *(rev. code audit: v1.1 additionally implied that the same table would get **different** pseudonyms in two records of the same session, which contradicts FR-42 and is not achievable while keeping FR-42's comparability. Narrowed by D8; the corresponding v1.1 acceptance test is withdrawn — see §8.7.)* |
| FR-46 | The pseudonym key domain must be able to name every object that can be printed *(rev. code audit)*: relation pseudonyms key on the range-table entry, not solely on a relation OID, and column pseudonyms key on **(range-table index, attribute number)** within the deparse namespace, not on `(relid, attno)` — because subquery, join, function, `VALUES`, CTE, ENR and tablefunc entries have no relid and no catalog attribute number, yet their column names are printed (FR-12). Where a name has no OID-bearing object at all (composite fields per FR-93, window names per FR-91), the key is the node identity that produced it. *(rev. T13: FR-96's path labels were the third example here and are no longer keyed at all — the construct carrying them is collapsed, so nothing keys them.)* |
| FR-43 | No object OIDs, no physical attnos, no catalog metadata *identifiers* (relfilenode, table size), and no raw identifiers may appear anywhere in a redacted record as a side effect of redaction. (Statistics-*derived numbers* — row estimates, widths — are knowingly retained; see §9.) *(rev. security review: wording narrowed to identifying metadata)* |
| FR-44 | The mapping from object → pseudonym lives only for the duration of producing the record and is never logged. |
| FR-47 | Pseudonyms must be assigned **before** any name-uniquifying pass runs *(rev. code audit)*. Both the relation-alias assignment and the column-alias assignment append `_1`, `_2`, … suffixes to disambiguate colliding names; if pseudonyms are substituted after that pass, the suffixes fight the pseudonym counters and can produce either collisions (violating FR-40) or fragments of the real name (violating FR-41). |

### 5.5 Exemption boundary and allowlist

| ID | Requirement |
|---|---|
| FR-50 | The exemption test is **namespace-primary**: an object is exempt if and only if its namespace is `pg_catalog`, `information_schema`, or a schema listed in FR-51's allowlist. The historical `OID < FirstNormalObjectId` heuristic must not be used as the primary test *(rev. security review: initdb-time provisioning of application schemas yields low-OID "user" tables that the OID test would wrongly print in full; conversely the namespace test correctly redacts low-OID non-exempt objects)*. Where no namespace can be determined for an object, it is redacted (fail closed, FR-60). |
| FR-51 | A list-valued option `auto_explain.redact_allow_schemas` exempts additional schemas (e.g. trusted extension schemas such as `pg_trgm`) from redaction. Allowlisting a schema exempts **everything later created in it**; documentation must warn against allowlisting user schemas such as `public`. Objects exempted by the allowlist print their real names; everything else still redacts. |

### 5.6 Safety / fail-closed behavior

| ID | Requirement |
|---|---|
| FR-60 | If a name or value cannot be classified as exempt during redacted output, it must be redacted (fail closed). A catalog lookup failure (e.g. a concurrently dropped object) must result in the **pseudonym being substituted**, not in the whole record being lost to an ERROR *(rev. security review)*. *(rev. code audit: several reachable sites currently `elog(ERROR)` on a failed lookup — the index-name fetch, the sort-key collation and operator lookups, the operator-class lookup, and the column-name and range-table-index sanity checks in the deparser. In redacted mode each of these must substitute a pseudonym instead. Sites that indicate a genuine internal inconsistency rather than a concurrent catalog change may still error; the design must state which is which.)* *(rev. T16: the first of those enumerated sites is discharged, and **structurally** rather than by handling the failure. `explain_get_index_name()`’s `elog(ERROR, "cache lookup failed for index %u")` sits after the redaction check, so a redacted record returns before reaching it — the failure is unreachable, not caught. The arbiter site never had an `elog`; `get_rel_name()` returns NULL there, and the redacted branch does not call it. This is only sound because the substitute cannot fail either, which is the half that is **measured**: `src/test/modules/test_explain_redact` asserts a nonexistent index OID yields `i1` rather than an error or a NULL. It is **not** asserted from the regression file, and cannot be — a regression run is one backend, and the plancache invalidates the plan the moment the index is dropped, so no SQL shape reaches the lookup with a dead OID. Recorded as argued-plus-unit-tested rather than end-to-end verified. The remaining sites — sort-key collation and operator, operator class, and the deparser’s sanity checks — belong to T20 and T21.)* |
| FR-61 | Redaction must not alter output structure: records remain parseable as `text`/`json`/`xml`/`yaml` respectively, and JSON output remains a valid single JSON object (the auto_explain JSON fix-up must continue to work). Substituting a pseudonym or `?` must not break a construct the pseudonym is embedded in (FR-99). |
| FR-62 | With `auto_explain.log_redact = off`, no code path may behave differently from today (no perf or output change). |
| FR-63 | Redaction must be applied **to the value at its source**, never to the serialized property *(rev. code audit)*. A filter placed on the property-emitting functions would be format-dependent and therefore incomplete: in `text` format a large number of identifiers — trigger, constraint and relation names in the trigger section, index names, the scan-target relation/schema/alias clause, the sampling method, and the sub-plan label — are appended directly to the output buffer and never pass through those functions. An implementation that redacts centrally at serialization will produce clean `json`/`xml`/`yaml` and leaky `text`, and the default format is `text`. |
| FR-64 | Redaction state must not be reachable only through a data structure that some call sites construct from scratch *(rev. code audit)*. At least one constant-printing path builds a fresh, zeroed deparse context before printing (partition bound values), which silently clears any flag carried there. Either the redaction state must be reachable independently of that structure, or every site that constructs one must be fixed and a regression test must pin it (§10). |

### 5.7 Interactions

| ID | Requirement |
|---|---|
| FR-70 | `errhidestmt(true)` remains in effect for redacted auto-explain records so the raw statement is not attached to the same log entry. |
| FR-75 | When redaction is enabled, auto_explain emits a one-time-per-session `LOG` notice if any concurrently active logging setting would place unredacted user information into the same log stream: `log_statement`, `log_min_duration_statement`, or a `log_line_prefix` containing `%q` *(rev. security review: envelope/statement channels; see §3)* |
| FR-71 | Documentation must state that `log_statement`, `log_min_duration_statement`, `log_line_prefix`, and the csvlog/jsonlog envelope fields (user, database, `application_name`, client address) are **not** redacted by this feature. |
| FR-72 | The following `EXPLAIN` option combinations are rejected with an `ERROR`: (a) `REDACT` with `SERIALIZE` — serialized output may contain query results and no redaction contract exists for it; (b) `REDACT` with any **extension-registered** option *(rev. code audit: FR-29)* — core cannot know what a plugin will print, and the plugin's output is emitted by hooks that run after the plan body. auto_explain must never enable serialization of query output. |
| FR-76 | A redacted record must carry a **correlation token** *(rev. code audit)*: a value that lets an operator tie the record to the statement that produced it without disclosing the statement. This is a functional requirement, not a nicety: `errhidestmt(true)` (FR-70) removes the `STATEMENT:` line, and auto_explain's design comment states that it relies on the surrounding context or `debug_query_string` logging to identify which statement is being reported. A redacted record therefore has no correlation handle at all, and the natural operator response is to enable `log_min_duration_statement`, which reintroduces the full disclosure that FR-75 can only warn about. The token must be per-record, unpredictable, and derived from **neither** the query text nor the query identifier (an identifier-derived token would reintroduce the FR-37 oracle). A random value emitted both in the redacted record and in a companion `DEBUG`-level entry that the operator can route to a separate, trusted destination satisfies this. |
| FR-73 | `auto_explain.log_extension_options` may activate extension explain output. In redacted records such options are ignored (per FR-25) and a `LOG` notice is emitted stating that extension explain options were skipped due to redaction. |
| FR-74 | Nested-statement records (`log_nested_statements`) are redacted independently; each nested record has its own pseudonym mapping (FR-45). |

### 5.8 Performance

| ID | Requirement |
|---|---|
| FR-80 | With redaction off: zero measurable overhead (a flag check per record). |
| FR-81 | With redaction on: overhead limited to in-memory hash lookups and short string generation per identifier; memory bounded by the distinct object count of the plan; no syscache storms beyond what normal explain already performs. **The cost is incurred per *logged record*, not per sampled query** *(rev. code audit)*: redaction is decided at `ExecutorEnd`, after the duration threshold, so an unsampled query pays nothing at all, a sampled-but-under-threshold query pays instrumentation only, and only records that are actually emitted pay for redaction. Per-node instrumentation overhead therefore dominates redaction by orders of magnitude, and enabling redaction must not change the sampling draw or the set of instrumentation flags requested at `ExecutorStart`. |

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Follows PostgreSQL coding style, GUC framework conventions, and regression-test conventions; no new compile-time dependencies. |
| NFR-2 | Feature is off by default; no upgrade/migration steps. |
| NFR-3 | Documentation: new GUC(s) documented in `auto_explain` extension docs; `REDACT` EXPLAIN option documented with `EXPLAIN` options, including the non-goal §3 caveats and the §9 residual risks. |

## 7. Resolved decision points

| ID | Question | Decision |
|---|---|---|
| **D1** | Redaction style | **Consistent pseudonyms** (`t1`, `t1_c3`, `f2`, …). Structure-only suppression is not offered in v1. |
| **D2** | Built-in boundary & allowlist | **OID range (`FirstNormalObjectId`) + schema allowlist.** *(Superseded by D7 in v1.1.)* |
| **D3** | Core `EXPLAIN (REDACT)` option | **Yes** — added to core, sharing the same implementation and contract as the auto_explain GUC. |
| **D4** | Third-party output (FDW `Remote SQL`, custom-scan callbacks, `log_extension_options`) | **Suppress** — callbacks are not invoked in redacted records (fail closed). |
| **D5** | `Query Identifier` in redacted records *(rev. security review)* | **Omit** — the hash is a fingerprint/membership oracle for guessed query texts. |
| **D6** | Constant-value policy *(rev. security review)* | **Uniform redaction: every constant, including `NULL`/`true`/`false`, becomes `?` + type label.** No value classes are exempt, removing per-class decisions and fail-open risk. |
| **D7** | Exemption boundary *(rev. security review)* | **Namespace-primary** (FR-50): exempt ⇔ namespace ∈ {`pg_catalog`, `information_schema`} ∪ allowlist. The OID range is not used, closing the initdb-provisioned-schema hole. |
| **D8** | Determinism vs. per-record mapping scope — FR-42, FR-45 and the v1.1 test in §8.7 could not all hold *(rev. code audit)* | **Keep determinism (FR-42); narrow FR-45 to "no state outlives one record".** Comparability across records is the reason pseudonyms exist at all (goal 3): a self-join must read as a self-join, and an operator diffing two runs of the same query must see the same names. Randomising per record would destroy that and buy less than it appears to — a log reader can already re-derive the mapping for a *known* query shape from the plan structure, so per-record randomisation only obscures the mapping for shapes the reader cannot guess, at the cost of making every record incomparable. What FR-45 must still forbid is *stateful* numbering: a session- or global-lifetime counter would let a reader order and join pseudonyms across unrelated statements and would grow without bound. The residual — identical query shapes yield identical pseudonyms — is accepted and recorded in §9 ("pattern fingerprinting"). The v1.1 acceptance test "two records in the same session use different pseudonyms for the same table" is **withdrawn** as unsatisfiable. |
| **D9** | GUC context for the redaction controls *(rev. code audit)* | **`PGC_SIGHUP` for both `auto_explain.log_redact` and `auto_explain.redact_allow_schemas`** (was `PGC_SUSET`). Under `PGC_SUSET` any superuser session — or any role granted `SET` on the parameter — can turn redaction off, or add `public` to the allowlist, for the duration of its own session; the resulting unredacted records land in the very log stream the third party reads, with nothing in the stream marking the change. §3 already disclaims administrators with full server access, but a *per-session* override of the redaction contract is a different thing from an administrator editing the configuration: the latter is file-controlled, survives review, and is visible in `postgresql.conf`. Note this makes the two settings uniform with the security posture, not with the other auto_explain GUCs; the inconsistency is intentional and must be documented (NFR-3). |
| **D10** | Rendering of the `Query Parameters` property *(rev. code audit)* | **Omit the property entirely** (FR-22), superseding v1.1's "parameter names only". `$1, $2, …` is not free: it discloses the parameter count, including parameters the plan never referenced, and it does so in configurations where `log_parameter_max_length = 0` suppresses the property today. Redaction must never disclose something the unredacted path would have withheld. Parameter *placeholders* still appear naturally wherever the deparser prints them inside expressions, which is where they carry diagnostic value. |

Secondary defaults confirmed (no objection raised): FR-23 omits query text;
FR-26 excludes `Settings`. Changed in v1.2: FR-22 now omits the parameter
property entirely rather than rendering names (D10).

## 8. Acceptance criteria

1. **Negative-content tests (the core gate).** For a fixture schema with
   distinctive names (`secret_customers`, `ssn_col`, `my_secret_func`, …),
   produce redacted records covering: plain & verbose; text/json/xml/yaml;
   analyze & non-analyze; triggers; parallel plans; partitioning &
   inheritance; self-join; CTE; ENR; `VALUES`; function-in-FROM;
   user-defined operators/types/collations; `json_table` (columns *and path
   strings*); custom and generic plans; `TABLESAMPLE` (method, parameters,
   seed); `INSERT`/`UPDATE`/`DELETE`/`MERGE`/CTAS targets; `ON CONFLICT`
   (arbiter indexes); `RETURNING`; merge-action quals. For each record:
   **none** of the fixture identifiers or literal values may appear anywhere
   in the record.
2. **Structure-preservation tests.** Each fixture record must still contain
   the expected node types and cost/rows/loops/buffer fields (§5.3).
3. **Consistency tests.** A self-join record shows the same relation
   pseudonym twice; two different tables show different pseudonyms.
4. **Off-mode regression.** Byte-identical output vs. current behavior for
   the existing auto_explain and EXPLAIN test suites.
5. **Fail-closed test.** An unclassifiable object (e.g. a schema removed
   from the allowlist) redacts rather than prints; a concurrent-drop lookup
   failure substitutes a pseudonym instead of erroring the record.
6. **Combination tests.** Redact × each EXPLAIN/auto_explain option in FR-4,
   including the FR-72 forbidden combination.
7. **Redaction-specific negative tests** *(rev. security review)*:
   - `Custom Plan Provider` / `Custom Scan (…)` absent for an extension
     custom scan (FR-28);
   - `Query Identifier` absent (FR-37/D5);
   - `NULL`/`true`/`false` literals in `VALUES`/output absent (FR-21/D6);
   - column pseudonym numbers never equal raw attnos (e.g. a table whose
     sensitive column is attno 9 must not surface `_c9` unless it is the
     9th *distinct column used*) (FR-12);
   - ~~two records generated in the same session use **different**
     pseudonyms for the same table (FR-45)~~ — **withdrawn in v1.2**, this
     contradicts FR-42; replaced by: pseudonym numbering restarts at 1 in
     each record, and the mapping holds no state between records (FR-45/D8);
   - a table created by initdb-time provisioning in a user schema is
     redacted (FR-50/D7);
   - `Sampling: <user-installed method>` redacted (FR-18).
8. **Leak-path tests** *(rev. code audit)*: every entry in §10 is an
   acceptance test. §10 exists because the tests in §8.1 are written against
   a *fixture-name* list, and a fixture-name test only catches a leak if the
   test author thought to exercise the syntax that reaches the leaking path.
   Each §10 entry therefore pairs the code site with the minimal query that
   reaches it, so coverage is a property of the catalog rather than of the
   test author's imagination.

## 9. Residual risk register (knowingly retained information)

Accepted after review; revisitable, but each item has direct diagnostic
value that pseudonymization must not destroy:

| Risk | Detail |
|---|---|
| Schema shape | Relation/column/index/trigger/function counts, index presence and key structure, partition counts, arity and argument types of redacted functions (`f2(?::text, ?::int)`). |
| Statistics metadata | Planner row estimates and widths derive from `pg_statistic`; they reveal distribution properties of user data. |
| Cardinality side channel | Actual rows, `Rows Removed by …`, and timing permit value-verification attacks against guessed predicates (e.g. `Filter: (ssn = ?)` with rows=1). *(rev. code audit: this risk is **activated by ANALYZE mode**, which is also the feature's entire reason for existing. Without `log_analyze` the record carries planner estimates, which derive from `pg_statistic` and are aggregate and fuzzy. With `log_analyze` it carries exact counts about real rows, so `Rows Removed by Filter: 999999` beside `Filter: (status = ?)` discloses the precise selectivity of one specific real value — a fact about data, not about schema. Suppressing, rounding or bucketing the counters is explicitly **not** the remedy: it would destroy goal 2 and leave a feature nobody would enable. The risk is accepted as the price of the diagnostic value, and any future proposal to "harden" the counters should be read as a proposal to remove the feature.)* |
| Pattern fingerprinting | FR-42 determinism means identical query shapes yield identical pseudonym patterns, permitting "seen this query before" correlation. |
| Log envelope | User name, database, `application_name`, client address, session id ride in the same log record (§3); FR-75 warns but cannot suppress. |
| Exempt-object names | Objects in `pg_catalog` / `information_schema` / allowlisted schemas print in full; superuser-created objects in `pg_catalog` are trusted by policy. |

## 10. Leak-path test catalog

§8.1's negative-content test is a *fixture-name* test: it asserts that none of
a list of distinctive names appears in the record. That only catches a leak if
the test author happened to write a query that reaches the leaking code. This
section removes that dependency by pairing each known emission path with the
minimal syntax that reaches it. Coverage becomes a property of the catalog.

Each entry is: the requirement, the code site, a fixture, and the assertion.
Entries are marked **[V]** where the path was verified by reading the code and
**[C]** where the reaching query shape still needs confirmation by running it —
an honest distinction, because a `[C]` entry that turns out to be unreachable
is a test to delete, not a leak to fix.

### 10.1 Fixture schema

All fixtures share one schema whose every identifier is distinctive, so a
single `grep` over a record can assert absence. Names deliberately avoid
substrings of PostgreSQL keywords and of the pseudonym alphabet.

> **Corrected by T01.** The marker prefix is **`zsec_`**, not a bare `z`. The
> claim that "nothing in core PostgreSQL output starts with z" is false:
> `timestamp with time zone` contains `zone`, which a `/z[a-z_]+/` detector
> reports as a leak. A four-character marker cannot collide with any English or
> SQL word in plan output, so the detector needs no word-boundary anchoring and
> has no false positives. The implemented schema lives in
> `src/test/regress/sql/explain_redact.sql`; the listing below is kept for
> reference and uses the corrected prefix.

```sql
CREATE SCHEMA zsecret;
SET search_path = zsecret, public;

CREATE COLLATION zcoll_secret (locale = 'C');
CREATE TYPE ztype_secret AS (zfield_ssn text, zfield_name text);
CREATE TYPE zenum_secret AS ENUM ('zval_a', 'zval_b');
CREATE DOMAIN zdomain_secret AS text CHECK (VALUE <> '');

CREATE TABLE zcustomers (
    zid         int GENERATED BY DEFAULT AS IDENTITY,
    zcol_ssn    text,
    zcol_bal    numeric,
    zcol_when   timestamptz,
    zcol_comp   ztype_secret,
    zcol_kind   zenum_secret
);
CREATE INDEX zidx_ssn ON zcustomers (zcol_ssn);
CREATE TABLE zorders (zid int, zcol_amt numeric);

-- non-inlinable, so the FuncExpr survives into the plan
CREATE FUNCTION zfunc_secret(zarg_secret text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE AS $$ BEGIN RETURN true; END $$;
```

The single assertion primitive used throughout: **no identifier beginning
`z` may appear anywhere in a redacted record, in any format.** Every fixture
name is prefixed `z`; nothing in core PostgreSQL output is.

### 10.2 Catalog

**FR-90 — sub-plan label carries the CTE name.** [V]
Site: `Subplan Name` property, explain.c:1661, built at explain.c:5152-5156
from `SubPlan->plan_name`, seeded from `cte->ctename` at subselect.c:980.

```sql
WITH zcte_secret AS MATERIALIZED (SELECT zcol_ssn FROM zcustomers)
SELECT * FROM zcte_secret;
```
Assert: no `zcte_secret`; the `Subplan Name` value matches
`^CTE (cte|sp)[0-9]+$`; the `CTE Name` property on the `CTE Scan` node and the
name inside `Subplan Name` resolve to the **same** pseudonym (FR-90 requires
the two lines stay relatable).

Companion, same requirement, second seed — **refuted by T01**: the
subquery-alias seed at allpaths.c:2828 sets `subroot->plan_name` from
`rte->eref->aliasname`, but that name does **not** reach `Subplan Name`. When
the subquery is flattened the alias vanishes from the plan entirely; when it
survives, it appears as a `Subquery Scan` alias — which is FR-13's territory and
is already covered there. No `Subplan Name` is produced either way.

```sql
-- flattened: alias vanishes
SELECT * FROM (SELECT count(*) FROM zsec_customers) AS zsec_alias;
-- un-flattenable: "Subquery Scan on zsec_alias2", still no Subplan Name
SELECT * FROM (SELECT zsec_ssn, count(*) FROM zsec_customers
                GROUP BY zsec_ssn OFFSET 0) AS zsec_alias2
 WHERE zsec_alias2.zsec_ssn = 'x';
```

Both shapes are retained as probes so the refutation stays pinned. FR-90's CTE
seed remains confirmed and is the one T19 must handle.

**FR-91 — window name.** [V]
Sites: `Window` property, explain.c:2912 → 2957; `OVER <name>` inside `Output`,
ruleutils.c:11194. Neither is `VERBOSE`-gated for the `Window` property.

```sql
SELECT zcol_ssn, rank() OVER zwin_secret
  FROM zcustomers
WINDOW zwin_secret AS (PARTITION BY zcol_ssn ORDER BY zcol_bal);
```
Assert: no `zwin_secret`; `Window` matches `^w[0-9]+ AS \(`; under `VERBOSE`
the `Output` list contains `OVER w1` with the same number.

**FR-92 — `Replaces` prints relation reference names.** [V — resolved by T01]
Site: explain.c:5036-5069. Requires a `Result` node with `relids` and **no**
`lefttree` (the function returns early otherwise), i.e. a scan/join/aggregate
that was replaced rather than gated.

T01 confirmed the property exists and found **three forms that differ in what
follows the replacement type** — all three must be covered:

```sql
SET constraint_exclusion = on;   -- the default 'partition' is NOT enough
-- Replaces: Scan on zsec_excluded          <- relation NAME
SELECT * FROM zsec_excluded WHERE zsec_k < 0;
-- Replaces: Join on zsec_ja, zsec_jb       <- ALIASES
SELECT * FROM zsec_excluded zsec_ja JOIN zsec_excluded zsec_jb USING (zsec_k)
 WHERE zsec_ja.zsec_k < 0;
RESET constraint_exclusion;
-- Replaces: MinMaxAggregate                <- no name at all
SELECT min(zsec_bal) FROM zsec_customers;    -- needs an index on zsec_bal
```

Two preconditions were not obvious from the code and cost a round of
experiment: `constraint_exclusion` defaults to `partition`, which applies only
to partitions and inheritance children, so a plain `CHECK`-constrained table is
**not** proven empty at the default setting; and the MinMax replacement requires
an index on the aggregated column or the planner produces an ordinary
`Aggregate`. A contradictory qual on an unconstrained column (`IS NULL AND
IS NOT NULL`) is not detected at all and produces no replacement — recorded as
a control in the test.

*(rev. T15: landed, and all three forms are pinned in their redacted rendering
rather than only as leak-scan verdicts:*

```
Replaces: Scan on t1
Replaces: Join on a1, a2
Replaces: MinMaxAggregate
```

*The two leak-scan rows for this requirement were previously vacuous — T04
withheld the names while keeping the line — and are now genuine. The names come
from the same `es->rtable_names` list `ExplainTargetRel()` reads, including the
`eref->aliasname` fallback for an RTE the plan walk did not reach, so a
`Replaces` line stays relatable to the scan nodes around it.)*

**FR-93 — composite-type field names.** [V]
Sites: `FieldSelect` → `get_name_for_var_field()`, printed at ruleutils.c:9712;
assignment form → `processIndirection()`, printed at ruleutils.c:13193.

```sql
-- field selection (Filter: not VERBOSE-gated)
SELECT zid FROM zcustomers WHERE (zcol_comp).zfield_ssn = 'x';
-- whole-row field reference, exercises the get_rte_attribute_name return path
SELECT (zc).zcol_ssn FROM zcustomers zc;
-- assignment form, needs VERBOSE to show the target list
EXPLAIN (REDACT, VERBOSE) UPDATE zcustomers SET zcol_comp.zfield_ssn = 'x';
```
Assert: no `zfield_ssn`, no `ztype_secret`, no `zcol_ssn`. Note the second
fixture is the one that reaches ruleutils.c:8214; without it that return path
is untested.

**FR-94 — named-argument labels.** [V]
Site: ruleutils.c:9424. The function is `plpgsql` specifically to defeat
inlining, which would otherwise remove the `FuncExpr`.

```sql
SELECT zid FROM zcustomers WHERE zfunc_secret(zarg_secret => zcol_ssn);
```
Assert: no `zarg_secret`; the printed call is `f1(arg1 => t1_c1)` or
`f1(t1_c1)`, both acceptable per FR-94.

**FR-95 — XML constructs.** [V] *(rev. T13: collapsed, not pseudonymized.)*
Sites: `get_rule_expr()` `case T_XmlExpr:`, and `get_tablefunc()` — the latter
covers `XMLTABLE` for both of its callers, so there is no longer one site per
name. The fixture schema needs one more column for this entry, `zcol_xml xml`
(declaring and selecting an `xml` column needs no libxml; only parsing an
`xml` *literal* does).

```sql
-- XmlExpr.  In the SELECT list, because that is the only place the deparse
-- harness can see (it deparses the top node's target list); an XmlExpr in a
-- Filter is the same node and the same guard.
SELECT xmlconcat(zcol_xml, zcol_xml) FROM zcustomers;
-- XMLTABLE: needs VERBOSE (the Table Function Call property)
SELECT * FROM XMLTABLE(XMLNAMESPACES ('http://x' AS zns_secret),
                       '/r' PASSING zcol_xml
                       COLUMNS zxcol_secret text PATH '.');
```
Assert: no `zns_secret`, no `zxcol_secret` — and, since the construct is
collapsed rather than rewritten name by name, assert the placeholder: the
first prints exactly `XMLEXPR(...)`, the second `XMLTABLE(...)`. There is no
pseudonym to check, so the placeholder *is* the positive assertion. Pair each
with a non-XML sibling in the same target list whose column pseudonym must
still print (`t1_c1, XMLEXPR(...)`), or a green result cannot be told apart
from output that was blanked wholesale.

**FR-96 — JSON constructs.** [V] *(rev. T13: collapsed, not pseudonymized.)*
Sites: `get_rule_expr()` `case T_JsonExpr:`, and the same `get_tablefunc()`
guard as FR-95, which covers `JSON_TABLE`. The five separate label sites the
pseudonym design listed here (root path `AS`, `NESTED PATH AS`, `PLAN` clause,
two `PASSING … AS`) are all inside the collapsed subtree and are no longer
reached under redaction.

```sql
SELECT * FROM JSON_TABLE('{"a":1,"b":[{"c":2}]}'::jsonb, '$' AS zpath_secret
    COLUMNS (zjcol_secret int PATH '$.a',
             NESTED PATH '$.b[*]' AS znest_secret
                 COLUMNS (zjc2_secret int PATH '$.c')));

SELECT JSON_QUERY('{"a":1}'::jsonb, '$.a' PASSING 5 AS zpass_secret);
```
Assert: no `zpath_secret`, `znest_secret`, `zjcol_secret`, `zjc2_secret`,
`zpass_secret`, and the surviving keyword: `JSON_TABLE(...)` for the first,
`JSONEXPR(...)` for the second. FR-24's point still holds — the path *string*
`'$.a'` was already a `Const` — but under the collapse it is not printed at
all, as `?` or otherwise. Same anti-vacuity pairing as FR-95.

Reachability caveat, measured, and it constrains how this entry can be tested
before T15–T21: `EXPLAIN (REDACT, VERBOSE)` currently suppresses every
expression property wholesale, so `Table Function Call` prints nothing at all
and any assertion made through it passes vacuously. And the deparse harness
cannot reach a `TableFunc` either — it lives in a range-table entry, never in
a target list. So the `XMLEXPR(...)` / `JSONEXPR(...)` halves are testable
today and the `XMLTABLE(...)` / `JSON_TABLE(...)` halves need either a new
harness entry point or deferral until the properties are un-suppressed.

**FR-97 — cursor name.** [V]
Site: ruleutils.c:10403, reached as a `TID Cond`.

```sql
BEGIN;
DECLARE zcur_secret CURSOR FOR SELECT * FROM zcustomers FOR UPDATE;
FETCH 1 FROM zcur_secret;
EXPLAIN (REDACT) UPDATE zcustomers SET zcol_bal = 0 WHERE CURRENT OF zcur_secret;
ROLLBACK;
```
Assert: no `zcur_secret`; `TID Cond` contains `CURRENT OF cur1`.

*(rev. T14: the code ships **untested**, and this fixture is the reason —
it needs `EXPLAIN (REDACT)` to print expression properties, which T21 does.
The deparse harness cannot substitute: measured, a `CurrentOfExpr` only ever
appears in an UPDATE/DELETE qual, so the same statement through
`test_redact_deparse()` returns the empty string without RETURNING and only the
RETURNING column with one, while plain `EXPLAIN (VERBOSE)` shows
`TID Cond: CURRENT OF zcur_secret` on the Tid Scan below the ModifyTable.
Carried into T21 on the same footing as T13's `get_tablefunc()` guard.)*

**FR-98(a) — sort-key `COLLATE` / `USING`, assembled after deparse.** [V]
Site: explain.c:2866 (`get_collation_name`), 2881 (`get_opname`). These are
appended to the sort-key string in explain.c, *after* `deparse_expression()`
returns — a ruleutils-only fix does not reach them.

```sql
SELECT zcol_ssn FROM zcustomers ORDER BY zcol_ssn COLLATE zcoll_secret;
```
Assert: `Sort Key` contains no `zcoll_secret`. For the `USING` half a
user-defined ordering operator is needed; built-in `>` is exempt and must
still print (see §10.4).

**FR-98(b) — collation via an explicit `COLLATE` expression.** [V]
Site: ruleutils.c:9841. Distinct from `get_const_collation()`, which is the
only collation site the v1.1 design named.

```sql
SELECT zid FROM zcustomers WHERE zcol_ssn COLLATE zcoll_secret = 'x';
```
Assert: no `zcoll_secret` in `Filter`.

**FR-98(c) — operator-class name.** [V, but not reachable from EXPLAIN today]
Site: ruleutils.c:13123-13128 via `T_InferenceElem` (ruleutils.c:10468).
explain.c prints `Conflict Arbiter Indexes` from catalog names
(explain.c:4852/4895) and does **not** deparse arbiter inference elements, so
this is currently unreachable from the EXPLAIN path. Treat as a **guard**: add
the redaction branch anyway, and assert by code inspection (or a
`deparse_expression()` unit call) rather than by SQL. Delete the guard only if
someone proves the path can never become reachable.

*(rev. T14: landed, and unreachability re-confirmed by reading the planner
rather than taken from this note — `arbiterElems` hangs off the Query's
`OnConflictExpr`, `createplan.c` reduces it to `ModifyTable.arbiterIndexes`, a
list of index OIDs, and that is what explain.c iterates. The `InferenceElem`
list is never copied into the plan. The guard therefore sits at the **call
site** in `get_rule_expr()`, not inside `get_opclass_name()`: that function
takes a bare `StringInfo` and no deparse context, so it cannot tell whether
redaction is on, and its other two callers — `pg_get_indexdef_worker()` and the
partition-bound printer — emit DDL that must name real objects. A guard inside
it would corrupt `pg_get_indexdef()`. The guard also replicates the function's
suppression of a type's default opclass, so a user-defined default does not
start printing `opc1` where nothing printed before. Verified by inspection; no
SQL, and none invented.*

*One thing this path does **not** honour, noted here because it is the same
vacuity in another guise: FR-60. Both `get_opclass_input_type()` and
`get_opclass_name()` `elog(ERROR)` on a concurrently dropped operator class, at
base as well as after T14. Not a regression and not T14's to fix — but the path
is only FR-60-clean today because it is unreachable, which is worth exactly
nothing the moment it becomes reachable. Whoever makes it reachable owns this.)*

**FR-98(d) — constants read straight from the node datum.** [V]
Sites: ruleutils.c:11284 (`EXTRACT` field), 11306 (`IS … NORMALIZED`), 11330
(`NORMALIZE`). These bypass the constant printer entirely.

~~All three need FR-21 treatment.~~ *(rev. T14: narrowed to one of the three,
and the narrowing is a measurement rather than a judgement. Only the `EXTRACT`
field can carry user data; the two normalization forms cannot, and are kept.)*

**The `EXTRACT` field is redacted, unconditionally.** It reads as though it
could only ever be a keyword such as `year` or `month`, but it is an ordinary
text constant and the grammar accepts any string at all. The "unit not
recognized" error that would reject a bad one is raised at *execution*, and
EXPLAIN without ANALYZE does not execute — so whatever the user wrote is
planned, deparsed and printed. Measured:

```sql
EXPLAIN (COSTS OFF, VERBOSE) SELECT EXTRACT('zsecdata-secret' FROM now());
--  Result
--    Output: EXTRACT("zsecdata-secret" FROM now())
```

So the field is user-controlled text and takes the same `?` as any other
redacted constant. Replaced unconditionally rather than checked against an
allowlist of valid units: that alternative was **rejected** as a second list to
keep in step with the date/time code, and losing `year` versus `month` is
accepted.

**The `IS <form> NORMALIZED` and `NORMALIZE(…, <form>)` forms are kept.** They
cannot carry user data. The form is a grammar keyword, not an expression, so
only `NFC`/`NFD`/`NFKC`/`NFKD` can ever reach those lines. Measured — both
non-keyword variants fail to parse, before planning, before deparse:

```sql
SELECT 'x' IS 'zsecdata-secret' NORMALIZED;  -- ERROR: syntax error
SELECT NORMALIZE('x', 'zsecdata-secret');    -- ERROR: syntax error
```

Same footing as the built-in operator names FR-19 exempts: PostgreSQL's own
words, disclosing nothing, and worth keeping because a reader needs them.
Note the parser supplies the form when it is omitted (`x IS NORMALIZED`
deparses as `x IS NFC NORMALIZED`), so both sites are always exercised — which
is why leaving them alone had to be a decision rather than an omission.

```sql
SELECT c_second, EXTRACT(year FROM c_when) FROM zsec_c;
SELECT c_second, EXTRACT('zsecdata-secret' FROM c_when) FROM zsec_c;
SELECT c_second, c_second IS NFC NORMALIZED FROM zsec_c;
SELECT c_second, NORMALIZE(c_second, NFKD) FROM zsec_c;
```
Assert: the field is rendered `?` and the marker string is absent, while `NFC`
and `NFKD` still print and the sibling column still carries its pseudonym. The
last part is not decoration — without a sibling that prints, "no marker in the
output" cannot be told apart from output that was blanked wholesale. Verified
by `test_redact_deparse()` in `src/test/modules/test_explain_redact`, which
reaches this site through a plan's target list; the two normalization rows are
the negative control that fails if either form is ever "fixed".

**FR-99 — sequence name inside a quoted literal.** [V]
Site: ruleutils.c:10419 (`nextval('…')` via `generate_relation_name`).

```sql
EXPLAIN (REDACT, VERBOSE) INSERT INTO zcustomers (zcol_ssn) VALUES ('x');
```
Assert: no `zcustomers_zid_seq`; the output still has the shape
`nextval('t2'::regclass)` or `nextval('t2')` — the surrounding literal must
not be destroyed (FR-61).

*(rev. T14: **no edit was needed** — T10 already routed this call through
`generate_relation_name(…, redact)`, so the name half is covered. What remains
unverified is the FR-61 *shape*, and this fixture is still the only vehicle for
it. Measured, the deparse harness cannot stand in: for
`INSERT INTO t (col) VALUES ('x')` the `NextValueExpr` sits in the target list
of the **Result** node feeding the ModifyTable — plain `EXPLAIN (VERBOSE)` shows
`Output: nextval('zt_zid_seq'::regclass), 'x'::text, …` there — and the harness
deparses only the top node's target list, returning the empty string. Deferred
to T21.)*

**FR-46 — columns of range-table entries that have no relid.** [V]
This is the structural test for the key-domain fix. Each fixture names its
columns through a path that does not consult the catalog
(`rte->eref->colnames` at ruleutils.c:4449, or `expandRTE()`), so an
implementation keyed on `(relid, attno)` prints them verbatim.

```sql
-- subquery output name + subquery alias
SELECT zsub_secret.zout_secret
  FROM (SELECT zcol_ssn AS zout_secret FROM zcustomers) AS zsub_secret
 WHERE zsub_secret.zout_secret = 'x';
-- function-scan column alias
SELECT * FROM generate_series(1,3) AS zg_secret(zgc_secret)
 WHERE zgc_secret > 1;
-- ROWS FROM with a column definition list
SELECT * FROM ROWS FROM (json_to_record('{"a":1}') AS (zrf_secret int))
 WHERE zrf_secret > 0;
-- join output names
SELECT * FROM zcustomers a JOIN zorders b USING (zid) WHERE zid > 0;
-- CTE column aliases
WITH zcte2_secret(zcc_secret) AS (SELECT zcol_ssn FROM zcustomers)
SELECT * FROM zcte2_secret WHERE zcc_secret = 'x';
```
Assert: no marker identifier in any of these records. Each is a separate test
case, not one combined query — a combined query would let one passing path mask
a failing one.

> **Withdrawn by T01: the `VALUES` fixture.** A `VALUES` range-table entry
> discloses nothing. Its user-written alias and column aliases do not survive
> into the plan: EXPLAIN prints the planner's internal `*VALUES*` name and
> `column1..columnN`. Verified in every shape tried — bare, wrapped in an
> un-flattenable subquery, `LATERAL`, and `INSERT ... VALUES`. This matches what
> the implementation design already said in §5 ("node alias is auto-generated");
> it was the fixture that was wrong, not the design.
>
> Column aliases written on a `VALUES` clause *do* reach output when the clause
> is wrapped in a subquery that survives flattening — but as the **subquery's**
> column names, which the first fixture above already covers.
>
> The case is retained in the test as a **negative control** rather than
> deleted: if a future version starts propagating the user's alias into the
> plan, the assertion fails and a new leak path gets noticed instead of shipping
> silently.

**FR-13(b) — `RETURNING` OLD/NEW aliases.** [V]
Site: `dpns->ret_old_alias` / `ret_new_alias` used as the Var prefix at
ruleutils.c:7738-7740; copied in by `set_deparse_context_plan()`. These bypass
`dpns->rtable_names` entirely.

```sql
EXPLAIN (REDACT, VERBOSE)
UPDATE zcustomers SET zcol_bal = zcol_bal
RETURNING WITH (OLD AS zold_secret, NEW AS znew_secret)
          zold_secret.zcol_bal, znew_secret.zcol_bal;
```
Assert: no `zold_secret`, `znew_secret`.

*(rev. T15: the assertion is in place and **still vacuous.** These aliases are
used as the `Var` prefix when the `Output` list is deparsed and reach output
through no other property, so with expression output suppressed there is nothing
to find with `REDACT` and the fixture would pass against an implementation that
did nothing. Measured: the fixture's redacted record emits `Relation Name`,
`Alias` and the plan structure, and no `Output` at all. T21 is what turns this
row into a real assertion — and until then FR-13(b) is untested, not verified.)*

**FR-13(a) — the reference-name path for a partition parent.**
[V — resolved by T01]
Sites: explain.c:4610 and explain.c:5042.

T01 established that the **`SELECT`** drives it, not the `INSERT`, and that the
disclosure is worse than v1.2 implied: a single scan node emits **two**
identifiers, the partition child as the object name and the parent as the
reference name.

```
Seq Scan on zsec_parted_p1 zsec_parted
```

```sql
CREATE TABLE zsec_parted (zsec_k int, zsec_ssn text) PARTITION BY RANGE (zsec_k);
CREATE TABLE zsec_parted_p1 PARTITION OF zsec_parted FOR VALUES FROM (0) TO (10);
SELECT * FROM zsec_parted WHERE zsec_k = 1;   -- discloses child AND parent
INSERT INTO zsec_parted VALUES (1, 'x');      -- ordinary path, parent only
```
Assert: neither `zsec_parted` nor `zsec_parted_p1` appears. T15 must redact
both names on that line, not only the object name.

*(rev. T15: done, and the mechanism is worth recording because it is what makes
the two names take different code paths.
`expand_single_inheritance_child()` sets `childrte->alias` to an `Alias` carrying
the **parent's** `eref->aliasname`. `set_rtable_names()` keys an RTE with an
explicit `alias` by range-table index rather than by OID, so the parent's name
becomes an `aN` while the child's becomes the `tN` of its own OID — the two do
not collapse into one identifier the way an ordinary unaliased scan's do, which
is exactly the shape T01 predicted. Measured:*

```
Seq Scan on t1 a1
```

*Both identifiers are pseudonyms, and the line keeps its two-identifier shape.)*

**FR-29 / FR-72 — extension option plus `REDACT`.** [V]
The highest-severity finding. `pg_overexplain` is in-tree.

```sql
CREATE EXTENSION pg_overexplain;
-- must ERROR, not produce a partially-redacted record
EXPLAIN (REDACT, RANGE_TABLE) SELECT * FROM zcustomers;
EXPLAIN (REDACT, DEBUG)       SELECT * FROM zcustomers;
```
Assert: an `ERROR` is raised (FR-72). Negative control: without `REDACT`, both
still work unchanged.

Companion via auto_explain (FR-73 route, already closed by D4 but must stay
closed):
```sql
SET auto_explain.log_extension_options = 'range_table';
-- with log_redact on, run any query past the threshold
```
Assert: the logged record contains no range-table section, no `Eref`, no
`Relation`, no marker identifier; and a one-time `LOG` notice states that
extension explain options were skipped.

> **Quantified by T01.** The `Eref` line lists **every column of the relation,
> whether or not the query referenced it**. A single-column `SELECT` still
> discloses the complete column list:
> `Eref: zsec_customers (zsec_id, zsec_ssn, zsec_bal)`. In text mode the dump
> has no `Range Table` header — it starts directly at
> `RTI 1 (relation, in-from-clause):` — so assert on `RTI n (` and on the
> `Eref:` / `Relation:` lines, not on a header string.

**FR-16 — index names, all four surfaces.** [V — added by T16]
Until T16 this requirement had no §10.2 entry of its own: the two rows the
catalog carries for it — `arbiter index (ON CONFLICT)` in the table-driven sweep
and `index name (scan)` in the GUC section — were the whole of it, and both were
vacuous, because T04 suppressed the name on the scan sites and skipped the
arbiter gather entirely. An entry exists now because the coverage does.

Four properties carry an index name and **three** different code paths feed
them, which is why one representative fixture is not enough:

| Surface | Emission | Redacted output |
|---|---|---|
| `Index Scan` | `ExplainIndexScanDetails()` | `Index Scan using i1 on t1` |
| `Index Only Scan` | same function, different node | `Index Only Scan using i1 on t1` |
| `Bitmap Index Scan` | inline in `ExplainNode()` | `Bitmap Index Scan on i1` |
| `Conflict Arbiter Indexes` | `show_modifytable_info()` | `Conflict Arbiter Indexes: i1` |

Each needs its own GUCs and therefore its own assertion — the settings that
force one plan shape rule out another, so they cannot share a table-driven query
the way the sweep does. `enable_indexonlyscan` must be off as well as
`enable_seqscan` and `enable_bitmapscan` to reach the plain `Index Scan` case:
with only the two the planner picks an Index Only Scan, the Index Only Scan
surface gets measured twice and the Index Scan surface goes untested. This is
the same class of mistake T01 recorded for the original fixture (§10.3), one
level further in.

Each assertion carries the anti-vacuity clause: the **unredacted** plan must
name a real index, or “no real index name in the redacted plan” is satisfied by
a plan that never reached the emission site.

Two further assertions, neither of which the surface list implies:

- **FR-40 relatability.** An `ON CONFLICT` statement whose arbiter index is also
  scanned prints the same `i1` on both lines, from two different functions.
  Verified:

  ```
  Insert on t1
    Conflict Resolution: NOTHING
    Conflict Arbiter Indexes: i1
    ->  Index Only Scan using i1 on t1 t1_1
  ```

  A mistake here produces a record that says the statement conflicts on an index
  it is not scanning — no real name, no marker, and every leak assertion still
  passes, so it is measured rather than reasoned about. The other half of FR-40
  is checked too: two different indexes on the **same** relation print `i1` and
  `i2` while the relation stays `t1`, so the index counter runs independently of
  the relation counter.
- **Exempt index, negative control.** `Index Scan using pg_class_oid_index on
  pg_class`, in all four formats. This assertion is load-bearing beyond the
  usual “don’t redact the catalogs” reason: T16 does **not** call
  `explain_redact_exempt()` itself and relies on `explain_redact_name()`
  deciding exemption and returning the real name, so this is the only thing that
  proves the reliance sound. Were it misplaced, a `pg_catalog` index would print
  as `iN`, every leak assertion in the file would still pass, and catalog plans
  would have become unreadable for no gain.

**Negative controls on the same nodes**, because every assertion above is
satisfied by printing the index name and nothing else: `Scan Direction` still
prints — checked in all four formats, since text emits the bare word `Backward`
while the others emit a property — and `Index Searches` still prints on both the
`Index Scan` node and the `Bitmap Index Scan` child.

`Rows Removed by Index Recheck` is deliberately **not** pinned. It is emitted by
`show_instrumentation_count()` on the Bitmap **Heap** Scan node, neither of the
two sites T16 touches, and reaching it needs a lossy `TIDBitmap`. Measured while
writing the tests: 60000 rows at 200 bytes goes lossy, 20000 does not, and at
the lossy size the index condition matched every row so nothing was rechecked
away. A `Heap Blocks: lossy=` count in an expected file moves with `work_mem`
and page layout, which costs more than a counter no T16 code path can suppress.

*What T16 did **not** need to change, recorded because it was expected to.* The
three existing FR-16 assertions — the sweep’s arbiter row, the unredacted
positive control and the redacted GUC row — were **not** inverted, and inverting
them would have been a regression. All three turn on the presence or absence of
a **real** index name, and T16 changes neither: the pseudonym carries no marker,
so “the real name is found without `REDACT`” and “the real name is absent with
it” both still hold and are still the assertions worth making. What changed is
that they stopped being vacuous. The one thing in the file that did assert the
opposite of the new behaviour was a comment — “Scan direction survives an index
scan even though the index name does not” — and it is corrected in place.

**FR-17 — trigger section, reachable only under ANALYZE.** [V]
Site: `report_triggers()`, explain.c:1134/1138/1140 (text) and 1151/1153/1154
(structured). `ExplainPrintTriggers` is called only when
`es->analyze && auto_explain_log_triggers`.

```sql
CREATE FUNCTION ztrigfunc_secret() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE CONSTRAINT TRIGGER ztrig_secret AFTER INSERT ON zcustomers
    DEFERRABLE FOR EACH ROW EXECUTE FUNCTION ztrigfunc_secret();
```
Run with `auto_explain.log_analyze = on`, `auto_explain.log_triggers = on`,
`log_redact = on`, then `INSERT INTO zsec_customers …`.
Assert: no trigger name, no constraint name, no trigger-function name, no
relation name; the timing and `Calls` values are still present (FR-38).
**A test matrix without this configuration reports success while FR-17 is
completely unexercised.**

> **Refined by T01: the trigger name and the constraint name are disclosed
> under different conditions**, so one fixture at one verbosity misses one of
> them. `report_triggers()` prints the trigger name only when `VERBOSE` is set
> *or* the trigger has no associated constraint; otherwise it prints just
> `Trigger for constraint <conname>`. The test therefore needs **two** triggers
> and **two** verbosities:
>
> - a plain trigger — its own name is printed at any verbosity;
> - a `CONSTRAINT TRIGGER` — without `VERBOSE` only the constraint name appears;
>   with `VERBOSE` both appear as `Trigger <tgname> for constraint <conname>`.
>
> Give the two objects distinguishable names, or the assertion cannot tell which
> one leaked. Note `CREATE CONSTRAINT TRIGGER` names the constraint after the
> trigger by default, which makes them identical unless you intervene.

**FR-63 — text format must be as clean as the structured formats.** [V]
Every fixture in §10.2 is run in all four formats and the same absence
assertion is applied. Additionally, these paths write directly to `es->str`
in text mode and never pass through the property functions, so they need
explicit text-mode assertions: trigger/constraint/relation names
(explain.c:1134/1138/1140), index names (1715-1716, 4550) *(rev. T16: the index-name half is done, and in all four formats rather than text alone — the text tail and the `Index Name` property are written by different branches of both emission sites, so a text-only check covers neither property path. `Scan Direction` is checked in all four for the same reason.)*, the scan-target
`on schema.name alias` clause (4710-4718), `Sampling:` (3075), and the bare
sub-plan label line in `ExplainNode`.

**FR-64 — redaction state must survive a scratch deparse context.** [V as a
defect; not SQL-reachable]
Site: `get_range_partbound_string()` zeroes a fresh `deparse_context` at
ruleutils.c:3921 and then calls the constant printer, discarding any flag
carried in that struct. `T_PartitionBoundSpec` does not appear in plan
expressions, so this is latent rather than live. Test it structurally: a unit
test (or a static assertion) that every `deparse_context` construction site
either inherits redaction state or is provably unreachable with redaction on.
Enumerate the construction sites in the design and assert the count, so a new
one added later fails the test.

**FR-45 / D8 — no state outlives a record.** [V]
Run the same statement twice in one session with redaction on.
Assert: both records use `t1` for the same relation (FR-42 determinism), and
the second record's numbering **starts at 1** — it must not continue from
where the first left off, which would indicate a session-lifetime counter.

**FR-76 — correlation token.** [V as a requirement]
Assert: each redacted record carries a token; two records carry different
tokens; the token is not derivable from the query text or the query
identifier; and the token appears in whatever companion channel the design
chooses so an operator can actually join on it.

### 10.3 Mode matrix

Each fixture above is a *content* test. It must be run across the
configuration axes that change which code paths execute, because several
emission sites are gated:

| Axis | Values | Why it changes coverage |
|---|---|---|
| format | `text`, `json`, `xml`, `yaml` | text bypasses the property functions (FR-63) |
| `VERBOSE` | off, on | gates `Output`, `Function Call`, `Table Function Call`, `Schema`, `Query Identifier` |
| `ANALYZE` | off, on | gates the entire trigger section (FR-17) and all counters |
| `log_triggers` | off, on | with ANALYZE, gates `report_triggers()` |
| `log_settings` | off, on | gates the `Settings` section (FR-26) |
| parallelism | serial, `debug_parallel_query = on` | gates per-worker blocks and the `es->str` swap |
| plan type | custom, generic (`plan_cache_mode`) | custom inlines `Const`s; generic prints `$N` |

The minimum honest matrix is: all four formats × {VERBOSE off, on} for every
fixture, plus the ANALYZE + `log_triggers` combination for FR-17, plus one
parallel run and one generic-plan run.

> **Fixtures corrected by T01 after review.** Five catalog entries did not reach
> the path they named, and passed only on the incidental table and column names
> every fixture touches. Recorded here because the shapes are not obvious:
>
> | Requirement | Why it missed | Fix |
> |---|---|---|
> | FR-16 index name | 20-row table, so the planner chose a Seq Scan and the index-name site was never executed | `enable_seqscan`/`enable_bitmapscan` off, in its own GUC section *(rev. T16: those two are enough for an **Index Only** Scan and not for a plain `Index Scan` — with only them the planner picks index-only, so the one surface gets measured twice and the other not at all. `enable_indexonlyscan` off as well for that case, and `enable_indexscan` off too for the bitmap case. Same failure, one level further in.)* |
> | FR-20 user collation | `COLLATE` on the Var is absorbed into the operator's `inputcollid` by constant folding; no `CollateExpr` survives to deparse | put `COLLATE` on the **constant** |
> | FR-46 subquery alias | subquery flattened into the outer scan; neither alias nor output name exists | `OFFSET 0` |
> | FR-93 composite assignment | no shape prints the target field name; it reaches output only through a **read** | withdrawn to a negative control |
> | FR-94 named-arg label | wrapper discarded by the parser (see §5.2.1) | withdrawn to a negative control |
>
> The root cause was systemic: the positive control asserted that *some* marked
> identifier appeared, never which one. Each fixture now carries the identifier
> it exists to produce and asserts membership, which turned all five red at once
> and will catch the next one when it is written.
>
> **Build-feature gap found by T01 — and closed.** T01 believed two requirements
> could not be verified at all on a default build. Both rows have since been
> measured and neither claim survived, so the table is now a record of two
> phantom gaps rather than a list of real ones:
>
> | Requirement | Needs | Consequence if absent |
> |---|---|---|
> | FR-95 (XML constructs) | ~~`--with-libxml`~~ **nothing** | **Corrected by T13, measured on a `USE_LIBXML = 0` build.** The claim was too broad, and the reason it was wrong is instructive: what libxml gates is narrower than "XML". The failure is raised by `map_sql_identifier_to_xml_name()` (xml.c) during **parse analysis**, so the constructs that turn a user identifier into an XML name — `XMLELEMENT`, `XMLFOREST`, `XMLPI` — cannot even be parsed here. Everything else can: `XMLCONCAT`, `XMLSERIALIZE`, `XMLPARSE`, `XMLROOT` and `IS DOCUMENT` all plan and deparse, and so does `XMLTABLE`, including an `XMLNAMESPACES` prefix and `COLUMNS` names, which off-mode prints in full (`Table Function Call: XMLTABLE(XMLNAMESPACES ('http://x'::text AS zns_secret), … COLUMNS zxcol_secret text PATH …)`). Since the collapse emits one placeholder regardless of which op it was, FR-95 is fully verifiable without libxml. The unparseable ops mattered only to the abandoned pseudonym design, which had to redact each name individually. |
> | FR-98d, `IS NORMALIZED` / `normalize()` half | *nothing* | **Corrected by T01:** these are implemented in `src/common/unicode_norm.c` and need no ICU at all. The original ICU gate skipped an assertion that would have run. |
>
> Detecting the libxml build is harder than it looks, and T01 got it wrong twice
> in opposite directions. Probing `pg_proc` for `xmlelement` always returns 0,
> because `xmlelement` is grammar and has no catalog row -- so the fixture
> skipped on *every* build, and a TAP skip counts as a pass. Probing for
> `xmlcomment` always returns 1, because the catalog row exists whether or not
> libxml was compiled in; only the runtime fails. No catalog probe can answer
> the question, because the question is about the build. Use
> `check_pg_config('#define USE_LIBXML 1')`, which reads `USE_LIBXML` out of the
> installed header. *(Kept as a record of the trap, but T13 removed the only
> reason to run the probe: no FR-95 fixture needs to be gated on the build any
> more, so none should be — a gated fixture is a fixture that can skip, and a
> skip counts as a pass.)*
>
> ~~These fixtures live in the TAP test rather than a regression file precisely
> so they can be skipped rather than failed.~~ *(rev. T13.)* FR-95's fixtures
> belong in the regression file with everything else and must **fail** rather
> than skip, because they now run everywhere. Nothing in FR-95 or FR-96 is
> gated on a build option. Write them with a parseable op — `XMLCONCAT` or
> `XMLSERIALIZE` over an `xml` column, not `XMLELEMENT` — and they exercise the
> same single guard that `XMLELEMENT` would reach on a libxml build. The
> remaining CI requirement is the narrow one: a libxml build is still the only
> place `XMLELEMENT`/`XMLFOREST`/`XMLPI` can be *parsed*, which is worth one
> confirmation that those ops reach the same guard, not a precondition for
> FR-95 being verified.

### 10.4 Negative controls — output that must **not** change

A redaction test suite that only asserts absence will pass if the
implementation blanks everything. These assert the opposite, and are what
protects goals 2 and 3:

- `pg_catalog` function names still print (`count`, `now`, `generate_series`).
- Core operators still print (`=`, `<`, `+`), and core type labels still
  appear (`?::integer`, `?::text`).
- Access-method names still print (`btree`).
- Node types, `Strategy`, `Join Type`, `Parent Relationship`, `Sort Method`,
  `Cache Mode`, `Storage` are unchanged.
- Costs, plan rows, plan width, actual rows, loops, timings, buffer/WAL/IO
  counters, worker counts and trigger timings are unchanged (FR-30 – FR-38).
  Two traps T01 fell into, worth stating so the next author does not:
  **actual** row counts are printed with two decimal places (`rows=15.00`)
  while the planner **estimate** is an integer (`rows=16`), so a pattern
  matching `rows=\d+` silently matches the estimate and tests nothing — anchor
  actual-row assertions to `actual time=`. And these assertions only mean
  anything if the fixture tables hold rows; against an empty table every count
  is zero and the whole set is vacuous.
- A self-join shows the **same** relation pseudonym twice; two different
  tables show different pseudonyms (FR-40). *(rev. T15: verified. The self-join
  is the case that separates the two halves of the rule — one relation
  pseudonym, two alias pseudonyms — and it is the case a "number the scans as
  you meet them" scheme gets wrong.)* *(rev. T16: the same rule verified
  for indexes. An `ON CONFLICT` arbiter index and an index scan on that index
  print the same `iN` from two different functions, and two different indexes on
  one relation print `i1`/`i2` while the relation stays `t1`.)*
- `Scan Direction` and `Index Searches` still print on redacted index-scan and
  bitmap-index-scan nodes *(rev. T16)*. Both live on the nodes T16 edits —
  `Scan Direction` in the same two format branches of the same function as the
  index name — so a guard widened from the name to the function or the node
  would take them with it.
- With `log_redact = off`, output is byte-identical to the unpatched build
  across the whole existing `auto_explain` and `EXPLAIN` regression suites
  (FR-62), and the existing `ruleutils` suites are byte-identical too.

## 11. Revision history

- **v1.0** — initial complete specification; D1–D4 resolved.
- **v1.1** — adversarial security review incorporated: custom-scan provider
  name (FR-28), non-scan index-name sites (FR-16), TABLESAMPLE methods
  (FR-18), `Query Identifier` omitted (FR-37/D5), uniform constant
  redaction (FR-21/D6), namespace-primary exemption (FR-50/D7), opaque
  column counters (FR-12), single-record mapping scope (FR-45), fail-closed
  lookup failures (FR-60), envelope/statement-channel notice (FR-75),
  json_table path strings (FR-24), residual risk register (§9), extended
  acceptance tests (§8.7).
- **v1.2** — source-code leak-path audit incorporated. Eleven additional
  sensitive items (§5.2.1, FR-90 – FR-99): sub-plan labels carrying CTE and
  subquery names, window names, the `Replaces` property, composite-type field
  names, named-argument labels, XML construction names, JSON/XML path and
  `PASSING` labels, cursor names, second-path collation/operator/opclass and
  raw-datum constants, sequence names. Structural fixes: pseudonym key domain
  widened to relid-less RTEs (FR-46), pseudonyms assigned before name
  uniquification (FR-47), redaction applied at the value source rather than the
  serializer (FR-63), redaction state must survive a scratch deparse context
  (FR-64). Scope fixes: generic per-plan/per-node EXPLAIN plugin hooks brought
  under suppression (FR-25), `REDACT` with an extension-registered option
  rejected (FR-29/FR-72), FR-4's orthogonality claim narrowed accordingly.
  Contradiction resolved: FR-42 vs FR-45 vs the v1.1 §8.7 test (D8) — the test
  is withdrawn. Policy changes: redaction GUCs moved to `PGC_SIGHUP` (D9), the
  `Query Parameters` property now omitted rather than rendered (D10).
  Additions: correlation token (FR-76), FR-81 cost scoped per logged record,
  §9 cardinality row now names ANALYZE as the activating mode and rules out
  counter suppression as a remedy, FR-60 enumerates the existing `elog(ERROR)`
  sites it obliges. New leak-path test catalog (§10) with fixtures, mode
  matrix and negative controls.
