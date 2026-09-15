# Auto-Explain Log Redaction — Functional Requirements

| | |
|---|---|
| **Status** | v1.1 — incorporates adversarial security review (2026-09-14); decision points **D1–D7** resolved (§7) |
| **Component** | `contrib/auto_explain`, `EXPLAIN` (core) |
| **Related** | [auto-explain-redaction-implementation-design.md](auto-explain-redaction-implementation-design.md) |
| **Terminology** | "redacted record" = one auto-explain log entry or one `EXPLAIN (REDACT)` result |

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
| FR-1 | A boolean option `auto_explain.log_redact`, default `off`, context `PGC_SUSET`, controls redacted logging. When `off`, output must be byte-identical to today's behavior. |
| FR-2 | When enabled, redaction applies to every plan auto_explain logs: top-level statements and nested statements, all log formats, all log levels, sampled and unsampled-per-`sample_rate` alike. |
| FR-3 | Core `EXPLAIN` gains an option `REDACT` (`EXPLAIN (REDACT ON|TRUE)`), producing the same redaction contract interactively, primarily so the behavior is regression-testable without loading auto_explain. |
| FR-4 | Redaction is orthogonal to every existing auto_explain option (`log_analyze`, `log_verbose`, `log_buffers`, `log_wal`, `log_io`, `log_timing`, `log_triggers`, `log_settings`, `log_format`, `log_level`, `log_nested_statements`, `log_min_duration`, `log_parameter_max_length`, `sample_rate`, `log_extension_options`) and to every `EXPLAIN` option except where §7 explicitly forbids a combination. |

### 5.2 Items that must be redacted

In every redacted record, the following must not appear in **any** field, in
**any** output format:

| ID | Item | Required treatment |
|---|---|---|
| FR-10 | Table, view, materialized view, foreign table, and partitioned-table names (scan and `INSERT`/`UPDATE`/`DELETE`/`MERGE`/CTAS targets, including the relation names shown in the trigger section) | pseudonym `t1`, `t2`, … |
| FR-11 | Schema/namespace names of redacted objects | omitted |
| FR-12 | Column names | pseudonym `t1_c3`, where the numeric part is an **opaque sequential per-relation counter** *(rev. security review: must never be the physical attno, which leaks ordinal position and column count; see FR-43)* |
| FR-13 | User-visible relation aliases / refnames | derived from the relation pseudonym, or `a1`, `a2`, … when a distinct alias must be shown |
| FR-14 | CTE names | `cte1`, `cte2`, … |
| FR-15 | Ephemeral named tuplestore (ENR) names | `enr1`, … |
| FR-16 | Index names in **any** property: index scans (`Index Name`), and non-scan sites such as `Conflict Arbiter Indexes` *(rev. security review)* | `i1`, `i2`, … |
| FR-17 | Trigger names and constraint names (trigger section, `Trigger Name` property) | `trg1`, … / `con1`, … |
| FR-18 | User-defined function, procedure, aggregate, window-function names — in every emission path: deparsed expressions, `Function Name` / `Function Call` properties, Function-Scan targets, **and TABLESAMPLE method names** (`Sampling:`, `Sampling Method`), which core resolves via a direct function-name lookup rather than the expression deparser *(rev. security review)* | `f1(…)`, …; argument expressions redacted recursively |
| FR-19 | User-defined operator names in expressions | `op1`; **exempt** operators (`=`, `<`, `+`, …) kept for readability |
| FR-20 | User-defined **type** names appearing in casts/labels (enums, domains, composite types: `::my_enum`) and user-defined **collation** names (`COLLATE …`) | pseudonym `ty1` / collation omitted or `coll1` |
| FR-21 | **All** constant/literal values in any decompiled expression (`Filter:`, `Index Cond:`, `Output:`, `Hash Cond:`, `VALUES` rows, `One-Time Filter`, `TABLESAMPLE` parameters and `REPEATABLE` seeds, …) — uniformly, including `NULL`, `true`, and `false` *(rev. security review: a `NULL` literal asserts a real row's nullability — data, not structure; uniform redaction is simpler and fail-closed)* | replaced by `?` plus the existing type label (`?::text`), preserving type information while removing the value |
| FR-22 | Parameter values: the `Query Parameters` property must not contain values. | property shows parameter names only (`$1, $2, …`) |
| FR-23 | Query text: the `Query Text` property must be omitted in redacted records | omitted |
| FR-24 | Column definitions **and path/plan strings** of table functions (`json_table` / `xmltable`): column names, and JSON path literals such as `'$.ssn'` which embed user key names and may not flow through the constant path *(rev. security review; fail-closed: if a path string cannot be redacted structurally, the property is omitted)* | column names per FR-12; path strings `?` or property omitted |
| FR-25 | Text emitted by third-party code paths: FDW `Remote SQL` and custom-scan callback output, plus extension explain options (`log_extension_options` / `apply_extension_options`) | suppressed: the callbacks are not invoked in redacted records |
| FR-28 | The extension-defined custom-scan provider name, printed **by core itself** as `Custom Scan (<name>)` and the `Custom Plan Provider` property — this does not come from the suppressed callbacks *(rev. security review)* | blanked/omitted |
| FR-26 | The `Settings` section (GUC names/values; `search_path` etc. reveal schemas) | excluded from redacted records |
| FR-37 | `Query Identifier`: the queryId is a deterministic, publicly specified hash of the parse tree — an offline dictionary attack can confirm that a specific guessed query ran *(rev. security review)* | **omitted** from redacted records |
| FR-27 | `xmltable`/`json_table` function names are core keywords | kept |

Exempt objects (per the §4 definition) are **not** sensitive: `pg_catalog`
function names, core operators, core type names (`::integer`), `btree` index
methods, etc. remain visible.

### 5.3 Items that must be preserved

| ID | Item |
|---|---|
| FR-30 | Complete plan node tree: node types, parent/child relationships, join algorithms, scan types, `Parent Relationship`, subplan structure, `Subplans Removed`, `Inner Unique` |
| FR-31 | Planner estimates: costs, plan rows, plan width, `Rows Removed by Filter/Join Filter` |
| FR-32 | Actual rows, loops, actual time, `Rows Removed by Index Recheck` (when `log_analyze`) |
| FR-33 | Buffer, WAL, I/O usage (`Shared Hit Blocks`, `Temp Read Blocks`, …) |
| FR-34 | Parallel-worker structure and per-worker stats |
| FR-35 | JIT section (timings only) |
| FR-36 | Planning Time / Execution Time / Triggers timing numbers |
| FR-38 | Trigger *timings and counts* (names redacted per FR-17) |

### 5.4 Pseudonym quality

| ID | Requirement |
|---|---|
| FR-40 | Within one redacted record, the same object always maps to the same pseudonym, and different objects map to different pseudonyms (per namespace: `t*`, `i*`, `f*`, `cte*`, `enr*`, `trg*`, `con*`, `ty*`, `op*`, `a*`). |
| FR-41 | Pseudonyms are ASCII, match `[a-z]+[0-9]+`, and never require quoting. |
| FR-42 | Pseudonym assignment is deterministic for a given plan (traversal order), so identical queries produce comparable records. |
| FR-45 | The pseudonym mapping is scoped to **exactly one record**: freshly allocated when record generation starts, discarded afterwards, never persisted, cached across statements, or reused across records *(rev. security review: a cross-record-stable mapping would let a log reader link pseudonyms between records and assemble the schema incrementally)* |
| FR-43 | No object OIDs, no physical attnos, no catalog metadata *identifiers* (relfilenode, table size), and no raw identifiers may appear anywhere in a redacted record as a side effect of redaction. (Statistics-*derived numbers* — row estimates, widths — are knowingly retained; see §9.) *(rev. security review: wording narrowed to identifying metadata)* |
| FR-44 | The mapping from object → pseudonym lives only for the duration of producing the record and is never logged. |

### 5.5 Exemption boundary and allowlist

| ID | Requirement |
|---|---|
| FR-50 | The exemption test is **namespace-primary**: an object is exempt if and only if its namespace is `pg_catalog`, `information_schema`, or a schema listed in FR-51's allowlist. The historical `OID < FirstNormalObjectId` heuristic must not be used as the primary test *(rev. security review: initdb-time provisioning of application schemas yields low-OID "user" tables that the OID test would wrongly print in full; conversely the namespace test correctly redacts low-OID non-exempt objects)*. Where no namespace can be determined for an object, it is redacted (fail closed, FR-60). |
| FR-51 | A list-valued option `auto_explain.redact_allow_schemas` exempts additional schemas (e.g. trusted extension schemas such as `pg_trgm`) from redaction. Allowlisting a schema exempts **everything later created in it**; documentation must warn against allowlisting user schemas such as `public`. Objects exempted by the allowlist print their real names; everything else still redacts. |

### 5.6 Safety / fail-closed behavior

| ID | Requirement |
|---|---|
| FR-60 | If a name or value cannot be classified as exempt during redacted output, it must be redacted (fail closed). A catalog lookup failure (e.g. a concurrently dropped object) must result in the **pseudonym being substituted**, not in the whole record being lost to an ERROR *(rev. security review)*. |
| FR-61 | Redaction must not alter output structure: records remain parseable as `text`/`json`/`xml`/`yaml` respectively, and JSON output remains a valid single JSON object (the auto_explain JSON fix-up must continue to work). |
| FR-62 | With `auto_explain.log_redact = off`, no code path may behave differently from today (no perf or output change). |

### 5.7 Interactions

| ID | Requirement |
|---|---|
| FR-70 | `errhidestmt(true)` remains in effect for redacted auto-explain records so the raw statement is not attached to the same log entry. |
| FR-75 | When redaction is enabled, auto_explain emits a one-time-per-session `LOG` notice if any concurrently active logging setting would place unredacted user information into the same log stream: `log_statement`, `log_min_duration_statement`, or a `log_line_prefix` containing `%q` *(rev. security review: envelope/statement channels; see §3)* |
| FR-71 | Documentation must state that `log_statement`, `log_min_duration_statement`, `log_line_prefix`, and the csvlog/jsonlog envelope fields (user, database, `application_name`, client address) are **not** redacted by this feature. |
| FR-72 | `EXPLAIN (REDACT)` combined with `SERIALIZE` is rejected with an `ERROR`: serialized output may contain query results, and no redaction contract exists for it. auto_explain must never enable serialization of query output. |
| FR-73 | `auto_explain.log_extension_options` may activate extension explain output. In redacted records such options are ignored (per FR-25) and a `LOG` notice is emitted stating that extension explain options were skipped due to redaction. |
| FR-74 | Nested-statement records (`log_nested_statements`) are redacted independently; each nested record has its own pseudonym mapping (FR-45). |

### 5.8 Performance

| ID | Requirement |
|---|---|
| FR-80 | With redaction off: zero measurable overhead (a flag check per record). |
| FR-81 | With redaction on: overhead limited to in-memory hash lookups and short string generation per identifier; memory bounded by the distinct object count of the plan; no syscache storms beyond what normal explain already performs. |

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

Secondary defaults confirmed (no objection raised): FR-22 shows parameter
names only; FR-23 omits query text; FR-26 excludes `Settings`.

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
   - two records generated in the same session use **different** pseudonyms
     for the same table (FR-45);
   - a table created by initdb-time provisioning in a user schema is
     redacted (FR-50/D7);
   - `Sampling: <user-installed method>` redacted (FR-18).

## 9. Residual risk register (knowingly retained information)

Accepted after review; revisitable, but each item has direct diagnostic
value that pseudonymization must not destroy:

| Risk | Detail |
|---|---|
| Schema shape | Relation/column/index/trigger/function counts, index presence and key structure, partition counts, arity and argument types of redacted functions (`f2(?::text, ?::int)`). |
| Statistics metadata | Planner row estimates and widths derive from `pg_statistic`; they reveal distribution properties of user data. |
| Cardinality side channel | Actual rows, `Rows Removed by …`, and timing permit value-verification attacks against guessed predicates (e.g. `Filter: (ssn = ?)` with rows=1). |
| Pattern fingerprinting | FR-42 determinism means identical query shapes yield identical pseudonym patterns, permitting "seen this query before" correlation. |
| Log envelope | User name, database, `application_name`, client address, session id ride in the same log record (§3); FR-75 warns but cannot suppress. |
| Exempt-object names | Objects in `pg_catalog` / `information_schema` / allowlisted schemas print in full; superuser-created objects in `pg_catalog` are trusted by policy. |

## 10. Revision history

- **v1.0** — initial complete specification; D1–D4 resolved.
- **v1.1** — adversarial security review incorporated: custom-scan provider
  name (FR-28), non-scan index-name sites (FR-16), TABLESAMPLE methods
  (FR-18), `Query Identifier` omitted (FR-37/D5), uniform constant
  redaction (FR-21/D6), namespace-primary exemption (FR-50/D7), opaque
  column counters (FR-12), single-record mapping scope (FR-45), fail-closed
  lookup failures (FR-60), envelope/statement-channel notice (FR-75),
  json_table path strings (FR-24), residual risk register (§9), extended
  acceptance tests (§8.7).
