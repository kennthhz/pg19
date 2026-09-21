# Auto-Explain Log Redaction — Execution / Coding Task Plan

| | |
|---|---|
| **Status** | v1.0 — derived from [requirements v1.2](auto-explain-redaction-requirements.md) and [implementation design v1.2](auto-explain-redaction-implementation-design.md) |
| **Shape** | 23 tasks in 6 stages. One task = one revertible commit (or a small series landed together). |
| **Related** | [requirements](auto-explain-redaction-requirements.md) · [implementation design](auto-explain-redaction-implementation-design.md) |

---

## 1. Sequencing rules

The order below is not a convenience. It is chosen so that three properties
hold at every task boundary, and they are what make the plan safe to stop or
unwind at any point.

### 1.1 Monotonic safety

**Redaction starts as total suppression and is progressively *narrowed*.**

The first shippable state (T04) blanks or omits every name and every
expression: the record is plan shape, costs and counters only. Every task
after that replaces one blanked field with a pseudonym — trading
informativeness for nothing, and never the reverse.

The consequence is the property that matters for rollback: **reverting a task
always makes the output *more* redacted, never less.** A revert can cost you
diagnostic detail. It cannot open a leak. Contrast the naive ordering — build
pseudonymization bottom-up and enable output as you go — where a revert in the
middle leaves a record that prints real names.

### 1.2 The plan is a stack; unwind from the top

Each task depends only on tasks before it. Reverting the most recent task is
always safe and always leaves every earlier task's value intact.

**Reverting out of order is not safe after T21.** Once T21 re-enables
expression output, tasks T06–T20 are load-bearing for the redaction contract:
reverting, say, T09 (constant redaction) while T21 is in place would print real
literal values. If you need to unwind past T21, revert T21 first. T21's commit
message must say this, and T21 ships a defensive assertion (see the task) so
the mistake fails loudly rather than silently.

### 1.3 No user-visible surface until the contract is complete

T01–T03 add no option, no GUC and no behavior change. `EXPLAIN (REDACT)` and
`auto_explain.log_redact` do not exist until T04, at which point they are
already fail-closed. There is no window in which a user can enable a
half-implemented redaction mode.

### 1.4 Standing exit criteria — every task

A task is not done until all of these pass, regardless of what the task
itself changed:

1. **Off-mode byte identity (FR-62).** Full `make check-world` with no
   redaction enabled produces output byte-identical to the pre-patch tree.
   This is the single most important standing check: it is what keeps the
   `ruleutils.c` changes from affecting `pg_get_viewdef`, `pg_get_ruledef`,
   `pg_get_expr`, FDW deparse and every extension that calls
   `deparse_expression()`. Design §8 calls it gating; treat a failure as a
   blocker, never as an expected-file update.

   **The tree must be configured with `--enable-depend`, and this criterion is
   void without it.** PostgreSQL's makefiles do not track header dependencies
   unless it is set, so editing a header recompiles nothing. T03 hit the
   consequence: adding a field to `ExplainState` shifted the offsets of
   `es->indent` and everything after it, `contrib/pg_plan_advice` was not
   rebuilt, and its module read the new backend's `ExplainState` through the old
   layout — nine test files failed on indentation alone, with no defect in the
   change. The reverse is what makes this a standing criterion rather than a
   footnote: a task that edits a header and is verified against stale objects
   can report a clean check-world for code that was never compiled, and on this
   feature that failure mode passes a leak. Any task touching
   `explain_state.h`, `explain_redact.h` or `ruleutils.h` must either build with
   dependency tracking on or `make clean` first.

   Two further host requirements were established the same way, both of which
   made check-world fail before any redaction code was involved:
   `IO::Tty` >= 1.12 (`src/bin/psql/t/030_pager.pl` calls `set_winsize`, absent
   in 1.10, and the test dies rather than skipping), and an expected-output
   sort order that does not depend on the host locale — see criterion 6.
2. **Leak-check suite green** (T01 harness): no fixture identifier appears in
   any redacted record, in any of the four formats.
3. **Negative controls green** (requirements §10.4): exempt names, operators,
   type labels, node types and every counter still print. This is what stops a
   task from "passing" by blanking more than it should.
4. **Coverage check.** Build with `--enable-coverage`, run the fixture suite,
   and confirm that every choke point the task claims to cover was actually
   executed. This converts "I believe this fixture reaches
   `get_name_for_var_field()`" into a checked fact. It is a standing criterion
   rather than a task because it applies to each task's own choke points, and
   because T01 demonstrated the failure mode it catches: two of six predicted
   fixture shapes did not reach the code they were written for. A fixture that
   passes without executing its target is worse than a missing fixture, because
   it reports coverage that does not exist.
5. **No new compiler warnings**; PostgreSQL coding style (NFR-1). From T02
   onward, `src/tools/pgindent` for C and `src/tools/pgindent/pgperltidy` for
   Perl (perltidy 20230309 specifically, per `src/tools/pgindent/README`).
6. **Locale-independent expected output.** Every `ORDER BY` on a text column in
   a new test needs `COLLATE "C"`. The suite runs under whatever locale the host
   provides, and `pg_upgrade`'s harness initialises its cluster with a different
   one than `make check` does — so a linguistic sort order that looks stable
   under repeated `make check` runs still fails once check-world reaches
   `src/bin/pg_upgrade`. T01 shipped with this defect and it went unnoticed
   because check-world had not been run. The markers make it likelier than it
   looks: `zsec_ssn` and `zsecdata-ssn` first differ at `_` against `d`, and a
   linguistic collation ignores punctuation at the primary level where C does
   not. Note that `ORDER BY 1 COLLATE "C"` does not mean the first column — it
   collates the integer 1 and fails at run time; sort in an enclosing query
   instead.

---

## 2. Test infrastructure

Three existing harnesses are extended rather than replaced:

| Where | Exists today | Used for |
|---|---|---|
| `src/test/regress/sql/explain.sql` + `expected/` | `explain_filter()`, `explain_filter_to_json()` helpers; registered in `parallel_schedule:126` | core `EXPLAIN (REDACT)` behavior, all four formats |
| `contrib/auto_explain/sql/` + `expected/` | `REGRESS = alter_reset extension_options` | GUC behavior, option interactions |
| `contrib/auto_explain/t/001_auto_explain.pl` | `TAP_TESTS = 1` | log-content assertions, which is the only way to test what actually reaches the log |
| `src/test/modules/test_explain_redact/` | **new in T02** | C-level unit tests for `RedactCtx` and for `deparse_expression_redacted()`, exposed as SQL-callable functions |

`contrib/auto_explain/Makefile` already carries
`EXTRA_INSTALL = contrib/pg_overexplain`, so the FR-29 test needs no build
changes.

### 2.1 How completeness is actually established

The fixture catalog is a hand-built list derived from reading the source, and no
amount of care makes a hand-built list provably complete. Four mechanisms
compensate, in increasing order of strength. It is worth being explicit about
which of them are guarantees and which are only good practice.

**Marking discipline (T01, mechanical).** Every fixture object carries the
`zsec_` marker and every stored value carries `zsecdata-`, and a catalog query
asserts it — an unmarked fixture object fails the test at the moment it is
written. This makes the detector sound *for the paths a fixture exercises*. It
says nothing about paths no fixture exercises, and it is important not to mistake
it for more than that.

Marking the **values** as well as the names matters more than it first appears:
an identifier-only marker is structurally blind to the entire class of leaked
data, because a real value is not an identifier and matches no pattern. Making
the stored values self-identifying closes that class without needing a
classifier that recognises arbitrary sensitive data.

**Coverage verification (standing criterion 4, mechanical).** Confirms that each
fixture reaches the code it was written for. Closes the gap between "the fixture
passes" and "the fixture tests what it claims".

**Catalog-based scanning of the whole regression suite (T04a, mechanical, and
the strongest of the four).** Uses the live catalog as the oracle instead of a
naming convention, over PostgreSQL's own thousands of queries instead of our
thirty-odd. This is the mechanism that most reduces the risk, because it removes
both hand-built inputs at once: the fixture list and the marker.

**Assert-build tripwire (T02, mechanical, best diagnostics).** Traps at the
emission site rather than grepping the finished record, so a failure names a line
instead of a symptom — and it fires for *any* query touching marked objects, not
only for the fixtures, so it catches paths the catalog missed.

**Periodic re-audit of the source enumeration (judgement, not a gate).** The
residual weakness is not detection, it is enumeration: did we find every place in
`explain.c` and `ruleutils.c` that prints a user-derived string? That is an
exhaustive-reading problem over ~19,000 lines, it is where an LLM is genuinely
useful, and its output is *verifiable* because every claim is a file and line
someone can check. The v1.2 audit that produced FR-90 to FR-99 was exactly this.

Repeat it after every upstream rebase and record findings as new catalog entries.
Two constraints, both firm:

- **It is a review activity, never a CI gate.** Non-deterministic checks make bad
  security gates: a flaky pass manufactures confidence, and a flaky failure
  trains people to re-run until green.
- **It must not send plan text to an external service.** Uploading records to a
  third-party API to ask whether they contain sensitive data is architecturally
  the same act as the log-shipping this feature exists to make safe. Run it
  against source code and synthetic fixtures only.

**What none of this closes.** A leak reachable only by a plan shape that appears
in no test suite anywhere. That is unfalsifiable and is accepted. The point of
T04a is to change the residual from "our enumeration might be incomplete" —
a bet on one person's thoroughness — to "PostgreSQL's own suite does not cover
this shape", which is a materially better place to be.

---

## 3. Tasks

### Stage 0 — detection before construction

#### T01 — Fixture schema and leak-detection harness — **DONE**

**Goal.** Build the detector *before* the thing it detects, and prove the
detector works. No product code changes.

**Touches** (as landed; deviates from the original plan — see below).
`src/test/regress/sql/explain_redact.sql` (new),
`src/test/regress/expected/explain_redact.out` (new),
`src/test/regress/parallel_schedule` (one word),
`contrib/auto_explain/t/002_redact.pl` (new).

> **Deviation.** The plan said to extend `src/test/regress/sql/explain.sql`. A
> separate `explain_redact` test was used instead: the fixture schema creates a
> schema, a collation, three types, four tables, two indexes and a function, and
> folding that into a core test file would produce a large expected-file delta
> that conflicts on every upstream rebase — and would make T01 awkward to revert,
> which is the one property T01 must have. `meson.build` reads
> `parallel_schedule`, so the single-word registration covers both build systems.

**Result.** 33 of 33 catalog fixtures leak under ordinary EXPLAIN; the detector
self-checks return zero; both marking conventions are enforced by catalog
assertions in both test files; the full `src/test/regress` suite passes 241/241
with the new test in the `explain` parallel group; the TAP test passes 24
subtests with 1 skipped (no libxml on the build host). Expected output verified
stable across repeated independent runs, and the Perl file is perltidy-clean at
the version `src/tools/pgindent/README` requires.

**On the two fixture schemas.** They are deliberately *not* identical and are not
kept in lockstep: the regression file needs a collation, enum, domain, composite
type and partitioned tables to reach type- and collation-name paths it asserts
on, while the TAP file needs triggers, which the regression file cannot reach at
all. Forcing parity would mean each file carrying objects its own assertions
never touch. What is shared is the marker convention, and *that* is enforced in
both files — schema divergence is acceptable, marker divergence is not.

**Delivers.** The requirements §10.1 fixture schema — with **marked data as well
as marked names**, and with the marking convention **enforced** rather than
trusted (§2.1) — plus a helper that returns the fixture identifiers and values
found in an EXPLAIN result:

```sql
-- returns leaked identifiers; empty result = pass
create function zsec_leaks(query_text text, explain_opts text)
returns setof text language plpgsql as $$
declare ln text; buf text := '';
begin
  for ln in execute format('EXPLAIN (%s) %s', explain_opts, query_text) loop
    buf := buf || ln || E'\n';
  end loop;
  return query
    select distinct m[1] from regexp_matches(buf, '(z[a-z0-9_]+)', 'g') m
    order by 1;
end $$;
```

Two markers, because they cover two different leak classes: `zsec_` on every
identifier, and `zsecdata-` on every stored value. The second is not optional —
an identifier-only pattern is structurally blind to leaked *data*, since a real
value is not an identifier and matches nothing. Marking the values makes them
self-identifying and closes that class without a classifier.

Both conventions are asserted by catalog queries, so an unmarked fixture object
or an unmarked stored value fails the test when it is written rather than
becoming a permanent blind spot. Seeding rows also removes a plain gap: with
empty tables, ANALYZE-mode records report zero rows everywhere and plan shapes
needing real data never occur. `ANALYZE` is run explicitly afterwards, because
otherwise `reltuples` stays stale and autovacuum may update it mid-run, making
plan choice — and the expected output — nondeterministic.

**Tests — positive control.** Call `zsec_leaks(q, '')` (no `REDACT`) for
every fixture in requirements §10.2 and assert it **returns** the identifiers.
A detector that finds nothing today would silently pass every later task. This
task's whole promise is "the detector works", and this is what exercises it.

**Findings.** All three `[C]` questions are resolved, and running the fixtures
corrected six things that reading the code had gotten wrong. All six are now
recorded in requirements §10.

1. **Marker prefix corrected, `z` → `zsec_`.** The requirements claimed nothing
   in core output starts with `z`; `timestamp with time zone` contains `zone`,
   which a `/z[a-z_]+/` detector reports as a leak. Four characters removes the
   need for word-boundary anchoring.
2. **FR-92 confirmed, in three forms** that differ in whether a name follows:
   `Replaces: Scan on <relname>`, `Replaces: Join on <aliases>`, and
   `Replaces: MinMaxAggregate` (no name). Two non-obvious preconditions:
   `constraint_exclusion` defaults to `partition` and must be set to `on` for a
   plain `CHECK`-constrained table, and the MinMax replacement needs an index on
   the aggregated column. Neither of the two shapes the requirements originally
   proposed worked.
3. **FR-13a confirmed via the `SELECT`, not the `INSERT`, and it is worse than
   specified** — scanning a partitioned parent emits **two** identifiers on one
   line, `Seq Scan on zsec_parted_p1 zsec_parted`. T15 must redact both.
4. **FR-90's subquery-alias seed refuted.** It never reaches `Subplan Name`:
   flattened, the alias vanishes; un-flattened, it surfaces as a `Subquery Scan`
   alias, which is FR-13's territory. The CTE seed remains confirmed.
5. **FR-46's `VALUES` fixture withdrawn.** A `VALUES` RTE discloses nothing —
   EXPLAIN prints `*VALUES*` and `column1..columnN`, never the user's alias, in
   every shape tried. Retained as a negative control so that a future version
   propagating the alias would fail the test rather than ship silently. The
   implementation design was already right about this (§5); the fixture was wrong.
6. **FR-17 refined: trigger name and constraint name leak under different
   conditions.** Without `VERBOSE`, a constraint trigger prints only
   `Trigger for constraint <conname>` — the trigger name is suppressed. The test
   needs two triggers (plain and constraint) at two verbosities, with
   distinguishable names, or it silently covers only one of the two.

Two further facts worth carrying forward:

- **FR-29 quantified.** `pg_overexplain`'s `Eref` line lists *every* column of
  the relation regardless of what the query referenced, and in text mode there is
  no `Range Table` header to match on — assert on `RTI n (` and the `Eref:` /
  `Relation:` lines.
- **Build-feature gap.** FR-95 needs `--with-libxml` and half of FR-98d needs
  `--with-icu`; neither is verifiable otherwise. Those fixtures live in the TAP
  test so they skip visibly rather than passing vacuously, and CI must include a
  build with both.

**One finding came from reviewing the harness rather than running it.** The
marking convention was enforced only by hand, and the fixture tables held **zero
rows** — so leaked *values* were undetectable by construction, and ANALYZE-mode
plan shapes could not occur. Both are fixed here: the two marker conventions are
asserted by catalog queries, and the tables are seeded with marked values and
explicitly analysed. The object-marking assertion earned its place immediately
by flagging three unmarked column names on its first run (the identity
sequence's internal `last_value` / `log_cnt` / `is_called`, which are
PostgreSQL's names rather than ours and are now excluded with a written reason).

**Revert.** Test-only; four new files plus one word in `parallel_schedule`.
Reverting loses coverage and changes no behavior.

---

### Stage 1 — foundation, no user-visible surface

#### T02 — `RedactCtx`: lifetime, counters, pseudonyms, exemption

**Goal.** The pseudonym engine, standalone and directly unit-tested. Nothing
consumes it yet.

**Touches.** new `src/include/commands/explain_redact.h`,
new `src/backend/commands/explain_redact.c`,
new `src/test/modules/test_explain_redact/`.

**Delivers.** Design §3 in full: one `HTAB` per pseudonym namespace;
per-namespace counters held **in the context**, never file- or session-scope
(FR-45); the two entry points `explain_redact_name()` (OID-keyed) and
`explain_redact_local()` (`(kind, scope, ordinal)`-keyed, for names with no
catalog object); the namespace-primary exemption test (FR-50/D7); allocation in
the caller's memory context.

**Tests** (`test_explain_redact`, SQL-callable wrappers):

- FR-41: every generated pseudonym matches `^[a-z]+[0-9]+$` and needs no
  quoting.
- FR-40: same key → same pseudonym; different keys → different pseudonyms;
  namespaces do not collide.
- FR-42: assignment is a pure function of request order — the same request
  sequence yields the same names on a fresh context, and numbering is not
  seeded from a pointer value, an OID sort order, or a hash-scan order.
- FR-45: a fresh context restarts numbering at 1. Assert explicitly that a
  second context does **not** continue from the first — this is the test that
  catches an accidental `static` counter.
- FR-46: all four key domains are representable, including keys with no OID.
- FR-50/D7: `pg_catalog` and `information_schema` are exempt; a **low-OID**
  object in a user schema is **not** exempt (the initdb-provisioning hole the
  OID heuristic left open).
- FR-60: a failed namespace lookup yields a pseudonym, not an error.

**Also delivers: the assert-build tripwire.** In a `cassert` build, and only
when redaction is enabled, check at the point where bytes are appended to
`es->str` that no marked string is being written, and abort with a stack trace
if one is.

This is worth the cost because it changes what a failure tells you. The T01
detector greps the finished record, so a failure says "something leaked" and
leaves you to find where. The tripwire names the line. More importantly it fires
for **any** query that touches a marked object, not only for the fixtures — so
it catches emission paths that no fixture in the catalog happens to exercise,
which is precisely the completeness gap the catalog cannot close on its own
(§2.1).

Constraints: `cassert`-only, so production builds pay nothing; keyed on the test
marker rather than on any general notion of sensitivity, so it has no false
positives; and it must not change output, only abort. Requires the marker
convention that T01 established, which is why it lands here and not earlier.

**Revert.** Self-contained new files plus a test module. Nothing depends on it
yet.

#### T03 — `ExplainState` fields

**Goal.** `bool redact` and `void *redact_ctx` on `ExplainState`, initialised
in `NewExplainState()`, allocated lazily. No consumers, no output change.

**Touches.** `src/include/commands/explain_state.h`,
`src/backend/commands/explain_state.c`.

**Tests.** Standing criterion 1 only, and it is the point of the task: adding
struct fields must not perturb any existing output. Run the full
`check-world` byte-identity comparison.

**Revert.** Two struct fields and an initialiser.

---

### Stage 2 — first shippable state: total suppression

#### T04 — `EXPLAIN (REDACT)`, `auto_explain.log_redact`, and total suppression

**Goal.** The first state that can be enabled, and it is fail-closed by
construction. Output is plan shape, costs, estimates, actual rows, loops,
timings, buffers/WAL/IO, worker structure and trigger *timings* — and nothing
else.

This is the largest single task in the plan and is deliberately not split:
splitting it would create an enable-able state that leaks. It may be landed as
a commit series, but the option must not become visible until the last commit.

**Touches.** `src/backend/commands/explain.c`,
`src/backend/commands/explain_state.c`,
`contrib/auto_explain/auto_explain.c`.

**Delivers** — design §6 Phase 1, with the audit additions:

- Option parsing: `REDACT` in `ParseExplainOptionList()`; GUCs
  `auto_explain.log_redact` (bool, `off`, **`PGC_SIGHUP`** — D9) set alongside
  `es->analyze` at `auto_explain.c:440`.
- Suppress **every** deparsed-expression property by skipping the `show_*`
  calls: `Output`, `Filter`, `Index Cond`, `Order By`, `Recheck Cond`,
  `TID Cond`, `Join Filter`, `Merge Cond`, `Hash Cond`, `Run Condition`,
  `One-Time Filter`, `Conflict Filter`, `Sort Key`, `Group Key`, `Hash Key`,
  `Presorted Key`, `Cache Key`, `Function Call`, `Table Function Call`,
  `Sampling Parameters`, `Repeatable Seed`. No `ruleutils.c` changes.
- Blank or omit every name explain.c prints. Enumerated, because "blank object
  names" is not one code site (design §6): `ExplainTargetRel` including the
  `eref->aliasname` fallback at `explain.c:4610`; `explain_get_index_name`
  (ignore the hook at `:4237`) and `Conflict Arbiter Indexes` (`:4852`/`:4895`);
  `report_triggers` all six sites (`:1134`/`:1138`/`:1140` text,
  `:1151`/`:1153`/`:1154` structured); `Subplan Name` (`:1661` and the bare
  text line); `show_window_def` (`:2912`); `Replaces` (`:5042`/`:5064`/`:5069`);
  `Custom Plan Provider` and the `Custom Scan (…)` name; `show_tablesample`
  method (`:3052`); `show_sortorder_options` `COLLATE`/`USING`
  (`:2866`/`:2881`).
- Omit `Query Text` (FR-23), the `Query Parameters` property entirely
  (FR-22/D10), `Query Identifier` (`:825`, FR-37/D5), and the `Settings`
  section (FR-26).
- Suppress FDW callbacks, the custom-scan callback, and **both** generic
  plugin hooks — `explain_per_plan_hook` (`:657`, plus auto_explain's own call)
  and `explain_per_node_hook` (`:2335`) — and `apply_extension_options()`
  (`auto_explain.c:590`) (FR-25/D4).
- Reject `REDACT` + `SERIALIZE` and `REDACT` + any extension-registered option
  with an `ERROR` (FR-72/FR-29).
- Notices: FR-75 (one-time-per-session when `log_statement`,
  `log_min_duration_statement` or a `%q` `log_line_prefix` is active) and
  FR-73 (extension options skipped).
- Keep `errhidestmt(true)` (FR-70).

**Tests.** This is where the §10 catalog earns its keep. Every §10.2 fixture,
in all four formats, `VERBOSE` off and on: `zsec_leaks()` returns empty. Plus:

- FR-17 requires a dedicated config — `log_analyze = on`,
  `log_triggers = on` — or the trigger section is never reached and its six
  sites ship unexercised (design §1.2). TAP test.
- FR-29: `CREATE EXTENSION pg_overexplain;` then
  `EXPLAIN (REDACT, RANGE_TABLE) …` and `EXPLAIN (REDACT, DEBUG) …` must
  `ERROR`. Negative control: both still work without `REDACT`.
- FR-72: `EXPLAIN (REDACT, SERIALIZE TEXT) …` must `ERROR`.
- FR-73: with `auto_explain.log_extension_options = 'range_table'` and
  redaction on, the logged record has no range-table section and the notice is
  emitted. TAP test.
- Requirements §10.4 negative controls, in full — without them this task
  passes by blanking the counters too. The ANALYZE-mode counter assertions
  landed in T01 (`actual time=`, actual rows against seeded data,
  `Rows Removed by Filter`, `Buffers:`, planner estimates, and the duration
  prefix) must all still hold **unchanged**; they are the standing proof that
  redaction has not become deletion. Note FR-36's channel split: auto_explain
  emits no `Execution Time` property, only the `duration: N ms` prefix.
- FR-61: JSON output parses as a single object; XML and YAML parse.
- FR-2: nested statements (`log_nested_statements = on`) are redacted too.
- Parallel: one fixture under `debug_parallel_query = on`, asserting worker
  sections are present and clean.

**Revert.** Removes the option and the GUC. The tree returns to today's
behavior. Everything T01–T03 built is untouched.

**Ship note.** T04 + T05 together are the minimum viable release. T04 alone is
safe but has no correlation handle (see T05).

#### T05 — Correlation token

**Goal.** Make T04 usable in production. Without this, a redacted record cannot
be tied to the statement that produced it, and the operator's natural
workaround — enabling `log_min_duration_statement` — reintroduces the entire
disclosure that FR-75 can only warn about.

**Touches.** `contrib/auto_explain/auto_explain.c`.

**Delivers.** FR-76: a per-record token drawn from `pg_prng`, emitted in the
record's `errmsg` (`duration: %.3f ms  ref: %s  plan:\n%s`), plus a companion
`DEBUG`-level entry carrying token → statement that an operator can route to a
trusted destination.

**Tests.** TAP: two records carry different tokens; the token is present in
every redacted record; the token is **not** derivable from `queryId` — assert
that two different statements with the same `queryId` shape get different
tokens, and that the token does not equal any rendering of `queryId` (a
queryId-derived token would rebuild the offline membership oracle FR-37/D5
removes).

**Revert.** Independent and additive.

#### T04a — Catalog-based leak scan over the whole regression suite

Numbered `T04a` rather than inserted as `T05` to avoid renumbering 87 existing
cross-references; its position in the sequence is exactly what the name says,
after T04 and before T05.

**Goal.** Stop depending on a hand-built fixture list and a naming convention.
Use the **live catalog** as the oracle, over **PostgreSQL's own regression
suite** as the query corpus.

This is the highest-value item in the test plan and it must land before Stage 4
starts narrowing the suppression, so that every narrowing is checked against
thousands of query shapes rather than the thirty-odd in the catalog.

**Why it is stronger than everything else here.** The T01 harness has two
hand-built inputs, and each is a completeness risk: the fixture list (did we
think of every leak path?) and the marker convention (did we tag every object?).
This removes both. The oracle becomes a query over `pg_class`, `pg_attribute`,
`pg_proc`, `pg_type`, `pg_collation`, `pg_constraint` and `pg_trigger` for
everything outside `pg_catalog` and `information_schema` — the database already
knows every user-defined name, so nothing has to be tagged and nothing can be
forgotten. The corpus becomes the existing suite, which covers partitioning,
inheritance, every join type, window functions, recursive CTEs, foreign tables
and node types no hand-written fixture set will ever match.

**Touches.** New `src/test/modules/test_redact_scan/` (or a TAP test under
`contrib/auto_explain/t/`), plus a `--temp-config` fragment.

**Delivers.**

1. A config fragment forcing `auto_explain.log_redact = on`,
   `auto_explain.log_min_duration = 0`, `log_analyze = on` and
   `session_preload_libraries = 'auto_explain'`.
2. A run of the full regression suite under that config, via
   `pg_regress --temp-config`.
3. A scanner that reads the resulting server log and reports any occurrence of a
   non-exempt user-defined name from the catalog.
4. An allowlist for the unavoidable, each entry carrying a written reason — this
   file is the honest record of what the feature does not redact, and it should
   be short enough to read.

**Tests.** The scan is itself the test. Two things must hold, and the second is
the one people forget:

- **Positive control**, exactly as in T01: run the scan with redaction *off* and
  assert it reports a large number of names. A scanner that finds nothing because
  its log parsing is broken would otherwise pass forever.
- **The exempt set must be principled, not fitted.** It is trivial to make this
  test pass by growing the allowlist. Every entry needs a reason, and the file
  needs reviewing as carefully as the code.

**Cost to be honest about.** Running the full suite with `log_min_duration = 0`
and `log_analyze = on` produces a very large log and is slow — this is a
nightly or pre-merge job, not something to run per commit. And it will surface
leaks in paths nobody has specified yet, which is the entire point but will feel
like scope creep when it happens.

**Revert.** Test-only and self-contained.

---

### Stage 3 — deparse machinery, with nothing re-enabled

Every task in this stage is invisible in EXPLAIN output, because expressions
remain suppressed until T21. Each is verified by calling
`deparse_expression_redacted()` directly from `test_explain_redact` and
asserting the returned string. This is the stage that makes T21 low-risk.

#### T06 — Deparse plumbing and the reachability guarantee

**Goal.** Get a `RedactCtx` to every deparse site, including the one that
builds its own context.

**Touches.** `src/backend/utils/adt/ruleutils.c`,
`src/include/utils/ruleutils.h`.

**Delivers.** `RedactCtx *redact` on the private `deparse_context`
(`ruleutils.c:112-128`); the three new entry points
`select_rtable_names_for_explain_redacted()`,
`deparse_context_for_plan_tree_redacted()` (needed because column pseudonyms
are assigned under `deparse_context_for_plan_tree()`, `ruleutils.c:3762`, not
under the per-expression call) and `deparse_expression_redacted()`; and the
FR-64 reachability fix for `get_range_partbound_string()`, which zeroes a fresh
context at `ruleutils.c:3921`.

**Tests.**

- A census test: assert the number of `deparse_context` construction sites in
  `ruleutils.c` equals a pinned constant, so a newly added one fails the build
  rather than silently leaking (FR-64).
- If the file-scope-static option is chosen, a test that raises an error
  mid-deparse and asserts the static is cleared (`PG_FINALLY` correctness).
- Standing criterion 1 is the real gate here: this task touches the file shared
  by all deparse callers.

**Revert.** Additive plumbing; no caller passes a context yet except the test
module.

#### T07 — Layer C: relation aliases

**Goal.** `set_rtable_names()` (`ruleutils.c:3892`) yields `tN`/`aN`.

**Delivers.** All four branches — user alias (`:3959`), `get_rel_name()` for
`RTE_RELATION` (`:3963`), unnamed join → NULL (`:3967`), and
`rte->eref->aliasname` for everything else (`:3973`). Assignment happens
**before** the `_%d` uniquifier at `:3990-4015` (FR-47).

**Tests.** For each RTE kind, assert the alias is a pseudonym. FR-47
specifically: two relations whose real names collide must not produce `t1_1` or
any name-fragment; the uniquifier must be a no-op.

#### T08 — Layer C: column names

**Goal.** `set_relation_column_names()` (`ruleutils.c:4383`) yields
`t<n>_cN`, keyed `(varno, attno)`.

**Delivers.** Both branches — the `RTE_RELATION` catalog branch
(`:4411-4419`) and the `expandRTE()` / `rte->eref->colnames` branch
(`:4440-4460`). Also `ret_old_alias`/`ret_new_alias`, pseudonymized where
`set_deparse_context_plan()` installs them (read at `:7738-7740`).
`get_variable()` needs no change: its read of
`colinfo->colnames[attnum - 1]` (`:7839`) picks the pseudonym up.

**Tests.** The FR-46 fixture set from requirements §10.2 — subquery output
name, `VALUES` aliases, function-scan alias, `ROWS FROM` coldeflist, join
output names, CTE column aliases — each as a **separate** case, so one passing
path cannot mask a failing one. Plus FR-12: the numeric part is an opaque
per-RTE counter, never the attno (a table whose sensitive column is attno 9
must not surface `_c9` unless it is the 9th distinct column used). Plus
FR-13b: `RETURNING WITH (OLD AS …, NEW AS …)`. Plus system columns still print
`ctid`/`xmin` (exempt), and whole-row Vars print `t1.*`.

#### T09 — Layer B: constants

**Goal.** Every constant becomes `?` plus its type label.

**Delivers.** `get_const_expr()` (`:11529`) — including `NULL`, `true`,
`false`, with no exempt value class (D6) — and `get_const_collation()`
(`:11660-11675`).

**Tests.** Each SQL base type; `NULL`/`true`/`false` explicitly (§8.7);
arrays and `ScalarArrayOpExpr` right-hand sides; the `showtype = -1` callers;
`VALUES` rows. Assert the type label survives (`?::text`) — FR-21 keeps type
information deliberately.

#### T10 — Layer B: relation, function and operator names

**Delivers.** `generate_relation_name()` (`:13396`) → `tN`, schema dropped;
`generate_function_name()` (`:13492`) → `fN` for user-defined, exempt names
kept, resolution unchanged; `generate_operator_name()` (`:13599`) → `opN` for
user-defined, exempt operators kept.

**Tests.** A user function and a `pg_catalog` function in one expression:
first pseudonymized, second not. Same for operators (`=` kept, user operator
→ `op1`). Same relation in two places → same `tN` (FR-40).

#### T11 — Layer B: type and collation names

**Delivers.** All **twelve** `format_type_with_typemod()` sites in the
expression path (`:7908, 9492, 9937, 9999, 10267, 10754, 11510, 11547, 11649,
11723, 12124, 12321`) routed through a single helper rather than twelve edits;
`generate_collation_name()` sites including `T_CollateExpr` (`:9841`).

**Tests.** One case per site where reachable. Enum, domain, and composite type
names → `tyN`; a schema-qualified user type is not printed schema-qualified;
core type labels (`integer`, `text`) still print (negative control).

#### T12 — Layer B: composite field names and named arguments

**Delivers.** `get_name_for_var_field()` (`:8052`, printed at `:9712`) across
**all four** of its name sources — `RowExpr->colnames` (`:8074`),
`TupleDescAttr(...)->attname` (`:8110`, `:8478`),
`get_rte_attribute_name(rte, fieldno)` (`:8214`), sub-tlist resnames;
`processIndirection()` (`:13191-13193`); `T_NamedArgExpr` (`:9424`).

**Tests.** Field selection `(zcol_comp).zfield_ssn`; a whole-row field
reference `(zc).zcol_ssn` — this is the only fixture that reaches `:8214`, and
without it that return path is untested; the assignment form
`SET zcol_comp.zfield_ssn = …`; a named-argument call, using a `plpgsql`
function so inlining does not remove the `FuncExpr`.

#### T13 — Layer B: XML and JSON names

**Delivers.** `T_XmlExpr` name and `arg_names` (`:10165`, `:10186`);
`XMLNAMESPACES` prefix (`:12080`); tablefunc column names (`:12122`,
`:12319`); `JSON_TABLE` root path `AS` (`:12393`), `NESTED PATH AS`
(`:12166`), `PLAN` clause names (`:12234`), `PASSING … AS` (`:12418` and
`:10638`).

**Tests.** Requirements §10.2 FR-95 and FR-96 fixtures. Note the `XmlExpr`
fixture is placed in `Filter`, which is **not** `VERBOSE`-gated — that is the
point of it.

#### T14 — Layer B: remaining leaf sites

**Delivers.** `T_CurrentOfExpr` cursor name (`:10403`); `T_NextValueExpr`
(`:10419`), preserving the `nextval('…')` literal shape (FR-99/FR-61); the
three raw-datum constants in `get_func_sql_syntax()` (`:11284`, `:11306`,
`:11330`); the `T_InferenceElem` collation and `get_opclass_name()` guard
(`:10460`, `:10468`, `:13123`/`:13128`) — not reachable from EXPLAIN today, so
implemented as a guard and verified by direct call, not by SQL;
`get_parameter()`'s function/argument-name branch guard (`:8836-8842`).

**Tests.** §10.2 FR-97, FR-98c, FR-98d, FR-99 fixtures. For FR-99 assert the
literal shape survives, not just that the name is gone.

---

### Stage 4 — re-enable output, one surface per task

Each task replaces T04's blanking of one surface with the pseudonym. Reverting
any of them returns that surface to blanked.

#### T15 — Relation, schema and alias names

`ExplainTargetRel` (`:4599`): `objectname` → `tN`, `namespace` omitted,
`refname` from layer C — **including** the `eref->aliasname` fallback at
`:4610`. Plus `Replaces` (`:5036-5069`) with the same fallback at `:5042`.
Note `Alias` is emitted unconditionally in non-text formats (`:4724`) and is
not `VERBOSE`-gated.

**Tests.** Self-join shows the same `tN` twice; two tables show different
pseudonyms (FR-40); `Schema` absent; the FR-13a partition fixture.

#### T16 — Index names

`explain_get_index_name()` → `iN` (hook still ignored);
`ExplainIndexScanDetails` (`:4550`, `:4569`); `Conflict Arbiter Indexes`
(`:4852`, `:4895`).

**Tests.** Index scan, bitmap index scan, index-only scan, and
`ON CONFLICT` arbiter indexes. FR-60: a concurrently-dropped index substitutes
a pseudonym instead of erroring the record.

#### T17 — CTE, ENR, function-scan, sampling and custom-scan names

`rte->ctename` → `cteN` (`:4688`, `:4700`); `rte->enrname` → `enrN`
(`:4693`); function-scan `Function Name` → `fN` (`:4653`);
`show_tablesample` method → `fN` (`:3052`); custom-scan provider name.

**Tests.** CTE, recursive CTE (`WorkTable Scan`), ENR, function-in-`FROM`, a
user-installed `TABLESAMPLE` method, and an extension custom scan.

#### T18 — Trigger section

`report_triggers()` → `trgN`, `conN`, `tN`, all six sites.

**Tests.** Requires `log_analyze = on` **and** `log_triggers = on` — this
surface is unreachable otherwise (design §1.2). Assert timings and `Calls`
survive (FR-38).

#### T19 — Sub-plan labels and window names

`Subplan Name` → `CTE spN` / `InitPlan spN` / `SubPlan spN` (`:1661`,
`:5152-5156`), sharing the map with T17's `cteN` so the two lines stay
relatable (FR-90); `get_parameter()`'s `(hashed SubPlan …).colN` (`:8798`);
`show_window_def` → `wN` (`:2912`); `get_windowfunc_expr_helper()`'s
`OVER <winname>` (`:11194`) — dormant until T21 but landed and unit-tested
here.

**Tests.** The FR-90 CTE fixture asserting the `CTE Name` and `Subplan Name`
pseudonyms resolve to the same object; the FR-91 window fixture; a hashed
subplan.

#### T20 — Sort-key `COLLATE` / `USING` decorations

`show_sortorder_options()` (`:2866`, `:2881`). These are appended in
explain.c *after* deparse returns, so no Stage 3 change reaches them. **This
must land before T21**, or T21 would enable `Sort Key` output carrying a real
collation name. Both sites currently `elog(ERROR)` on lookup failure and must
become pseudonym substitution (FR-60).

**Tests.** `ORDER BY … COLLATE <user collation>`; a user-defined ordering
operator for the `USING` half; built-in `>` still prints `DESC` (negative
control).

#### T21 — Re-enable expression output

**Goal.** The flip. `Filter`, `Output`, `Index Cond`, all key properties,
`Cache Key`, `Function Call`, `Table Function Call`, `Sampling Parameters`,
`Repeatable Seed` and `Conflict Filter` stop being suppressed and start being
emitted through `deparse_expression_redacted()`.

This is the highest-risk task in the plan and it is deliberately last. Its risk
was moved into T06–T20, all of which are already landed and unit-tested.

**Delivers.** Replace the T04 suppression of the `show_*` calls with calls that
pass the `RedactCtx`. Plus a **defensive assertion**: if `es->redact` is set and
the deparse context carries no `RedactCtx`, error rather than emit. That
converts an out-of-order revert of T06–T20 (§1.2) from a silent leak into a
loud failure.

**Tests.** The whole §10.2 catalog re-run with expressions enabled — this is
the first point at which most of it is meaningful. Plus §10.3's full mode
matrix. Plus the §10.4 negative controls, which now matter far more: exempt
function and operator names, core type labels, and plan structure must all be
present *inside* expressions.

**Revert.** Returns to expression suppression: less informative, still safe.
Reverting this task is the correct first move if anything downstream of T06
needs unwinding.

---

### Stage 5 — policy and documentation

#### T22 — `auto_explain.redact_allow_schemas`

**Goal.** The allowlist (FR-51/D7), `PGC_SIGHUP` (D9), empty by default.

This task **widens** disclosure, which is why it is last: it is the one task
whose revert makes output *more* redacted for a reason other than losing a
pseudonym. Consistent with §1.1 — reverting it is still strictly safer.

**Tests.** An allowlisted schema's objects print real names; everything else
still redacts; removing a schema from the list re-redacts (FR-60 fail-closed);
`public` in the list produces the documented warning behavior.

#### T23 — Documentation and release note

**Goal.** NFR-3: the new GUCs in the auto_explain docs, `REDACT` with the
`EXPLAIN` options, the §3 non-goals, and the §9 residual risks.

Must state explicitly: `log_statement`, `log_min_duration_statement`,
`log_line_prefix` and the csvlog/jsonlog envelope fields are **not** redacted
(FR-71); the GUCs are `PGC_SIGHUP` and why that differs from the other
auto_explain settings (D9); and `EXPLAIN (REDACT)` now rejects extension
options, which is a visible behavior change for anyone scripting
`EXPLAIN (RANGE_TABLE)` (design §8).

**Also: an operator-side defence-in-depth note.** Recommend running redacted
logs through a PII/DLP scanner before shipping them onward — Microsoft Presidio
is the credible open-source option, and the cloud providers have equivalents.
The framing matters and should be written carefully: this is a second,
independent layer over the in-database redaction, useful because it can catch
value-shaped leaks (things resembling identifiers, card numbers, addresses) that
a schema-aware redactor is not looking for. It is **not** a substitute for
redaction, and it must not be presented as one — a scanner sees only what
already reached the log, whereas redaction prevents it being written. Also note
the residual risks in requirements §9 that no scanner addresses: row counts,
timings and plan shape are not PII-shaped and will pass any DLP tool untouched.

---

## 4. Dependency summary

```
T01  harness ─────────────────────────────────────────────► (gates every later test)
T02  RedactCtx ──► T03 ExplainState ──► T04 total suppression ──► T05 token
 (+ tripwire)                                 │
                                              │  (shippable here)
                                              ▼
                                   T04a full-suite catalog scan
                                        (must precede Stage 4)
                                              ▼
                                   T06 deparse plumbing
                                              │
                    ┌────────────┬────────────┼────────────┬────────────┐
                    ▼            ▼            ▼            ▼            ▼
                 T07 aliases  T09 consts  T10 names   T12 fields   T13 xml/json
                    │            │            │            │            │
                 T08 columns     └── T11 types/collations ─┴─── T14 leaf sites
                    │                                              │
                    └──────────────────┬───────────────────────────┘
                                       ▼
        T15 rel ─► T16 idx ─► T17 cte/enr ─► T18 triggers ─► T19 subplan/window
                                       │
                                       ▼
                              T20 sort decorations
                                       ▼
                              T21 ENABLE EXPRESSIONS   ◄── requires all of T06–T20
                                       ▼
                              T22 allowlist ─► T23 docs
```

Stage 3 tasks (T07–T14) have no ordering constraint among themselves beyond
T07 before T08, so they can be parallelised across people. Stage 4 tasks
T15–T19 are likewise independent of each other. Two orderings are mandatory:
T20 before T21, and **T04a before any Stage 4 task** — otherwise the narrowing
tasks are validated against thirty fixtures instead of the whole suite, which is
the difference between the two completeness regimes described in §2.1.

## 5. Rollback matrix

| Revert | Effect on output | Safe? |
|---|---|---|
| T23 | docs only | yes |
| T22 | allowlisted schemas re-redact | yes — strictly safer |
| T21 | expressions suppressed again | yes — strictly safer |
| T15–T20 (after T21) | that surface returns to blanked | yes |
| T06–T14 (after T21) | **would leak** | **no** — revert T21 first (§1.2); the T21 assertion makes this fail loudly |
| T06–T14 (before T21) | none; output already suppressed | yes |
| T04a | loses the strongest completeness check; output unchanged | yes, but do not — every later task's assurance drops to the fixture catalog alone |
| T05 | no correlation token; feature usable but hard to operate | yes |
| T04 | feature disappears; tree returns to today's behavior | yes |
| T03, T02, T01 | foundation and tests removed | yes |
