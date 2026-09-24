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

*(rev. T15: this property is about **reverts** and it still holds unchanged. What
it does not cover, and what changes at the Stage 3 / Stage 4 boundary, is the
direction of a **mistake**. Through T14 a bug could only suppress more than
intended, which the §10.4 negative controls catch. From T15 a bug can print more
than intended, and the leak detector only catches the subset where the extra
thing is a *real* name — a surface re-enabled one task early prints a pseudonym,
carries no marker, and passes every leak assertion in the suite. Each Stage 4
task therefore owes a by-name assertion that the surfaces belonging to the tasks
after it are still absent. T15 wrote the first one; the pattern, including its
anti-vacuity clause, is in that task's section.)*

*(rev. T16: T16 owes nothing new under that rule and pays it anyway in a second
currency. No later task owns an adjacent index-name surface — there is no
half-surface here to re-enable early — and T15's by-name block for T17's three
names still passes unchanged, which is the check that T16 did not wander. What
T16 adds is the form the rule takes when the error mode is not "printed a name
too early" but "printed the **wrong** pseudonym": the arbiter index and an index
scan on that index are asserted to print the same `iN`. A mismatch there carries
no marker, leaks nothing, and passes every absence assertion in the suite, so it
is the same class of invisible mistake and needs the same kind of explicit
assertion.)*

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
which of them are guarantees and which are only good practice — and, since T18,
which of them is not yet connected to anything.

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

> ***(rev. T18: as of this commit it fires for nothing.
> `explain_redact_tripwire()` has **no caller anywhere in the backend** — confirmed
> tree-wide; its only caller in the tree is its own unit test at
> `src/test/modules/test_explain_redact/test_explain_redact.c:326`. The function
> exists and works; nothing invokes it at an emission site. So of the four
> mechanisms listed here, this one currently contributes **no** coverage, and the
> completeness argument above should be read as resting on three. Recorded rather
> than fixed: wiring it up is its own task and a decision about where the call
> sites belong, not a side effect of T18. Note that this also means nothing in the
> suite would fail if the tripwire were deleted, which is worth knowing before
> anyone treats its presence as evidence of anything.)***

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
  (`:3267`/`:3289` *(rev. T20: was `:2866`/`:2881`. Only this one entry was
  re-verified — the rest of this inventory has not been audited against the
  current tree and several others are likely to have drifted too)*).
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

#### T04a — Catalog-based leak scan over the whole regression suite — **DONE**

**Result.** Landed as `contrib/auto_explain/t/003_redact_scan.pl`, gated behind
`PG_TEST_EXTRA=redact_scan`. All 241 core regression tests pass with
`auto_explain.log_redact = on`, `log_min_duration = 0` and `log_analyze = on`;
the run produces 164,397 lines of redacted plan records, the catalog yields 3,914
distinct user-defined names, and **none of them appears in any record**. Runtime
is about 13 seconds, far cheaper than the plan assumed, because `--use-existing`
avoids a second initdb and the suite's own parallel groups are left intact.

**Deviations from the plan, all verified rather than assumed.**

- `--use-existing` does **not** create the test database: pg_regress skips both
  the drop and the create in that mode, so the test creates `regression` itself
  along with the locale settings pg_regress would have applied.
- `--max-concurrent-tests=1` is not a way to serialise the run. It caps how many
  tests one schedule line may list, so pg_regress rejects the core schedule at its
  first parallel group. No concurrency limit is passed.
- `top_srcdir` is not exported to TAP tests; only `top_builddir` and
  `PG_REGRESS` are.
- The scan reads **only** auto_explain's plan records, not the log file. Three
  other things put user names into the same file: `PostgreSQL::Test::Cluster`
  defaults (`log_statement = all` and a `%q` prefix, both overridden here and the
  override asserted), the error messages the suite provokes on purpose, and T05's
  companion entries.

**The allowlist stayed empty**, which was the point. One false positive appeared
and was fixed without weakening the oracle: `Conflict Resolution` can print
`SELECT FOR KEY SHARE`, and the suite contains an object named `key`. Adding
`key` to the vocabulary would have blinded the scan to that name everywhere, so
instead the handful of properties whose values are closed sets of code constants
are skipped as whole lines. A line that can only contain code constants cannot
contain a leak.

The test reports how many catalog names it cannot distinguish from plan
vocabulary — currently 8 of 3,922 (`original percent result sample sorted tid
time usage`). That number is the honest measure of what a pass is worth, and a
jump in it means the vocabulary is being grown to keep the test quiet.

**Known limits, both recorded in the file.** The catalog is read after the suite
finishes, so objects created and dropped during the run are not searched for —
a coverage reduction rather than a blind spot, since what is under test is
emission paths and a path that leaks a dropped table's name would leak a
surviving one's. And a leak reachable only by a plan shape absent from every test
suite remains unfalsifiable and accepted.

---

#### T04a — original plan

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
any name-fragment; ~~the uniquifier must be a no-op~~.

*(rev. T15: **the no-op claim is wrong, and so is the comment T07 left in
`set_rtable_names()` asserting it.** Generated names can collide. Two unaliased
RTEs of the same relation are keyed by the same OID, both derive `t1`, and the
uniquifier fires and produces `t1_1`:*

```
-- SELECT zsec_id FROM zsec_customers UNION ALL SELECT zsec_id FROM zsec_customers
Append
  ->  Seq Scan on t1
  ->  Seq Scan on t1 t1_1
```

*The half of FR-47 that matters still holds: the suffix is appended to a
pseudonym, so no fragment of a real name survives, and the substitution still
has to happen before the uniquifier for that to be true. What fails is only the
stronger claim that the uniquifier never runs. The output shape is identical to
the unredacted plan's (`zsec_customers zsec_customers_1`), so nothing is
disclosed that was not disclosed before and no code change is warranted — but the
comment states as a fact something a two-line query disproves, which is worse
than saying nothing, so it should be corrected when that file is next touched.
Pinned as a test in the regression file.)*

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

#### T13 — Layer B: XML and JSON constructs

*(rev. T13: rescoped from names to constructs. The original plan listed the
nine sites below and pseudonymized the name at each; the implementation
collapses the whole construct instead. Requirements FR-95 and FR-96 carry the
rescope and the reasoning, which is that pseudonymizing the names inside an XML
or JSON payload — a corner case — needed ten guarded sites, five helpers, a
pre-order walk of the path tree and a range-table pointer search with a known
failure mode under parameterized `LATERAL`, where collapsing needs three
guards and is leak-proof by inspection. Sites withdrawn: `T_XmlExpr` name and
`arg_names`, `XMLNAMESPACES` prefix, tablefunc column names, `JSON_TABLE` root
path `AS`, `NESTED PATH AS`, `PLAN` clause names, both `PASSING … AS`. They are
all inside a collapsed subtree and are not reached under redaction.)*

**Delivers.** Three guards. No helpers, no new pseudonym kind, no counter.

| Guard | Placeholder |
|---|---|
| `get_rule_expr()` `case T_XmlExpr:` | `XMLEXPR(...)` |
| `get_rule_expr()` `case T_JsonExpr:` | `JSONEXPR(...)` |
| `get_tablefunc()`, ahead of its `functype` dispatch | `XMLTABLE(...)` / `JSON_TABLE(...)` |

Each prints its placeholder and returns without deparsing the subtree, so every
name inside is absent rather than pseudonymized. "Skipped" here means omitted
from the output; it never means left printing raw.

Five points that carry the design:

- The third guard belongs to `get_tablefunc()` rather than to `get_rule_expr()`'s
  `case T_TableFunc:`, so both of today's callers are covered and a third is
  covered by default. The other caller is `get_from_clause_item()`, deparsing a
  table function in a query's `FROM` clause — not reachable from EXPLAIN while
  redacted query text is deferred (requirements §3.1.1), which is precisely why
  the guard must not sit in the caller that *is* reachable.
- `T_XmlExpr` gets one fixed token instead of its op's own keyword because
  `IS_DOCUMENT` has no keyword of its own: it deparses as `arg IS DOCUMENT`. A
  per-op placeholder therefore could not be one self-contained `NAME(...)`
  shape for every op, and that shape is what lets `isSimpleNode()` go on
  classifying an `XmlExpr` as function-like, leaving every parenthesization
  rule alone. `get_tablefunc()`'s two constructs both do spell as `NAME(...)`,
  so there the placeholder names the construct.
- No guard for `T_JsonConstructorExpr` (`JSON_OBJECT`, `JSON_ARRAY`, …) or for
  `T_JsonIsPredicate`. Both route to `get_json_constructor()`, which prints no
  identifier of its own — no `quote_identifier`, no `strVal` — and recurses
  through `get_rule_expr()`, so a `JSON_OBJECT` key, being a `Const`, already
  comes out as `?` under T09.
- Removals, not additions: `REDACT_XMLNAME`, `REDACT_PATHNAME` and
  `REDACT_ARGNAME` leave `explain_redact.h` with this task. Nothing assigns
  them, and an enumerator advertising coverage the code does not have is the
  same false-promise failure that produced the suite's vacuous verdicts. One
  consequence for **T12**, whose scope is otherwise untouched: its FR-94
  `T_NamedArgExpr` guard must *omit* the `name =>` decoration rather than
  pseudonymize the label — which is what FR-94's treatment already permits,
  and the label never survives into a plan tree anyway.
- Zero deletions. Every guard is an insertion; no line that exists at HEAD is
  modified. That makes `log_redact = off` output unchanged **by construction**
  rather than by comparison, which is a stronger guarantee than the byte
  comparison T09–T11 relied on and the reason this task can skip it.

**Tests.** Requirements §10.2 FR-95 and FR-96, as amended. Three things differ
from what this section used to say.

FR-95 needs **no** libxml, measured. What libxml gates is the parse-time
mapping of an SQL identifier to an XML name, so `XMLELEMENT`, `XMLFOREST` and
`XMLPI` cannot be parsed without it — but `XMLCONCAT`, `XMLSERIALIZE`,
`XMLPARSE`, `XMLROOT`, `IS DOCUMENT` and `XMLTABLE` all plan and deparse, and
the placeholder does not depend on which op it was. So the fixtures belong in
the regression file and must fail rather than skip.

The `Filter` placement this section called "the point of it" is unavailable in
the deparse harness, which sees only the top plan node's target list. It is the
same node and the same guard from the `SELECT` list; the `Filter` shape remains
right for the EXPLAIN vehicle after T21.

Every assertion needs a non-collapsed sibling in the same list whose column
pseudonym still prints, or it cannot be told apart from T04's wholesale
blanking — the vacuity pattern this work has hit four times. Delivered as nine
rows plus two booleans in `src/test/modules/test_explain_redact`, one per
distinct deparse shape, each carrying a `t1.t1_c2` sibling, with `JSON_OBJECT`
as the negative control that still prints `JSON_OBJECT(?::unknown : t1.t1_c2
…)` and so shows the collapse is targeted rather than blanket.

**Decided, not left open:** the `get_tablefunc()` guard ships **untested**. A
`TableFunc` lives in a range-table entry, never in a target list, so the deparse
harness cannot reach it, and `Table Function Call` prints nothing until T21.
Adding a harness entry point for it was considered and rejected — it is a new
test-only deparse path built to observe one guard whose body is the same
one-token-and-return as the two guards that *are* tested, so what would be
covered is the guard's placement, not the collapse. T21 un-suppresses the
property and gets the assertion for free; it is listed there as inherited work.

Two consequences outside this task's own fixtures, both recorded where they
happen rather than absorbed silently:

- T09's `showtype = -1` fixture used `JSON_QUERY` as its vehicle, so its
  redacted half now reads `JSONEXPR(...)` and no longer witnesses that mode.
  Every `-1` call site was re-checked: what remains reachable from a plan under
  redaction is `get_coercion_expr()`'s same-type length coercion over a `Const`,
  and it has no fixture. Annotated at the fixture; a replacement belongs to T09.
- The two FR-96 rows in `src/test/regress/expected/explain_redact.out` report
  `clean` vacuously, since T04 blanks the property the label would sit in. The
  verdict is annotated at the catalog entries and the vacuity is now measured by
  two queries after the sweep, rather than the row being left to read as
  verification. ~~Repairing the sweep so that a suppressed property reports as
  such — 33 rows share the defect — is its own task.~~ *(rev. T15: not a separate
  task after all, or at least not the whole of one. Eleven of the 33 rows became
  genuine at T15 simply because the property their identifier sits in is printed
  again, and the remainder will resolve the same way as T16–T21 land. The two
  FR-96 rows are the exception and will stay vacuous here permanently, because
  the construct is collapsed by design — their real coverage is the test module.
  What is left of the original idea is the per-row annotation, which T15 wrote
  out in full at the vacuity note in that file.)* *(rev. T16: two more, and the
  count is now 13 of 33 — both of FR-16's rows, the arbiter row in the sweep and
  the `index name (scan)` row in the GUC section. The arbiter one is the clearer
  of the two: T04 skipped the gather loop, so `Conflict Arbiter Indexes` was
  absent from the record entirely and its `clean` verdict meant only that an
  absent property carries no marker. Enumerated at the same vacuity note.)*
  *(rev. T17: **15 of 34**, and the denominator moved for the first time. FR-14's
  row was promoted — its CTE name now prints as `cteN` on the scan target. FR-18's
  existing row could **not** be: that fixture reaches the function name through a
  `Filter`, which is an expression property and therefore T21's surface, so a
  **new** row was added on the Function-Scan surface instead of the old one being
  relabelled. Adding rather than promoting is the honest move and is why the
  sweep is 29 rows now rather than 28. Not promoted and never will be: FR-15,
  which has no emission site at all.)*

#### T14 — Layer B: remaining leaf sites

*(rev. T14: rewritten to match what was built. This section listed six items.
Four needed code; two were already covered by earlier tasks, and two of the
"three raw-datum constants" turned out to be sites that must **not** change.
Line numbers below are as landed, not the stale ones this plan carried.)*

**Delivered.** Four insertions in `ruleutils.c` plus one `#include` — 144
insertions, **0 deletions**, which is the whole safety argument for the task:
no existing line moved, so nothing that was printing before can have stopped.

1. **`T_CurrentOfExpr` cursor name** (FR-97, `:10781-10812`). An early-exit
   guard above the untouched block, taken only when `cursor_name` is non-NULL,
   printing `CURRENT OF cur1`. The `cursor_param` branch is deliberately
   untouched: it prints `$n`, a parser-assigned index, not anything the user
   wrote. Keyed on `hash_bytes()` of the name, because `explain_redact_local()`
   keys on two integers and a cursor has no numeric identity to offer. A fixed
   key would collapse every cursor in one record to `cur1`, and that is
   reachable — a data-modifying CTE can hold a second `DELETE … WHERE CURRENT
   OF`, putting two TidScans in one plan. The hash is only ever a hash-table
   key, never printed. Needs `#include "common/hashfn.h"`.
2. **`EXTRACT` field** (FR-98d, `:11793-11796`). `if (redact) '?' else` inserted
   in front of the existing brace block, which becomes the `else` body at its
   existing indentation. The field is user-controlled text, not a keyword; see
   the FR-98d amendment for the measurement.
3. **Inference-element operator class** (FR-98c, `:10883-10932`). Guard at the
   **call site**, with the exemption test and a replica of `get_opclass_name()`'s
   default-opclass suppression, then `break` out of `get_rule_expr()`'s switch.
   `get_opclass_name()` itself is untouched, and that placement is the point:
   it takes a bare `StringInfo` and no deparse context, and its other two
   callers (`pg_get_indexdef_worker()`, the partition-bound printer) emit DDL
   that must name real objects — a guard inside it would corrupt
   `pg_get_indexdef()` output. The `break` is safe because `context->varprefix`
   is restored above it and nothing but closing braces follows the call.
4. **`get_parameter()`'s argnames branch** (`:9124-9130`). Guard at the top of
   the `PARAM_EXTERN` branch, printing `$n` and returning. It repeats the
   function's own fallback rather than jumping to it, again to keep the change
   an insertion with no line moved.

**Already covered — no edit needed.** Both were listed here as work and were
not:

- **`T_NextValueExpr`** (FR-99, `:10419` → `:10768`). Already reads
  `generate_relation_name(…, context->redact)` since **T10**. FR-99 is a
  verification fixture, not an edit.
- **The inference-element *collation*** (`:10460` → `:10818`). Already
  `redact_collation_name()` since **T11**.

**Must not change — two of the "three raw-datum constants."**
`IS <form> NORMALIZED` (`:11825`) and `NORMALIZE(…, <form>)` (`:11849`) are
grammar keywords, not expressions: both non-keyword variants are syntax errors,
so nothing user-derived can reach those lines. Kept, on the same footing as the
built-in operator names T10 keeps, and pinned by a negative control so a future
"fix" fails. Also untouched: `get_opclass_name()` itself (`:13768`) and its two
other callers (`:1525`, `:2130`); the hashed-SubPlan `.colN` print (`:9096`,
which is T19's).

**Tests.** What was testable was **measured first**, and the measurement decided
the set. `test_redact_deparse()` deparses the top plan node's target list, so:

| fixture | reachable from the harness? | evidence |
|---|---|---|
| FR-98d `EXTRACT` | **yes** | `t1.t1_c2, EXTRACT(? FROM t1.t1_c10)` |
| FR-97 cursor name | **no** — qual only | harness returns `''` for the UPDATE; plain `EXPLAIN (VERBOSE)` shows `TID Cond: CURRENT OF zcur_secret` on the Tid Scan |
| FR-99 `nextval` shape | **no** — child node | harness returns `''`; the `NextValueExpr` is in the **Result** node's target list, one level below the ModifyTable |
| FR-98c opclass | **no** — by construction | planner reduces inference elements to index OIDs before EXPLAIN |
| `get_parameter()` argnames | **no** — by construction | only `print_function_sqlbody()` sets `argnames`, on a context with redaction off |

Landed in `src/test/modules/test_explain_redact`: six EXTRACT/normalization rows
plus a `LIKE`/`NOT LIKE` pair on a marker field string. Every fixture carries a
non-redacted sibling column in the same target list — T13's anti-vacuity
control, without which a green result cannot be told apart from output that was
blanked wholesale. Two of the six rows are the normalization negative control.

**Ships untested, carried into T21.** The cursor name (FR-97), the `nextval`
shape (FR-99/FR-61), the opclass guard (FR-98c) and the `get_parameter` guard.
Same treatment as T13's `get_tablefunc()` guard, and for the same reason: a
harness entry point added only so that a test can pass does not show the
production path works. T21 must verify FR-97 and FR-99 through
`EXPLAIN (REDACT)` once expression properties are un-suppressed — they are on
that task's list, not discharged here.

**Carried defect, not T14's.** The inference-element path does not honour FR-60:
`get_opclass_input_type()` and `get_opclass_name()` both `elog(ERROR)` on a
concurrently dropped operator class, at base as well as after this change. It is
only FR-60-clean today because the path is unreachable — which is precisely the
vacuity this work keeps hitting, in a fourth guise. Whoever makes the path
reachable owns it.

---

### Stage 4 — re-enable output, one surface per task

Each task replaces T04's blanking of one surface with the pseudonym. Reverting
any of them returns that surface to blanked.

#### T15 — Relation, schema and alias names

*(rev. T15: rewritten to match what was built. The section below listed four
emission sites and the tests for them; it did not mention the one thing the task
actually had to discover, which is that `es->redact_ctx` was never allocated
anywhere in the tree, so passing it to T07's redacted name selector would have
passed NULL and produced **no redaction** rather than an error. Line numbers are
as landed.)*

**Delivered.** Three edits and two new static helpers, all in
`src/backend/commands/explain.c` — 147 insertions, 44 deletions. This is the
first task in Stage 4, and therefore the first task in the plan where the
deletions matter: up to T13/T14 the changes were pure insertions and "off-mode
output is unchanged by construction" was an argument rather than a measurement.
Here the off-mode path was restructured — two locals retyped to `const char *`
and the `eref->aliasname` fallback rewritten — so it was measured instead (see
**Revert**).

1. **`explain_redact_context()`** (`:795`) — new. Lazily creates
   `es->redact_ctx` with `explain_redact_create(NIL)` on first use. Needed
   because nothing allocated it before: `explain_state.c` sets `es->redact` and
   stops, and the header's "built on first use" had no first use. The map
   deliberately outlives the individual plan trees of a record, since a
   pseudonym has to denote the same object across a main plan and any nested
   statements (FR-45), so it is not reset with the per-tree fields. The empty
   allowlist argument is where T22's `auto_explain.redact_allow_schemas` will
   arrive.

2. **`explain_redact_refname()`** (`:816`) — new. Stands in for the
   `rte->eref->aliasname` fallback, which is the user's real alias and so cannot
   be printed. Its keying mirrors `set_rtable_names()` exactly: an unaliased
   `RTE_RELATION` by **OID**, everything else by range-table index. Keying it
   any other way makes the reference name and the object name disagree about the
   same RTE.

3. **`ExplainPrintPlan()`** (`:866`) — `if (es->redact)` selects
   `select_rtable_names_for_explain_redacted()`, which T07 landed and which had
   **no caller in the backend** until now (only the test module). This one call
   decides two things and the second is easy to miss: the list is what
   `ExplainTargetRel()` and `Replaces` print as an alias, and it is also what
   `deparse_context_for_plan_tree()` on the next line builds the deparse context
   from. A real alias here would be harmless only for as long as expression
   output stays suppressed.

4. **`ExplainTargetRel()`** (`:4887`) — T04's blanket `return` replaced by
   per-kind handling. Relations get `tN` and no schema; **exempt** relations take
   the original path unchanged, real name plus `VERBOSE`-gated schema;
   `xmltable`/`json_table` are untouched because both names are SQL keywords
   (FR-27). Function, CTE and worktable names are left absent on purpose — they
   are T17's `fN`/`cteN`, and "finishing the job" here would mean printing the
   user's real names.

5. **`show_result_replacement_info()`** (`:5386`) — names restored,
   pseudonymized, from the same list (FR-92). The loop always ran under T04
   because its counts decide whether the line appears at all.

**Not done here, on purpose.**
`deparse_context_for_plan_tree_redacted()` (T08) is **still uncalled**. `:874`
passes the pseudonymized `rtable_names` into the *unredacted* context builder, so
relation reference names inside the deparse context are pseudonyms while column
names are assigned real. Harmless today — T04 suppresses every expression
property, measured across the whole §10.2 catalog — and **T21 owns wiring it**,
alongside the defensive assertion listed there. Recorded rather than fixed
because doing it here would land an untestable change.

**Findings.**

- `strcmp(refname, objectname)` alias suppression holds, and by pointer identity
  rather than by luck: `explain_redact_name()` caches `entry->name` per
  `(kind, oid)` and hands back the same buffer, so for an unaliased relation both
  sides are the same pointer. `Seq Scan on t1` stays a two-word tail. Asserted
  empirically, not argued, because keying the reference name differently would
  silently change the shape of every unaliased scan line.
- Two unaliased RTEs of the same relation **do** collide and take a `_1` suffix,
  giving `Seq Scan on t1 t1_1`. Cosmetic, and identical in shape to the
  unredacted plan, but it disproves the comment T07 left in `set_rtable_names()`
  — corrected in T07's section above.
- FR-15 has no reachable emission site. `ExplainNode()` omits
  `T_NamedTuplestoreScan` from the list that calls `ExplainScanTarget()`, so the
  `T_NamedTuplestoreScan` case in `ExplainTargetRel()` has no caller and a named
  tuplestore scan prints no name in any format, redacted or not. **T17's ENR
  deliverable is a guard, not a substitution**; its section still lists an ENR
  test and that test can only be a negative control. *(rev. T17: acted on. T17
  re-verified the finding, left the guard, kept `REDACT_ENR` unassigned, and its
  section now says so rather than listing an ENR substitution. The negative
  control was widened to pin the `Tuplestore Name` property tag in all four
  formats and both modes.)*

**Tests.** The negative test first, because Stage 4 inverts the failure
direction: from here a mistake makes output *less* redacted, and the leak sweep
cannot catch a name that came back early as a **pseudonym** — no marker, no leak,
no failure. So the function, CTE and worktable names are asserted **absent by
name**, with an anti-vacuity clause requiring the unredacted plan to print them,
and the tuplestore name is pinned as unreachable. Then: self-join shows the same
`tN` twice while two tables show different pseudonyms (FR-40); no `Schema` in any
of the four formats and no `schema.table` in text (FR-11); the FR-13a partition
fixture, both identifiers (`Seq Scan on t1 a1`); `Replaces` in all three of
T01's forms; `pg_class` keeping its real name and its real schema as the negative
control for the whole rule; and the `Alias` property, which json/xml/yaml emit
regardless of `VERBOSE` and which a text-only test would miss entirely.

This is also the task that gives the inverted sweep in
`src/test/regress/sql/explain_redact.sql` its first real signal. Eleven of its 33
previously-vacuous rows now assert something: the four FR-10 rows, FR-13, the
alias halves of the two FR-46 rows, both FR-92 rows, the parallel-plan row, and
FR-11 — which stays an assertion of omission but now distinguishes "schema
dropped from a named relation" from "nothing printed at all". Enumerated at the
vacuity note in that file. The remaining rows still need the task that owns
their surface; repairing the sweep so a suppressed property reports as suppressed
is no longer the whole answer it looked like at T13.

**Revert.** Reverting the whole task returns these three surfaces to blanked:
less informative, still safe, and still the rule §1.2 states.

What changes at T15 is the direction of a **mistake**, and that is the reason
this task's tests are shaped the way they are. Through T14, every error mode was
"suppressed something it should have kept", which the §10.4 negative controls and
the plan-shape assertions catch. From T15 the available error mode is
"printed something it should have withheld", and the leak sweep only catches the
subset of those where the printed thing is a *real* name. A name that comes back
early as a **pseudonym** carries no marker and every assertion in the file still
passes. Hence the by-name negative test for T17's three surfaces, and hence the
anti-vacuity clause on it.

The partial revert to be careful about is hunk 3 alone. Dropping the
`select_rtable_names_for_explain_redacted()` call while leaving Stage 3 in place
is safe *today*, because T04 still suppresses every expression, and becomes a
live leak the moment T21 lands: the same list feeds the deparse context. T21's
defensive assertion is what converts that from silent to loud.

#### T16 — Index names

*(rev. T16: rewritten to match what was built. The three lines it replaced named
the sites and the tests; they said nothing about the **direction** the guard
went, which is the one thing about this task a later reader will get wrong,
because it is the opposite of T14's. Line numbers are as landed.)*

**Delivered.** One signature change, two call sites and one retyped loop, all in
`src/backend/commands/explain.c` — 80 insertions, 25 deletions, most of them T04
comment and guard text rather than logic.

1. **`explain_get_index_name()`** (decl `:149`, def `:4546`) — gains an
   `ExplainState *` and the redaction guard, which returns
   `explain_redact_name(…, REDACT_INDEX, indexId)` as its first statement.
2. **`ExplainIndexScanDetails()`** (`:4877`) — T04's `es->redact ? NULL :` and its
   nine-line comment removed; feeds both `Index Scan` and `Index Only Scan`.
3. **Bitmap Index Scan** (`:1893`) — same removal, back to the upstream shape.
4. **Arbiter gather** (`:5237`) — T04 skipped the whole loop and left `idxNames`
   NIL. The loop runs in both modes now: `get_rel_name()` off-mode,
   `explain_redact_name()` redacted. The `if (idxNames)` print guard at `:5292`
   goes back to its upstream meaning (a bare `DO NOTHING` has no arbiters)
   instead of doubling as the suppression.

**THE GUARD WENT INWARD. T14'S WENT OUTWARD. Do not reconcile them.**

This is the part worth reading twice, because the two tasks look like the same
problem and are not. `get_opclass_name()` (T14) has a caller that must **never**
redact — `pg_get_indexdef`, which is a user-facing function, not EXPLAIN — so
its guard had to sit at its call sites: a guard inside it would redact
`pg_get_indexdef` output. `explain_get_index_name()` has no such caller. It is
`static`, it is EXPLAIN-only, and every caller wants the same answer, so the
guard belongs inside, where it covers the call sites that exist and the ones
someone adds later.

Two things follow that a call-site guard cannot give:

- **FR-25, the hook.** `explain_get_index_name_hook` is `PGDLLIMPORT` and an
  extension answering it returns any string it likes. Returning before the hook
  is consulted is only possible inside the function; a call-site check can
  decline to call it, but it cannot make the function safe for the next caller.
- **FR-60, the lookup failure.** The
  `elog(ERROR, "cache lookup failed for index %u")` sits after the hook, on the
  unredacted path only. The redacted path returns before it, so a concurrently
  dropped index cannot destroy the record — unreachable rather than handled,
  which is the stronger property.

Both functions now carry a comment saying which way their guard went and why, so
the asymmetry reads as deliberate.

**The arbiter site deliberately does not route through the function.** It gathers
with `get_rel_name()` in off mode, which is the upstream shape: the hook has
never applied there. Routing it through `explain_get_index_name()` would newly
expose unredacted arbiter names to an extension hook — a change to
**non-redacted** output, which is not this feature's to make. Under redaction it
calls the same `explain_redact_name(…, REDACT_INDEX, oid)` the function calls, so
an arbiter index and an index scan on that index print the same `iN`. That is the
property the site exists for and the one a careless change breaks, so it is
asserted rather than argued.

**Deviation from the brief, and the assertion that pays for it.** The brief
called for an explicit `explain_redact_exempt()` test, as T15 has in
`ExplainTargetRel()`. There is none. For an exempt index `explain_redact_name()`
already returns the real name — it tests exemption itself and caches the real
name the way it caches a pseudonym. T15 needed the explicit test because its
exempt path prints a **second** thing, the schema, which FR-11 keeps off a
pseudonym, so it was choosing between code paths rather than between strings.
There is no schema on an index name, and an explicit test here would add a
`get_rel_name()` call that can return NULL on the one path whose purpose is to
survive that. Same observable behaviour, strictly better FR-60 property. The
regression file asserts `Index Scan using pg_class_oid_index on pg_class` in all
four formats, which is what makes the reliance sound rather than assumed.

**Tests.** All four surfaces separately — `Index Scan`, `Index Only Scan`,
`Bitmap Index Scan`, `Conflict Arbiter Indexes` — because three different code
paths feed them and one fixture would leave two untested. Each carries its own
GUCs (the settings that force one plan shape rule out another, so they cannot
share a table-driven query) and its own anti-vacuity clause requiring the
unredacted plan to name a real index. `enable_indexonlyscan` has to be off as
well as the two GUCs the older FR-16 fixture set, or the plain `Index Scan`
surface is never reached — the same mistake T01 recorded for that fixture, one
level further in. Then FR-40 both halves, all four formats, the exempt negative
control, and the two negative controls on the same nodes: `Scan Direction`, which
comes out of the same two format branches as the index name, and `Index
Searches`, which sits on both node types.

Two things are **not** asserted, and the file says so rather than dressing them
up as passing fixtures:

- **FR-60 end-to-end.** Not constructible from a regression test: one backend,
  and the plancache invalidates the plan the moment the index is dropped, so
  nothing reaches the lookup with a dead OID. Held up instead by the structural
  argument above plus a module assertion that `explain_redact_name()` answers a
  nonexistent index OID with `i1` rather than erroring or returning NULL — the
  half that would falsify the structural argument if it were wrong.
- **`Rows Removed by Index Recheck`.** Emitted on the Bitmap **Heap** Scan node,
  neither T16 site, and needs a lossy `TIDBitmap`: 60000 rows at 200 bytes goes
  lossy, 20000 does not, and at the lossy size the index condition matched
  everything so nothing was rechecked away. An unstable expected file costs more
  than a counter no T16 path can suppress.

**Nothing was inverted, and that is a finding.** §1.1 says each Stage 4 task
inverts its by-name assertions rather than deleting them, and this task had none
to invert. The three existing FR-16 assertions all turn on a **real** index name
— found without `REDACT`, absent with it — and T16 changes neither, because the
pseudonym carries no marker. Inverting them would have been a regression. What
changed is that they stopped being vacuous, which converts the two §10.2 sweep
rows FR-16 owns. The one artefact that did state the opposite of the new
behaviour was a comment — "Scan direction survives an index scan even though the
index name does not" — corrected in place. One expected line changed in the whole
suite: `Index Only Scan Backward on t1` became
`Index Only Scan Backward using i1 on t1`.

**Revert.** Reverting returns the index name to blanked on all four surfaces:
less informative, still safe. The partial revert to be careful about is the
arbiter loop alone — restoring T04's `if (!es->redact)` around it while leaving
the rest is safe, but restoring the loop **without** its `explain_redact_name()`
branch prints real index names in redacted records, because the `if (idxNames)`
guard is no longer doing double duty.

**Not T16's, and left alone.** `get_opclass_name()`'s FR-60 defect, recorded in
T14's section, is untouched: the inference-element path still `elog(ERROR)`s on a
concurrently dropped operator class, at base as well as after T14, and is
FR-60-clean only because it is unreachable. T16 closing the index-name `elog`
does not generalise to it.

#### T17 — CTE, function-scan, sampling and custom-scan names

*(rev. T17: rewritten to match what was built. Two corrections the old text
needed. It listed the **custom-scan provider name** among the names this task
assigns, which reads as promising an `fN`; FR-28's disposition is
blanked/omitted, FR-28 is the requirement of record, and the name stays blank —
the deliverable is the confirmation, not a pseudonym. And its line references
(`:4688`, `:4700`, `:4693`, `:4653`, `:3052`) were pre-T15 and stale, T15 and
T16 having rewritten the surrounding code; line numbers below are as landed.)*

**Delivered.** One new helper and five guarded sites, all in
`src/backend/commands/explain.c` — 202 insertions, 60 deletions, a large share
of it comment text recording which of the five names is printed and which is
not.

1. **`explain_redact_by_name()`** (decl `:154`, def `:843`) — pseudonym for a
   name with no catalog object and no numeric identity, keyed on
   `hash_bytes(name)`. Needs `#include "common/hashfn.h"` (`:27`).
2. **CTE name** — `T_CteScan` (`:5177`) and `T_WorkTableScan` (`:5215`), both
   `explain_redact_by_name(REDACT_CTE, rte->ctename)`.
3. **Function-scan `Function Name`** (`:5123`) — two branches, not two strings:
   the exempt path also prints the schema under `VERBOSE`, the pseudonym path
   must not (FR-11). Same shape T15 used for the relation case.
4. **`show_tablesample()` method** (`:3387`) — `REDACT_FUNCTION` on
   `tsc->tsmhandler`, so built-in `system`/`bernoulli` keep their real names by
   exemption. Arguments and `REPEATABLE` seed stay suppressed (`:3393`, `:3428`,
   `:3451`).
5. **Named tuplestore** (`:5191`) and **custom-scan provider name** (`:1766`) —
   comment only. Both guards unchanged; see below.

**THE CTE KEY IS THE NAME STRING, NOT THE RANGE-TABLE INDEX.**

This is the one decision here with a consequence past this task, and T19
inherits it. FR-90 requires the `Subplan Name: CTE …` label to carry the same
pseudonym as the `CTE Name` beside it, and a `SubPlan` has only `plan_name` —
a string `choose_plan_name()` (planner.c) seeds verbatim from `cte->ctename` —
with no range-table index anywhere in reach. A string key is therefore the only
key all three printers can compute: `ExplainTargetRel()`/`T_CteScan`,
`ExplainTargetRel()`/`T_WorkTableScan`, and T19's `ExplainSubPlans()`. Keying on
`CteScan->ctePlanId` was considered and rejected: it is exact and would match
`SubPlan->plan_id`, but `WorkTableScan` has no plan id (only `wtParam`), so a
recursive CTE could not agree with itself. Same shape T14 used for the cursor
name.

Measured, and the closest rehearsal of FR-90 available before T19 exists: the
`CTE Scan` and the `WorkTable Scan` of one recursive CTE both print `cte1`,
because the self-reference RTE carries the same `ctename` string. One CTE
scanned twice keeps one pseudonym; two different CTEs get two.

**Two names T17 owned and did not print.**

- **ENR (FR-15) — unreachable, guard kept.** `ExplainNode()` omits
  `T_NamedTuplestoreScan` from the node list that calls `ExplainScanTarget()`,
  so `ExplainTargetRel()`'s `T_NamedTuplestoreScan` case has no caller and no
  `Tuplestore Name` is printed in any format, in either mode. T15 measured this
  from inside a trigger with a `REFERENCING NEW TABLE` transition table — the
  only way to get an ENR into a plan — and T17 re-verified it against the tree.
  `REDACT_ENR` stays declared and unassigned rather than spending a pseudonym
  namespace on a dead path, and the `es->redact` check ships as a guard on the
  same footing as FR-94 and FR-98c. The negative control was strengthened rather
  than added: the regression file now pins the property **tag**
  `Tuplestore Name` as absent in all four formats and both modes, which is the
  string that would appear if the missing case ever arrived.
- **Custom-scan provider name (FR-28) — blanked, confirmed.** `custom_name`
  stays NULL, which drops it from the node label and skips the
  `Custom Plan Provider` property, leaving the node reading `Custom Scan on t1`.
  The reasoning, so it is not reopened: the string is
  `CustomScan->methods->CustomName`, chosen by the extension author and not by
  the user, so a pseudonym would not be concealing a user identifier — it would
  be standing in for the identity of a loaded extension, which FR-25 keeps out
  of a redacted record altogether. Every other channel that extension has
  (`ExplainCustomScan`, the per-node hook) is already silent, so an `fN` here
  would be the one trace of an extension in a record that otherwise has none.

**Redaction must not become deletion, on this task's surfaces.** The sampling
method came back but its arguments and its `REPEATABLE` seed did not, and that
split is deliberate: both are deparsed expressions, both are T21's, and there is
nothing to print in their place today but the user's literal values. The seed in
particular looks harmless and is not — it is what makes a sample reproducible,
so printing it beside a row count tells a reader which rows were examined. Text
mode drops the parenthesised argument list along with them, so a redacted line
reads `Sampling: f1` rather than `Sampling: f1 ()`, which would describe a
sampling method that takes no arguments. None does.

**Tests.** CTE name in four formats; the recursive-CTE agreement above; FR-40 on
CTEs (one CTE scanned twice → one pseudonym, two CTEs → two); a user-defined SRF
in `FROM` → `f1`, with `generate_series` beside it as the exemption control and
the no-schema-on-a-pseudonym assertion in all four formats; built-in `SYSTEM`
and `BERNOULLI` keeping their real names; and the shape divergence below, pinned
rather than fixed.

Two fixtures cannot live in `src/test/regress` because they need an extension
loaded, and a core regression test runs against a plain install — giving it an
`EXTRA_INSTALL` pointed at contrib would invert the core/contrib dependency, in
two build systems. They are in `src/test/modules/test_explain_redact`, whose
Makefile gained
`EXTRA_INSTALL = contrib/tsm_system_rows src/test/modules/test_extensible`
(precedent: `contrib/auto_explain/Makefile` does this for `pg_overexplain`; the
meson build needs no counterpart, since it installs every module into the shared
`tmp_install`):

- a **user-installed sampling method**, `TABLESAMPLE system_rows (…)` →
  `Sampling: f1` asserted verbatim, with `Sampling Parameters`, `Repeatable
  Seed` and the argument value all absent, against an unredacted control that
  contains the method name and the argument. `system_rows` sets
  `repeatable_across_queries = false`, so the parser rejects `REPEATABLE` on it
  — the seed half of the suppression is measured on the built-in `BERNOULLI`
  fixture in the regress file instead, where the clause is legal.
- an **extension custom scan**, `test_extensible` → `Custom Scan on t1` in all
  four formats, with the provider name and the `Custom Plan Provider` property
  both absent and both present unredacted.

**Shape divergence, recorded rather than fixed.** An unaliased CTE or function
scan prints **two** tokens under redaction where plain mode prints one:
`CTE Scan on cte1 a1` against `CTE Scan on my_cte`. `ExplainTargetRel()` prints
the reference name only when it differs from the object name, and
`set_rtable_names()` keys every non-relation RTE as `REDACT_ALIAS` (T07), so a
CTE's reference name is `aN` while its object name is `cteN` and the two never
match. An unaliased **relation** does not diverge, because T15 arranged for both
of its names to come from the same `(kind, oid)` lookup. Making the CTE case
agree would mean changing the refname keying in ruleutils.c, which is T07's
surface and also feeds the deparse context T21 turns on — out of scope here.
Both tokens are pseudonyms and nothing is disclosed, so this is pinned in the
regression file as a decision rather than left to be reported as a bug later.

**Note on T15's by-name block, because the old text got this wrong.** It said
the three assertions T15 left behind — function, CTE and worktable names absent
from redacted output — were "expected to **fail** when this task lands, and must
be inverted". **None of them failed and none was inverted.** Each says a *real*
name is absent under `REDACT` and present without it, and both halves stay true:
a pseudonym carries no `zsec_` marker. This is the second brief in a row to
predict inversions here and the second to need none — T16's expected four and
needed none of them. The block keeps its title and its purpose: it is still the
only thing standing between a later task and printing a name *early* as a
pseudonym, which no marker-based sweep can see. What T17 actually changed there
was two verdict strings that named T17 as a future owner, and the three plan
dumps below them, which now carry the pseudonyms.

#### T18 — Trigger section

`report_triggers()` → `trgN`, `conN`, `tN`, all six sites: explain.c:1368, 1372,
1374 (text, direct `es->str` appends) and 1385, 1387, 1388 (structured).

**Structure: resolve all three names up front, then delete every redaction
special case.** T04 left four suppressions here — an `if (!es->redact)` around the
two catalog lookups, a redaction-specific `"Trigger"` print arm ahead of the
upstream verbose/conname test, an `if (!es->redact)` around the three
`ExplainPropertyText` calls, and a widened `if (show_relname && relname != NULL)`.
Resolving `tgname`, `conname` and `relname` before any printing lets all four go,
so the printing logic is upstream's byte for byte and the pseudonyms substitute
into it. That is not tidiness; see the shape hazard below.

**Hazard: `pfree`.** The string `explain_redact_name()` returns is owned by the
`RedactCtx` (the LIFETIME note in explain_redact.h), and the map returns the *same
buffer* for a repeated `(kind, oid)`. So `pfree(conname)` would free into the
pseudonym map, and a second trigger on the same constraint would then read freed
memory. Keep a separate `char *conname_alloc`, set only on the
`get_constraint_name()` path, and free that. `conname` becomes `const char *` so
the compiler holds the line.

**Hazard: shape.** Do **not** print `Trigger trgN` unconditionally. T01 measured
that a constraint trigger without `VERBOSE` prints only
`Trigger for constraint <conname>` — its own name is deliberately omitted — so an
unconditional arm would make the redacted record show *more* structure than the
plain one. Leaving `if (es->verbose || conname == NULL)` alone preserves it
exactly, and that is the reason for resolving up front rather than branching at
the print site.

**Exemption.** Neither a trigger nor a constraint can be reached except through a
user relation, so neither is ever exempt: `redact_object_namespace()` has no case
for `REDACT_TRIGGER` or `REDACT_CONSTRAINT` and both fall through to "not exempt".
Ask `explain_redact_name()` for a name, not for a decision. The relation is an
ordinary relation and that same call decides its exemption itself.

**Tests — the vehicle is the regression suite, not TAP.** *(rev. T18: this entry
used to read "Requires `log_analyze = on` **and** `log_triggers = on` — this
surface is unreachable otherwise (design §1.2)". The premise is wrong and is
corrected in §1.2: `ExplainPrintTriggers` has a second caller, in `ExplainOnePlan()`
at explain.c:645, gated on `es->analyze` **alone** — so
`EXPLAIN (ANALYZE, REDACT, COSTS OFF, TIMING OFF)` reaches the section with no GUC
at all. The regression file is the better vehicle because it can pin the emitted
line instead of scraping a log.)*

Use `TIMING OFF`: it takes the `: calls=N` arm, which is stable in an expected
file, whereas `TIMING ON` prints a machine-dependent float. `BUFFERS OFF` too —
ANALYZE enables buffers by default, and `zsec_plan()` strips a `Buffers:` line but
not the `I/O Timings:` line that hangs off it.

What the tests must cover, with the finding that makes each one necessary:

* **Both name paths at both verbosities** — two triggers, one plain and one
  constraint-backed, with distinguishable names, or the suite silently covers one
  of the two. Prefer a real `FOREIGN KEY` to `CREATE CONSTRAINT TRIGGER`: the
  latter gives the trigger and the constraint the same name, so `trgN` and `conN`
  cannot be told apart.
* **Shape preservation**, counted rather than eyeballed. The
  constraint-trigger-without-`VERBOSE` cell is the one that catches a regression.
* **FR-40 linkage** — and note that the obvious fixture cannot test it.
  `ExplainPrintTriggers()` sets
  `show_relname = (list_length(resultrels) > 1 || routerels != NIL || targrels != NIL)`,
  so a single-result-relation `INSERT` prints **no relation at all** on its trigger
  lines in text. A two-partition `UPDATE` is the clean case: two result relations,
  and both leaves appear in the plan as scan targets for the `tN` to agree with.
* **FR-38** — `Calls` must survive, and `Time` must survive when timing is on.
  Assert against raw output, not through `zsec_plan()`, which rewrites every digit
  to `N` and would make `calls=N` vacuous.
* **All four formats.** `Trigger Name`, `Constraint Name` and `Relation` are
  separate properties in json/xml/yaml and, unlike text, are printed
  *unconditionally* rather than gated on `VERBOSE`. Match XML as
  `Trigger[- ]Name`: an XML tag cannot contain a space, so it is `<Trigger-Name>`.
* **Tuple routing.** Under routing the trigger fires on the **leaf**, so `on tN`
  is the leaf's pseudonym and agrees with a scan line only if the leaf appears in
  the plan — which for an `INSERT` it does not. Plain output has the same shape, so
  nothing is disclosed; worth a fixture so it is not reported as a bug later.
* **A foreign key's internal trigger name must be filtered.** PostgreSQL names it
  from the constraint's OID (`RI_ConstraintTrigger_c_46760`), so the *unredacted*
  `VERBOSE` line cannot be pinned as it stands. `zsec_plan()` does not catch it: it
  rewrites a digit run only at a word boundary, and these digits follow an
  underscore.
* Keep the auto_explain TAP coverage — it is the channel the feature exists for,
  and `log_timing` is on by default there, so it is where the `time=` half of the
  section gets exercised at all. **`002_redact.pl` asserts
  `qr{Trigger: (?:time=[\d.]+ )?calls=\d+}`, which matched T04's nameless line and
  does not match T18's; it must be updated, not deleted.**
* Sweep bookkeeping: FR-17 is listed in explain_redact.sql as waiting on T18, but
  it had **no row in the fixture sweep to convert** — the file had classed it with
  FR-22/FR-23 as unreachable from plain `EXPLAIN`. T18 adds one, genuine in both
  directions from birth. Sweep 29 → 30 rows; inverted rows carrying real signal
  15/34 → 16/35.

#### T19 — Sub-plan labels and window names

*(rev. T19: rewritten to match what was built. The original text is preserved
only where it was right; five of its claims were not, and each correction is
named so a reader can tell a change of plan from a change of fact.)*

**Landed.** explain.c +136/−59, ruleutils.c +155/−7. Two EXPLAIN-side sites and
five deparse-side sites.

| # | Site | Prints | Key |
|---|---|---|---|
| 1 | explain.c `ExplainSubPlans()` (`:5820-5831`) | `CTE cteN` / `InitPlan spN` / `SubPlan spN` | `hash_bytes(plan_name)` for CTE, else `plan_id` |
| 2 | explain.c `show_window_def()` (`:3286-3297`) | `Window: wN` — **name only** | `winref` |
| 3 | ruleutils.c `get_parameter()` (`:9100-9119`) | `(hashed SubPlan spN).colN` | via `redact_subplan_name()` |
| 4 | ruleutils.c `get_rule_expr()` `T_SubPlan` (`:9998-10023`) | `EXISTS(SubPlan spN)`, `ARRAY(SubPlan spN)` | same |
| 5 | ruleutils.c `get_rule_expr()` `T_AlternativeSubPlan` (`:10048-10070`) | same strings; node never reaches a finished plan | same — guard only |
| 6 | ruleutils.c `get_windowfunc_expr_helper()` decompilation arm (`:11705-11721`) | `wN`; `pg_get_viewdef()` path, no redacting caller today | guard only |
| 7 | ruleutils.c `get_windowfunc_expr_helper()` EXPLAIN arm (`:11745-11765`) | `OVER wN` | `winref` |

**`winref` is an exact key; T17's `cteN` is a hash. Both are right, and the
difference is in what the printers share, not in taste.** `show_window_def()`
holds `wagg->winref`, and `get_windowfunc_expr_helper()` already matches
`wfunc->winref` against `wagg->winref` in order to *find* the name it prints — so
both sides hold the same integer and
`explain_redact_local(ctx, REDACT_WINDOW, winref, 0)` makes them one map entry,
with no collision risk and no agreement on a hash input to get wrong. A CTE has
no such luxury: three printers name it and one of them, the `Subplan Name` label,
holds only a string, so the string had to be the key. Each site carries a comment
saying this, because the two decisions sit one screen apart and read as an
oversight otherwise. Hash the window name only if some future printer of it turns
up holding the string alone.

**Non-CTE sub-plans are keyed on `plan_id`.** The index into
`PlannedStmt.subplans`, unique within the statement, and both printers hold the
`SubPlan` node — so this is the same exact-key argument as `winref`, in a second
namespace (`REDACT_SUBPLAN`, prefix `sp`). Only the CTE half hashes, and only
because it has to arrive at a map that is already string-keyed.

**`Window: wN` has no ` AS (`, and that was a decision.** `show_window_keys()`
and `get_window_frame_options_for_explain()` both call plain
`deparse_expression()`, so the `PARTITION BY`/`ORDER BY` keys and the frame
offsets are T21's surface; T19 re-enabled the name only, exactly as T17 did for
`Sampling:`. Printing `Window: w1 AS ()` to satisfy the requirement's stated
regex would have been worse than failing it — empty parentheses are a **valid**
window definition meaning no partition, no ordering and the default frame, so the
record would assert something false about the plan. The requirement was phased
instead; see requirements §10.2 FR-91.

**Five corrections to the pre-T19 text, and the first two would have caused bugs.**

1. **"after stripping the `CTE `/`InitPlan `/`SubPlan ` prefix" — WRONG, and
   stripping would have been the bug.** `plan_name` carries no prefix. It is
   seeded bare by `choose_plan_name()` — from `cte->ctename` at subselect.c:980,
   or from `sublinktype_to_string()` (`exists_1`, `any_2`, `expr_3`) at
   subselect.c:226 — and the prefix is built by the `psprintf()` calls in
   `ExplainSubPlans()` itself, which never write it back. So the string to hash is
   `sp->plan_name` verbatim, byte-identical to the `rte->ctename` T17 hashes.
   Hashing `"CTE " || plan_name` instead produces `Subplan Name: CTE cte2` over
   `CTE Name: cte1`; that was built on a scratch tree to confirm the fixture
   catches it, and all four format rows went red.

2. **The deparse side has THREE `plan_name` prints, not one.** The plan named
   only `get_parameter()`, and the design's FR-90 table listed only
   `get_parameter()` at `:8798`. `get_rule_expr()`'s `T_SubPlan` case (row 4
   above) also prints it and is EXPLAIN-reachable — a testexpr-less `SubPlan` in a
   target list, i.e. a correlated `EXISTS` or `ARRAY` subquery, arrives there and
   not at `get_parameter()`. Omitting it would have left a live leak for T21. The
   line numbers "~9984 and ~10015" in the T19 brief were attributed to
   `get_parameter()`; those are `get_rule_expr()`, and `get_parameter()`'s print
   was at `:9091-9099`. All three now route through one static helper,
   `redact_subplan_name()`.

3. **The CTE case is detected structurally, and already was.**
   `ExplainSubPlans()` branches on `sp->subLinkType == CTE_SUBLINK` — the same
   test the non-redacted arm uses — so no string matching was needed and none was
   added.

4. **Upstream already prints `wN`.** `name_active_windows()` (planner.c) invents
   `w1`, `w2`, … for *unnamed* window clauses "for the benefit of EXPLAIN". Two
   consequences: `wagg->winname` is never NULL on an EXPLAIN-reachable plan, so
   the existing unconditional `quote_identifier()` was safe and so is the
   pseudonym path; and a redacted `w1` and an unredacted `w1` **need not be the
   same window**. Cosmetic namespace overlap, independent counters, nothing
   disclosed — pinned as a fixture so nobody later reads agreement into it.

5. **`OVER wN` and `Window: wN` cannot be shown agreeing in one record, and the
   test task must not fake it.** `Output` is suppressed until T21, and would print
   the real name even then for the reason in T21's checklist below. Worse,
   comparing across two records is **unsound**: `explain_redact_local()` numbers
   pseudonyms in **first-use order**, and the two surfaces visit windows in
   different orders — measured, a two-window query whose target list mentions the
   bottom window first has the deparse side calling it `w1` while EXPLAIN, walking
   top down, calls the other one `w1`. Both cautions are pinned rather than
   asserted.

**The uniquifier limit, carried forward from T17 and not to be "fixed".**
`choose_plan_name()` renames a second CTE of the same name to `name_1`, which
hashes differently from the `ctename` the scan target still carries. Two CTEs
sharing a name in one statement therefore get a label and a scan target with
different `cteN`, and the record can show a `cteN` no scan target mentions.
Readability cost inside one record, no disclosure — and since it carries no
marker and no real name, the leak sweep is blind to it, which is why it is pinned
as a fixture. If it needs closing, the fix is on the planner-name side and is its
own task.

**Tests, as landed.**

* **FR-90 agreement, all four formats, and it is not vacuous.** `Subplan Name:
  "CTE cte1"` against `CTE Name: "cte1"`, with per-format extraction patterns —
  one format-agnostic pattern would compare text's single string with itself. The
  unredacted control shows the *same* real name in both places, which is what
  makes "the same pseudonym" the right demand. Failure demonstrated twice: the
  duplicate-name query above returns label set `{cte1,cte2}` against scan-target
  set `{cte1}` in-tree, and the perturbed build in correction 1 turned all four
  rows red.
* **Non-CTE labels.** One statement, one uncorrelated and one correlated
  sub-plan, `InitPlan sp1` and `SubPlan sp2`, asserted **distinct**. The
  unredacted control shows `expr_1` / `expr_2` — planner-made names that carry no
  marker, which is exactly why the sweep cannot see this surface.
* **FR-91.** `Window: w1` in all four formats, with five absence clauses: the
  ` AS (`, the partition key, the ordering key, the frame keywords, and both frame
  offsets **by value**. The offsets are values, not identifiers, so no marker
  convention reaches them. `count(*)` not `rank()`: `rank()` is frame-insensitive
  and the planner rewrites its frame to a default, so an unredacted `rank()`
  record does not contain the offsets and the absence clauses would assert
  nothing. Negative control is one boolean per absence clause.
* **Module coverage of the deparse sites** —
  `src/test/modules/test_explain_redact`, which is the **only** place any of them
  executes today (see T21's checklist). All four EXPLAIN-reachable strings
  measured: `(InitPlan sp1).col1`, `EXISTS(SubPlan sp1)`, `ARRAY(SubPlan sp1)`,
  `hashed SubPlan sp1`, `rank() OVER w1`. Two fixture facts that cost an
  experiment each and are recorded so they are not rediscovered: a
  **non-equality** correlation is required for `EXISTS(SubPlan …)`, because an
  equality correlation becomes a hashed ANY and lands back in `get_parameter()`;
  and the `hashed ` marker **is** module-reachable through that same rewrite,
  contrary to the working note that said it was not.
* **Not covered, and stated rather than skipped.** FR-40 for sub-plans — one
  sub-plan referenced twice keeping one pseudonym — could not be produced:
  PostgreSQL does not CSE scalar subqueries, so two occurrences are always two
  `plan_id`s even when the planner duplicates a subquery written once (measured:
  `expr_1` / `expr_2` unredacted). It rests on the key being an identity, argued
  from the code; it **is** measured for CTEs, in T17's "one CTE scanned twice"
  fixture.

**Sweep bookkeeping.** Two existing rows **promoted**, none added, none
relabelled away. Both `FR-90 Subplan Name carries CTE name` and `FR-91 window
name` reach their marker through a property T19 itself changed — `Subplan Name`,
which read `CTE` with nothing after it from T04 to T18, and `Window`, which T04
suppressed entirely — so the T17 precedent (add a row when the surface is
someone else's) did not apply. Sweep stays 30 rows; inverted rows carrying real
signal 16/35 → **18/35**. One correction to T17's arithmetic recorded in the
file: the FR-90 row stopped being *entirely* vacuous at T17, since its fixture is
a CTE and `CTE Name` was live from then, so by any-surface accounting the counts
would be 16/17/18 rather than 15/16/18. The file's convention throughout is
own-surface accounting; the two agree from here on.

**Revert.** Sub-plan labels return to a bare `CTE`/`InitPlan`/`SubPlan` and the
`Window` property disappears again. Strictly safer, less informative — §1.1.

#### T20 — Sort-key `COLLATE` / `USING` decorations

`show_sortorder_options()` — `get_collation_name()` at explain.c`:3267`,
`get_opname()` at `:3289`, redaction branches at `:3262` and `:3284`, decorations
printed at `:3271` and `:3293`. *(rev. T20: this section previously cited `:2866`
and `:2881`, which were stale before T20 changed anything.)* Both names are
assembled in explain.c **after** `deparse_expression()` has returned the key
string, so no Stage 3 change reaches them — which is the whole reason FR-98 lists
this site apart from the deparser ones. **This must land before T21**, or T21
enables `Sort Key` output carrying a real collation name.

**Delivered.** The `ExplainState` is threaded into the function (forward
declaration `:117-119`, sole call site `:3173-3178`) and both lookups become
`explain_redact_name(explain_redact_context(es), REDACT_COLLATION|REDACT_OPERATOR,
oid)` under `if (es->redact)`. 90 insertions, 15 deletions, explain.c only.

**Guard direction: inward, and this is now the third such decision in the
feature.** Someone will eventually try to make the three uniform, so the reasons
are recorded together rather than one per task:

| task | site | direction | why |
|---|---|---|---|
| T14 | `get_opclass_name()` (ruleutils) | **outward**, to the call site | non-EXPLAIN callers: `pg_get_indexdef_worker()` and the partition-bound printer emit DDL that must name real objects. A guard inside would corrupt `pg_get_indexdef()`. It also takes a bare `StringInfo` and no deparse context, so it *cannot* decide for itself. |
| T16 | `explain_get_index_name()` | **inward** | `static`, EXPLAIN-only, no caller that should stay unredacted. |
| T20 | `show_sortorder_options()` | **inward** | same three properties as T16: `static` in explain.c, EXPLAIN-only, exactly one caller (verified by grep tree-wide — the declaration, the definition, one call, one mention in a comment) and no caller that should stay unredacted, so a caller added later is covered by default. |

The rule the three share is not "inward" or "outward": it is **whether every
caller wants the same answer**. T14's did not; T16's and T20's do.

**Dormant as landed, and that is the surface, not an oversight.** The only
caller, `show_sort_group_keys()`, still returns early under redaction, so the
function is not entered and T20 changes no byte of output. It cannot be otherwise:
a decoration is appended to the deparsed key string, and there is no printing
`" COLLATE coll1"` without the expression it decorates — that expression is T21's
surface. Contrast T17 (tablesample method name, separable from its parameters) and
T19 (window name, separable from its body): those had a printable name with no
expression attached. This one does not. The blanket return **stays**, and the
caller's comment was rewritten to say so along with the real reason: the callee
*can* check now, what keeps the return is that the expression is still suppressed.
Do not lift it to demonstrate the guard — what comes out with it is real column
names.

**FR-60 fixed at both sites, structurally.** Each `elog(ERROR, "cache lookup
failed for …")` now sits on the `else` branch only; the redacted branch assigns
from `explain_redact_name()` — which neither errors nor returns NULL — and falls
through to the `appendStringInfo`. The failure is **unreachable** under redaction
rather than handled, the same move T16 made for the index lookup. Recorded against
FR-60 in the requirements as well, since that requirement has been accumulating a
list of paths that do and do not honour it and these two arrive with a status of
their own: clean by construction **and unexecuted**, unlike T16's (executes, unit
tested) and unlike FR-98c's (clean only because unreachable, and breaks the day it
is not).

**Preserved deliberately.** `DESC`, `NULLS FIRST`/`NULLS LAST` and the `reverse`
flag are plan structure and print identically in both modes. In particular
`get_equality_op_for_ordering_op()` (`:3300`) is called for its `reverse` **output
parameter**, not for a name, and so sits *outside* the redaction split, with a
comment saying why: skipping it under redaction would silently change the `NULLS`
decision, which is a correctness bug in the structure rather than a disclosure.

**Tests — T20 has none, and none were invented.** The guard has no verification
reach before T21, which is worth stating rather than papering over:

* Not through EXPLAIN — the caller returns before the call.
* Not through `src/test/modules/test_explain_redact` either — the function is
  `static` in explain.c, so unlike the ruleutils guards the module reaches
  directly, it cannot be called from outside.
* The only way to see it fire is the out-of-tree perturbation T19 used
  (temporarily drop the caller's return, run a user collation and a user ordering
  operator under redaction, observe `COLLATE coll1` / `USING op1`, restore). Not
  run in this slice and **not to be committed as a fixture.**

So FR-98(a) is verified by **T21's tests plus the existing off-mode coverage**, and
by nothing of its own.

**What the checks in this slice confirm** is the **non-redacted** path, which the
restructure did touch when both lookups moved into `else` branches. That coverage
was counted, not assumed: 46 sort-key decorations across five `expected/*.out`
files, of which **11 execute** in this build — `collate.out` (`COLLATE "C"` ×3,
`COLLATE "POSIX"`, one of them alongside `DESC` and `NULLS FIRST`),
`equivclass.out` (`USING <` ×3) and `incremental_sort.out` (`COLLATE "C"` ×4). Both
restructured branches are therefore exercised. `make -C src/test/regress check`:
**241/241, no expected file changed.** A changed sort-key expected file would be a
defect in the `else` branches, not something to regenerate.

The 35 remaining occurrences are real but unreachable here, and this is the gap to
know about: 31 are in `collate.icu.utf8.out`, which self-skips because this tree
has `with_icu = no`, and 4 are in `contrib/postgres_fdw/expected/postgres_fdw.out`,
which holds the **only** user-defined ordering operator in any expected output
(`USING <^`). Off-mode coverage is indifferent to whether a name is exempt — the
`else` branch calls `get_collation_name()` / `get_opname()` either way — so the
11 cover the restructure fully; but if a future task needs a *user* collation or
operator name in off-mode expected output, those two files are where it lives and
neither runs in a default `make check`.

**Exemption.** Not asserted separately: `explain_redact_name()` decides it and
returns the real name where it applies, so `COLLATE "C"` (T11) and `USING <` (T10)
stay readable. That matters more here than elsewhere — a pg_catalog collation and
a built-in operator are most of what makes a sort key diagnosable, and both
disclose nothing.

**Revert.** Nothing observable changes, since the guard is dormant: the decorations
are suppressed by T04's return either way. The FR-60 property at both sites is lost,
and T21 must not be applied on top of a reverted T20.

#### T21 — Re-enable expression output

**Goal.** The flip. `Filter`, `Output`, `Index Cond`, all key properties,
`Cache Key`, `Function Call`, `Table Function Call`, `Sampling Parameters`,
`Repeatable Seed` and `Conflict Filter` stop being suppressed and start being
emitted through `deparse_expression_redacted()`.

This is the highest-risk task in the plan and it is deliberately last. Its risk
was moved into T06–T20, all of which are already landed and unit-tested.

**Delivers — three required steps, not one.** *(rev. T20: step 3 added. Step 1 was added by T19. The pattern is worth naming: every task that lands a guard it cannot execute pushes a confirmation obligation onto T21, and T21 is the only place any of them can be discharged.)*

1. **`explain.c:918` must call `deparse_context_for_plan_tree_redacted()`.** *(rev. T20: `:917` was off by one; the call is at `:918`, re-verified against the current tree.)*
   *(rev. T19: this step was missing from this section and it is not a detail.)*
   `ExplainPrintPlan()` calls the **non-redacted**
   `deparse_context_for_plan_tree()` today, unconditionally, in both modes. T06
   added the `_redacted()` variant and nothing in the backend calls it: its only
   callers are its own NULL-passing wrapper and
   `src/test/modules/test_explain_redact`. So `context->redact` is NULL on every
   EXPLAIN path, and **every layer-B guard landed by T09–T14 and T19 is unreached
   there** — not merely unprinted. If T21 does only what the sentence below used
   to say, expression output comes back with no `RedactCtx` in the context and
   every one of those guards falls through to the real name. That is precisely
   the leak the whole of Stage 3 exists to prevent, and it would ship looking
   like a working feature: the properties would be populated, plausible, and
   unredacted. Two further consequences, both already true: the test module is
   the only place any layer-B guard executes today, so its coverage carries more
   weight than a unit test normally would; and no amount of T09–T20 testing
   through `EXPLAIN` can detect this, because the code under test is not reached.

2. **Replace the T04 suppression of the `show_*` calls** with calls that pass the
   `RedactCtx`.

3. **Confirm T20's sort-key guard starts producing output.** *(rev. T20.)*
   `show_sortorder_options()` (explain.c`:3240`) pseudonymizes the `COLLATE`
   collation and the `USING` operator itself, and as landed it is **never entered
   under redaction**: `show_sort_group_keys()` returns early, because a decoration
   is appended to the deparsed key string and the string cannot be printed without
   the expression. Lifting that return is step 2's job, and the instant it is
   lifted T20's guard goes from unexecuted to load-bearing on the same line of
   output as the key expression. Until then **T20 has no verification reach at
   all** — not through EXPLAIN, and not through
   `src/test/modules/test_explain_redact` either, because the function is `static`
   in explain.c and out of the module's reach.

   So T21's tests **must** include, in a sort key: a **user-defined collation**
   and a **user-defined ordering operator**. Assert `coll`*N* and `op`*N* in
   `Sort Key`, with `COLLATE "C"` and `USING <` as the exempt negative controls
   (T11 and T10). Without both, T20 ships permanently unverified — and unlike the
   FR-94 / FR-98c / FR-15 guards, T20 is **not** an unreachable-path guard that
   can be left argued; it is a reachable path that this task makes reachable.
   Note that neither name exists in the tree's off-mode expected output in a form
   this build runs: the only user-defined ordering operator is `USING <^` in
   `contrib/postgres_fdw`, and the user collations are in `collate.icu.utf8.out`,
   which self-skips under `with_icu = no`. T21 creates its own.

   Same shape as step 1, and the same failure mode: nothing errors, nothing looks
   wrong, the property is simply populated with a real name.

Plus a **defensive assertion**: if `es->redact` is set and the deparse context
carries no `RedactCtx`, error rather than emit. That converts an out-of-order
revert of T06–T20 (§1.2) from a silent leak into a loud failure — **and, as of
the finding above, it is also the check that would have caught step 1.** Write it
so that it fires on exactly that state: `es->redact` true and the context's
`redact` pointer NULL. Verify it by temporarily reverting step 1 and confirming
the assertion fires rather than output appearing.

**Tests.** The whole §10.2 catalog re-run with expressions enabled — this is
the first point at which most of it is meaningful. Including step 3's user
collation and user ordering operator in a sort key, which is not optional. Plus §10.3's full mode
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
T07 before T08, so they can be parallelised across people. T13's edges are
unchanged by its rescope, and it is now the most loosely coupled of them: the
collapse reads nothing but the `context->redact != NULL` test that T06 puts in
place — no pseudonym counter, no key domain, no agreement with any other task's
naming — so it can land anywhere after T06. Stage 4 tasks
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
