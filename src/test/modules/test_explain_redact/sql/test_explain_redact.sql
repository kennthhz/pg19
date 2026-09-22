--
-- Unit tests for the EXPLAIN redaction pseudonym engine (task T02).
--
-- The engine is tested directly, not through EXPLAIN, because nothing consumes
-- it yet.  That is deliberate: these properties are far easier to pin down here
-- than to infer later from plan text, and getting them wrong would be invisible
-- in any single redacted record.
--
CREATE EXTENSION test_explain_redact;

CREATE SCHEMA zsec_t02;
CREATE TABLE zsec_t02.zsec_a (zsec_c1 int, zsec_c2 text);
CREATE TABLE zsec_t02.zsec_b (zsec_c1 int);

--
-- FR-41: pseudonyms are lower-case ASCII plus digits, so they never need
-- quoting and can never collide with a quoted identifier.
--
-- Synthetic OIDs are taken from a range far above anything a catalog contains.
-- A first draft used 100, 200, 300 and hit real pg_catalog entries -- OID 200 is
-- float4in -- so the engine correctly returned the real name and the numbering
-- assertions were testing exemption by accident.  Keep these OIDs nonexistent so
-- that only numbering is under test here; exemption gets its own section below.
SELECT bool_and(p ~ '^[a-z]+[0-9]+$') AS oid_kinds_wellformed
  FROM unnest(test_redact_oid_seq(
        ARRAY['relation','index','function','operator','type',
              'collation','opclass','trigger','constraint'],
        ARRAY[900000001,900000001,900000001,900000001,900000001,
              900000001,900000001,900000001,900000001]::oid[])) AS p;

-- The locally-keyed kinds too.  The first draft checked only the nine OID kinds,
-- which left eleven of the twenty unverified -- including the column form, whose
-- qualified shape does NOT match the bare pattern and needs its own rule.
SELECT bool_and(p ~ '^[a-z]+[0-9]+$') AS local_kinds_wellformed
  FROM unnest(test_redact_local_seq(
        ARRAY['alias','cte','enr','subplan','window','field','argname',
              'xmlname','pathname','cursor'],
        ARRAY[1,1,1,1,1,1,1,1,1,1],
        ARRAY[0,0,0,0,0,0,0,0,0,0])) AS p;

-- Columns are qualified, so FR-41's bare pattern does not apply to them; the
-- rule is <pseudonym>_c<n>, which still needs no quoting.  Stated explicitly so
-- the exception is deliberate rather than an untested gap.
SELECT bool_and(p ~ '^[a-z]+[0-9]+_c[0-9]+$') AS column_form_wellformed
  FROM unnest(test_redact_local_seq(ARRAY['column','column'],
                                    ARRAY[1,2], ARRAY[1,1])) AS p;

--
-- FR-40: within one record, the same object always gets the same pseudonym and
-- different objects always get different ones.  Asked here with a repeated OID
-- in the middle of the sequence, so a cache miss would be visible.
--
SELECT test_redact_oid_seq(
        ARRAY['relation','relation','relation','relation'],
        ARRAY[900000001,900000002,900000001,900000003]::oid[])
    AS same_object_same_name;

--
-- Each kind counts independently, so the first relation is t1 whether or not a
-- function was named first.  This keeps numbering dense and readable and stops
-- an unrelated object from shifting a relation's number.
--
SELECT test_redact_oid_seq(
        ARRAY['relation','function','relation','function','index'],
        ARRAY[900000001,900000001,900000002,900000002,900000001]::oid[])
    AS per_kind_counters;

--
-- FR-42: numbering follows request order and nothing else.  Two different
-- objects requested in the opposite order must swap names -- if they did not,
-- numbering would be keyed on something other than traversal order (an OID sort,
-- a pointer, a hash-scan order) and the same plan could produce different
-- records on different backends.
--
-- Requested in DESCENDING OID order.  The expected answer is {t1,t2,t1,t2}:
-- the larger OID, asked first, gets t1.  Had numbering been keyed on the OID
-- value rather than on request order -- an easy accident if a sorted scan or a
-- hash iteration ever crept in -- the smaller OID would have taken t1 and this
-- would read {t2,t1,t2,t1}.
SELECT test_redact_oid_seq(
        ARRAY['relation','relation','relation','relation'],
        ARRAY[900000009,900000004,900000009,900000004]::oid[])
    AS larger_oid_asked_first_gets_t1;

--
-- FR-45: counters restart for every record.  A file-scope counter would make
-- numbering continue across records, which would let a log reader order and join
-- pseudonyms between unrelated statements, and would grow without bound.  It is
-- the most likely way to break FR-45 and is invisible within any one record, so
-- it gets its own assertion.
--
SELECT test_redact_counters_restart('zsec_t02.zsec_a'::regclass)
    AS counters_restart_per_context;

--
-- FR-46: the locally-keyed kinds.  These have no catalog object, which is the
-- whole reason they need a second entry point.
--
SELECT test_redact_local_seq(
        ARRAY['alias','cte','enr','subplan','window','field','argname',
              'xmlname','pathname','cursor'],
        ARRAY[1,1,1,1,1,1,1,1,1,1],
        ARRAY[0,0,0,0,0,0,0,0,0,0]) AS local_kinds;

--
-- Columns are qualified by their relation's pseudonym, so a reader can see which
-- relation a column belongs to without learning which relation it is.  Note the
-- numeric part is a per-relation counter: both relations start at c1.
--
-- The prefix reads "a1_" here because at this stage nothing has associated a
-- range-table index with a relation -- that linkage arrives with the
-- name-assignment layer in T07/T08, after which a plain relation's columns read
-- "t1_c1" and a subquery's read "a1_c1".  The prefix is deliberately whatever
-- pseudonym the owning range-table entry received, rather than a fixed letter.
--
SELECT test_redact_local_seq(
        ARRAY['column','column','column','column'],
        ARRAY[1,1,2,2],
        ARRAY[3,7,3,9]) AS columns_qualified_per_relation;

--
-- FR-12 and FR-43: the column number must NOT be the attribute number, which
-- would leak the column's ordinal position and therefore the table's shape.
-- Asking for attno 9 first must yield c1, not c9.
--
SELECT test_redact_local_seq(ARRAY['column'], ARRAY[1], ARRAY[9])
    AS attno_9_is_not_c9;

--
-- Same column asked twice is stable; different columns of the same relation are
-- distinct (FR-40 for the local map).
--
SELECT test_redact_local_seq(
        ARRAY['column','column','column'],
        ARRAY[1,1,1],
        ARRAY[4,4,5]) AS column_stability;

--
-- D7 / FR-50: exemption is decided by NAMESPACE, not by an OID range.
--
-- A pg_catalog object prints in full...
SELECT test_redact_exempt('relation', 'pg_class'::regclass) AS pg_catalog_exempt;
SELECT test_redact_exempt('function', 'pg_catalog.upper(text)'::regprocedure)
    AS pg_catalog_function_exempt;

-- ...while a user-schema object is redacted, and this is the case the old
-- OID-range heuristic got wrong: provisioning an application schema during
-- initdb yields low-OID objects that an OID test would print in full.
SELECT test_redact_exempt('relation', 'zsec_t02.zsec_a'::regclass)
    AS user_schema_redacted;

-- The allowlist (FR-51) exempts additional schemas by name.
SELECT test_redact_exempt('relation', 'zsec_t02.zsec_a'::regclass, 'zsec_t02')
    AS allowlisted_schema_exempt;

-- An allowlist naming some other schema must not exempt this object.
SELECT test_redact_exempt('relation', 'zsec_t02.zsec_a'::regclass, 'other_ns')
    AS unrelated_allowlist_ignored;

--
-- FR-60, fail closed.  A nonexistent OID cannot be classified, so it must be
-- redacted rather than erroring -- losing an entire record because an object was
-- concurrently dropped would be worse than redacting it.
--
SELECT test_redact_exempt('relation', 999999999::oid) AS missing_oid_redacted;
SELECT test_redact_exempt('function', 999999999::oid) AS missing_func_redacted;
SELECT test_redact_exempt('type', 999999999::oid) AS missing_type_redacted;

-- Triggers and constraints are always redacted: they are reached only through a
-- user relation, so there is no exempt case to recognise.
SELECT test_redact_exempt('trigger', 1::oid) AS trigger_always_redacted;
SELECT test_redact_exempt('constraint', 1::oid) AS constraint_always_redacted;

--
-- The tripwire.
--
-- It is compiled out without assertions, so a naive test would emit 'ok' in both
-- builds while only actually checking anything in one of them -- passing
-- vacuously wherever it matters least.  Instead the verdict compares what
-- happened against what THIS build should do, so the expected output is
-- identical everywhere and the assertion is real in both cases.
--
-- A cassert build is still required to exercise the trip itself, and CI must
-- include one; without it the tripwire ships unverified even though this test
-- reports success.
--
CREATE FUNCTION zsec_t02_verdict(str text, should_trip boolean)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    tripped boolean := false;
BEGIN
    BEGIN
        PERFORM test_redact_tripwire(str);
    EXCEPTION WHEN others THEN
        -- Identify the error rather than accepting any failure as a trip.  An
        -- unrelated elog, an OOM, or a future signature change would otherwise
        -- read as a successful catch, and on a cassert build should_trip is
        -- true, so the test would go green either way.
        IF SQLERRM NOT LIKE 'redaction leak at %' THEN
            RETURN 'FAIL: unexpected error: ' || SQLERRM;
        END IF;
        tripped := true;
    END;

    IF tripped = should_trip THEN
        RETURN 'as expected';
    ELSIF should_trip THEN
        RETURN 'FAIL: marker reached output uncaught';
    ELSE
        RETURN 'FAIL: tripwire fired on a clean string';
    END IF;
END $$;

-- A clean string must never trip, in any build.
SELECT zsec_t02_verdict('Seq Scan on t1  (cost=0.00..1.00 rows=1 width=4)', false)
    AS clean_string;

-- A marked identifier must trip iff the tripwire is compiled in.
SELECT zsec_t02_verdict('Seq Scan on zsec_customers',
                        test_redact_tripwire_enabled()) AS identifier_marker;

-- So must a marked value: the tripwire covers both leak classes, because an
-- identifier-only check would be blind to leaked data.
SELECT zsec_t02_verdict('Filter: (c1 = ''zsecdata-ssn-0001''::text)',
                        test_redact_tripwire_enabled()) AS value_marker;

DROP FUNCTION zsec_t02_verdict(text, boolean);

--
-- Regression coverage for two defects found by review, both of which were
-- reachable from SQL and neither of which any test touched.
--

-- explain_redact_destroy() used to hand the caller's own memory context to
-- hash_destroy(), which deletes that context outright -- freeing the RedactCtx
-- itself, so the next call read freed memory.  An exported entry point with no
-- coverage is how that survived; this exercises it.
SELECT test_redact_destroy_roundtrip() AS destroy_is_safe;

-- STRICT rejects a null array, not a null element.  These used to crash the
-- backend; they must now raise a clean error.
SELECT test_redact_oid_seq(ARRAY['relation', NULL], ARRAY[1, 2]::oid[]);
SELECT test_redact_local_seq(ARRAY['alias', NULL], ARRAY[1, 1], ARRAY[0, 0]);

--
-- T03: the ExplainState fields that will carry redaction.  Nothing consumes
-- them yet, so what is pinned here is the default: a state that has not opted
-- in redacts nothing and holds no pseudonym map.
--
SELECT test_explain_state_redact_defaults() AS fresh_state;
--
-- T07: relation aliases assigned by set_rtable_names().
--
-- Nothing in EXPLAIN output changes yet, so the assignment is observed by asking
-- for it directly.  The range table is built in C and covers all four branches
-- plus the RTE kinds that have no relid, which is the reason the alias key cannot
-- be an OID.
--
-- Order of entries: relation without alias, relation with a user alias, unnamed
-- join, subquery, function scan, VALUES.
CREATE TABLE zsec_t02.zsec_rt (c int);

-- Unredacted, for contrast: real names, and NULL for the unnamed join.
SELECT test_redact_rtable_names('zsec_t02.zsec_rt'::regclass, false, false)
         AS plain_names;

-- Redacted.  The unaliased relation is keyed by OID and so must read "t1", which
-- is what keeps it equal to the object name ExplainTargetRel will print -- had it
-- been keyed by range-table index, "Seq Scan on customers" would have become
-- "Seq Scan on t1 a1", a change of shape rather than of content.
--
-- Everything else is keyed by range-table index and so reads "aN".  The unnamed
-- join stays NULL: it prints nothing either way and has nothing to disclose.
SELECT test_redact_rtable_names('zsec_t02.zsec_rt'::regclass, true, false)
         AS redacted_names;

--
-- FR-47: the uniquifier must become a no-op.
--
-- Two entries whose chosen names are identical.  Unredacted, set_rtable_names()
-- appends "_1" to the second.  Redacted, both must come back as distinct
-- pseudonyms with no suffix -- a name like "a1_1" would mean the substitution
-- happened after the tie-breaking rather than before it, and would carry a
-- fragment of a real name's disambiguation into a redacted record.
SELECT test_redact_rtable_names('zsec_t02.zsec_rt'::regclass, false, true)
         AS plain_collision;
SELECT test_redact_rtable_names('zsec_t02.zsec_rt'::regclass, true, true)
         AS redacted_collision;

--
-- T08: column names assigned by set_relation_column_names().
--
-- Each RTE kind is a separate case, deliberately.  Combined into one query, a
-- single working path would mask a broken one -- which is the failure T01 found
-- in six of its own fixtures.
--
-- The left column is what EXPLAIN prints as "Output:" today; the right is what it
-- prints under redaction.  Both come from the same three calls explain.c makes,
-- so agreement between the name that gets assigned and the name that gets read
-- back is part of what is being checked.
CREATE TABLE zsec_t02.zsec_c (c_first int, c_second text, c_third numeric);
INSERT INTO zsec_t02.zsec_c VALUES (1, 'x', 2);
SET search_path = zsec_t02, public;

SELECT what,
       test_redact_deparse(qry, false) AS plain,
       test_redact_deparse(qry, true)  AS redacted
  FROM (VALUES
    ('plain relation',
     'SELECT c_first, c_second FROM zsec_c'),
    -- FR-46: every kind below has no relid and no catalog attribute number, so
    -- a (relid, attno) key could not name its columns at all.
    ('subquery output name',
     'SELECT s.o FROM (SELECT c_second AS o FROM zsec_c OFFSET 0) s'),
    -- Two rows, not one.  A single-row VALUES is folded to constants, no Var
    -- survives, and the case then passes having named no column at all --
    -- wrapping it in OFFSET 0 does not help, because the planner propagates the
    -- constants up through the subquery's target list anyway.
    ('VALUES column aliases',
     'SELECT v.v1, v.v2 FROM (VALUES (1,2),(3,4)) AS v(v1, v2)'),
    ('function scan alias',
     'SELECT g.g1 FROM generate_series(1,3) AS g(g1)'),
    ('ROWS FROM coldeflist',
     'SELECT r.* FROM ROWS FROM (json_to_record(''{"a":1}'') AS (a int)) AS r'),
    ('join output names',
     'SELECT a.c_first, b.c_second FROM zsec_c a JOIN zsec_c b USING (c_first)'),
    ('CTE column aliases',
     'WITH w(w1) AS MATERIALIZED (SELECT c_second FROM zsec_c) SELECT w.w1 FROM w')
  ) AS t(what, qry)
 ORDER BY what COLLATE "C";

--
-- Column numbering, and a known shortfall against FR-12.
--
-- FR-12 asks for an opaque counter that is never the attribute number: a table
-- whose sensitive column sits ninth should not surface "_c9" unless that column
-- is the ninth one the plan touched.  That is NOT what happens, and the result
-- below records it rather than hiding it.
--
-- The cause is structural.  set_relation_column_names() has to fill a name in for
-- every column of the RTE, because get_variable() reads the array by attribute
-- number, and it runs while the deparse context is being built -- before anything
-- knows which columns the plan will reference.  Numbering in assignment order
-- therefore yields the column's position, which for a relation with no dropped
-- columns is its attnum.
--
-- So a reader of a redacted record can infer that the column printed as "t1_c3"
-- is the third column of its table.  That is schema shape rather than data, and it
-- is a real disclosure that FR-12 meant to prevent.  Satisfying it needs either
-- lazy assignment, so a name is issued on first read rather than up front, or an
-- amendment to FR-12; see the requirements.
SELECT test_redact_deparse('SELECT c_third FROM zsec_c', true)
         AS number_is_the_position_not_a_use_counter;

-- And the counter is per RTE, so a self-join numbers each side from 1 rather than
-- continuing across the plan.
SELECT test_redact_deparse(
         'SELECT a.c_second, b.c_third FROM zsec_c a, zsec_c b WHERE a.c_first = b.c_first',
         true) AS per_rte_counters;

--
-- FR-47 for columns, the analogue of the relation-alias case above.  A subquery
-- may legally name two output columns the same; unredacted, make_colname_unique()
-- appends a suffix to the second.  Redacted, the pseudonyms are distinct by
-- construction and no suffix may appear -- "a1_c1_1" would mean the substitution
-- ran after the tie-breaking instead of before it.
SELECT test_redact_deparse(
         'SELECT x.a, x.b FROM (SELECT 1 AS a, 2 AS a, 3 AS b FROM zsec_c OFFSET 0) x(a, a2, b)',
         false) AS plain_duplicate_colnames;
SELECT test_redact_deparse(
         'SELECT x.a, x.b FROM (SELECT 1 AS a, 2 AS a, 3 AS b FROM zsec_c OFFSET 0) x(a, a2, b)',
         true) AS redacted_duplicate_colnames;

--
-- A USING join in a plan must be redacted.  set_using_names() pushes the real
-- USING column name into both child RTEs, where the substitution would be
-- skipped -- but that function belongs to query deparsing, and the plan path
-- skips join RTEs entirely.  Asserted rather than left to that argument.
SELECT test_redact_deparse(
         'SELECT a.c_second, b.c_third FROM zsec_c a JOIN zsec_c b USING (c_first)',
         true) AS using_join_redacted;

--
-- System columns are exempt and must still print: they are PostgreSQL's names,
-- not the application's, and a reader needs them to make sense of a plan.
SELECT test_redact_deparse('SELECT ctid, xmin FROM zsec_c', true)
         AS system_columns_still_print;

--
-- A whole-row Var prints the relation pseudonym with ".*", so the reference stays
-- legible without naming anything.
SELECT test_redact_deparse('SELECT zsec_c FROM zsec_c', true)
         AS whole_row_var;

--
-- FR-13b: RETURNING WITH (OLD AS ..., NEW AS ...) aliases are the user's own
-- words.  They are keyed outside the range-table index space, so they cannot
-- collide with a relation's alias, and the two get different pseudonyms -- a
-- reader must still be able to tell the row's before-image from its after-image.
SELECT test_redact_deparse(
         'UPDATE zsec_c SET c_third = 0 RETURNING WITH (OLD AS o, NEW AS n) o.c_third, n.c_third',
         false) AS plain_returning;
SELECT test_redact_deparse(
         'UPDATE zsec_c SET c_third = 0 RETURNING WITH (OLD AS o, NEW AS n) o.c_third, n.c_third',
         true) AS redacted_returning;

--
-- T09: constants become a placeholder plus the type label.
--
CREATE TYPE zsec_t02.zsec_kind AS ENUM ('cash', 'card');
CREATE COLLATION zsec_t02.zsec_coll (locale = 'C');
ALTER TABLE zsec_t02.zsec_c ADD COLUMN c_bool bool;
ALTER TABLE zsec_t02.zsec_c ADD COLUMN c_kind zsec_t02.zsec_kind;

SELECT what,
       test_redact_deparse(qry, false) AS plain,
       test_redact_deparse(qry, true)  AS redacted
  FROM (VALUES
    ('int',            'SELECT c_first + 5 FROM zsec_c'),
    -- The pair that matters most.  Unredacted, a negative int4 prints as
    -- '-5'::integer while a positive one prints as 5, so the cast itself tells a
    -- reader the sign.  Both must redact to the same thing, or replacing the
    -- value would have been pointless.
    ('int negative',   'SELECT c_first + (-5) FROM zsec_c'),
    ('numeric float',  'SELECT c_third + 2.5 FROM zsec_c'),
    -- Same idea for numeric: a float-looking literal needs no cast, an integral
    -- one does.
    ('numeric integral', 'SELECT c_third + 7 FROM zsec_c'),
    ('text',           'SELECT c_second || ''secret'' FROM zsec_c'),
    -- FR-21 and D6: no value class is exempt.  A NULL in a plan asserts that the
    -- query tested real rows for absence, and true/false are data as much as any
    -- other literal.  All three must be indistinguishable from each other and
    -- from an ordinary value of the same type.
    ('NULL',           'SELECT c_first + NULL::int FROM zsec_c'),
    ('bool literals',  'SELECT true, false FROM zsec_c'),
    ('user enum',      'SELECT c_kind = ''cash''::zsec_t02.zsec_kind FROM zsec_c'),
    ('collated const', 'SELECT c_second < (''x'' COLLATE zsec_t02.zsec_coll) FROM zsec_c'),
    -- The whole array constant is replaced, not its elements.
    ('array / ANY',    'SELECT c_first = ANY (ARRAY[1,2,3]) FROM zsec_c')
  ) AS t(what, qry)
 ORDER BY what COLLATE "C";

--
-- showtype = -1: the caller prints the type itself, so no cast may be inserted
-- here -- one would land in the middle of the caller's syntax.  JSON_QUERY shows
-- both modes at once: its context item is a labelled constant, its path spec is
-- not.
SELECT test_redact_deparse(
         'SELECT JSON_QUERY(''{"a":1}''::jsonb, ''$.a'') FROM zsec_c', false)
         AS plain_json_query;
SELECT test_redact_deparse(
         'SELECT JSON_QUERY(''{"a":1}''::jsonb, ''$.a'') FROM zsec_c', true)
         AS redacted_json_query;

-- Not covered here, and deliberately: the remaining showtype = -1 callers are
-- get_values_def(), which prints a VALUES list's rows, and
-- get_range_partbound_string(), which prints a partition bound.  Neither is
-- reachable from a plan -- EXPLAIN prints no VALUES rows and no partition bounds
-- -- and the second zeroes its own deparse context, so it never carries the
-- handle.  Both are noted in ruleutils.c at the point where it would matter.

--
-- T10: relation, function and operator names inside expressions.
--
-- The exemption rule is the substance of this task, and it is the first one where
-- erring on the safe side still breaks the feature.  A Filter reading
-- "(t1_c1 op1 ?::integer)" where op1 is "=" tells a reader nothing, so built-in
-- functions and operators must keep their names.  They also disclose nothing: they
-- are PostgreSQL's names, and any reader could look them up.
CREATE FUNCTION zsec_t02.zsec_fn(int) RETURNS int
  LANGUAGE plpgsql AS $$ BEGIN RETURN $1; END $$;
CREATE FUNCTION zsec_t02.zsec_opfn(int, int) RETURNS bool
  LANGUAGE plpgsql AS $$ BEGIN RETURN true; END $$;
CREATE OPERATOR zsec_t02.### (LEFTARG = int, RIGHTARG = int,
                              FUNCTION = zsec_t02.zsec_opfn);

SELECT what,
       test_redact_deparse(qry, false) AS plain,
       test_redact_deparse(qry, true)  AS redacted
  FROM (VALUES
    ('builtin function',  'SELECT lower(c_second) FROM zsec_c'),
    ('user function',     'SELECT zsec_t02.zsec_fn(c_first) FROM zsec_c'),
    -- The case the plan asks for by name: both in one expression, so the test
    -- cannot pass by treating every function the same way.
    ('both in one expr',  'SELECT lower(c_second), zsec_t02.zsec_fn(c_first) FROM zsec_c'),
    ('builtin operator',  'SELECT c_first = 1 FROM zsec_c'),
    ('user operator',     'SELECT c_first OPERATOR(zsec_t02.###) 1 FROM zsec_c'),
    -- FR-40: the same object reached twice yields the same pseudonym, which is
    -- what lets a reader see that two nodes touch the same function.
    ('same function twice',
     'SELECT zsec_t02.zsec_fn(c_first), zsec_t02.zsec_fn(c_first + 1) FROM zsec_c')
  ) AS t(what, qry)
 ORDER BY what COLLATE "C";

--
-- Exempt objects, and the negative control for the whole rule.
--
-- A catalog relation keeps its name, and so do its columns.  The column half was
-- missing until this task: set_relation_column_names() substituted regardless of
-- exemption, so a plan over the system catalogs read "pg_class.pg_class_c2"
-- instead of "pg_class.relname".  That protected nothing -- those are
-- PostgreSQL's names -- while making catalog plans unreadable, and it still
-- disclosed the attribute's position, which for a catalog table is published.
SELECT test_redact_deparse('SELECT relname, relnatts FROM pg_class', true)
         AS catalog_relation_and_columns_kept;

-- A user-written alias on a catalog table is still redacted, because the alias is
-- the user's word even when the table is not.
SELECT test_redact_deparse('SELECT c.relname FROM pg_class c', true)
         AS catalog_column_kept_user_alias_redacted;

-- Mixed in one query: the catalog column survives, the user column does not.
SELECT test_redact_deparse(
         'SELECT c.relname, t.c_second FROM pg_class c, zsec_c t', true)
         AS mixed_catalog_and_user;

--
-- T11: type and collation names.
--
-- Same exemption rule as T10, applied to a different class of object.  Core type
-- labels and core collations keep their names: "?::integer" can be diagnosed while
-- "?::ty3" cannot, and neither "integer" nor COLLATE "C" discloses anything, being
-- PostgreSQL's names.
CREATE TYPE zsec_t02.zsec_enum2 AS ENUM ('a', 'b');
CREATE DOMAIN zsec_t02.zsec_dom AS int CHECK (VALUE > 0);
CREATE TYPE zsec_t02.zsec_pair AS (x int, y text);
CREATE COLLATION zsec_t02.zsec_coll2 (locale = 'C');
ALTER TABLE zsec_t02.zsec_c ADD COLUMN c_enum2 zsec_t02.zsec_enum2;

SELECT what,
       test_redact_deparse(qry, false) AS plain,
       test_redact_deparse(qry, true)  AS redacted
  FROM (VALUES
    -- Negative controls: these must not change.
    ('core type + typmod', 'SELECT c_second::varchar(10) FROM zsec_c'),
    ('core collation',     'SELECT c_second < (''x'' COLLATE "C") FROM zsec_c'),
    ('core array type',    'SELECT c_first = ANY (ARRAY[1,2]) FROM zsec_c'),
    -- User-defined types.  Each casts to a *different* type than the column's
    -- own, because a cast to its own type is folded away and the fixture would
    -- then pass having printed no type label at all.
    ('user enum',          'SELECT c_enum2 = ''a''::zsec_t02.zsec_enum2 FROM zsec_c'),
    ('user domain cast',   'SELECT c_first::zsec_t02.zsec_dom FROM zsec_c'),
    ('user composite cast',
     'SELECT ROW(c_first, c_second)::zsec_t02.zsec_pair FROM zsec_c'),
    ('user collation',
     'SELECT c_second < (''x'' COLLATE zsec_t02.zsec_coll2) FROM zsec_c'),
    -- FR-40 again: one type reached twice yields one pseudonym.
    ('same type twice',
     'SELECT c_enum2 = ''a''::zsec_t02.zsec_enum2 OR c_enum2 = ''b''::zsec_t02.zsec_enum2 FROM zsec_c')
  ) AS t(what, qry)
 ORDER BY what COLLATE "C";

-- The schema qualifier goes with the name: a user type never prints as
-- "schema.ty1", because FR-11 drops schema names and there is nothing to qualify
-- a generated name against.  Asserted rather than left to inspection.
SELECT test_redact_deparse('SELECT c_first::zsec_t02.zsec_dom FROM zsec_c', true)
         NOT LIKE '%zsec_t02%' AS user_type_not_schema_qualified;

RESET search_path;
DROP SCHEMA zsec_t02 CASCADE;
DROP EXTENSION test_explain_redact;
