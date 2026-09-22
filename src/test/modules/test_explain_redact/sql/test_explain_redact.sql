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

DROP SCHEMA zsec_t02 CASCADE;
DROP EXTENSION test_explain_redact;
