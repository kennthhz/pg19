
# Copyright (c) 2021-2026, PostgreSQL Global Development Group

# Leak-detection harness for auto_explain redaction, log side.
#
# Task T01 of the auto-explain redaction plan.  No product code is exercised
# here: auto_explain.log_redact does not exist yet.  This file is the positive
# control for the paths that are only reachable through auto_explain's own log
# record, and therefore cannot be covered by src/test/regress/explain_redact:
#
#   FR-22  parameter VALUES        -- the Query Parameters property
#   FR-23  the query text itself   -- the Query Text property
#   FR-17  the trigger section     -- needs ANALYZE *and* log_triggers, so a
#                                     matrix of non-ANALYZE plans never
#                                     reaches report_triggers() at all
#   FR-26  the Settings section    -- needs log_settings
#   FR-37  Query Identifier        -- needs VERBOSE and compute_query_id
#   FR-29  extension output        -- pg_overexplain via log_extension_options
#
# It also covers the fixtures that depend on optional build features (libxml,
# ICU).  Those are skipped rather than failed when the feature is absent, which
# is why they live in a TAP test: a regression file would need alternative
# expected outputs for every combination.
#
# Every assertion here is "the identifier IS present".  Once T04 lands, the
# same fixtures run with auto_explain.log_redact = on and the assertions
# invert.  Proving the detector fires first is the whole point: an assertion
# that never had the chance to fail would pass for the rest of the project.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Runs the specified query and returns the emitted server log.
sub query_log
{
	my ($node, $sql, $params) = @_;
	$params ||= {};

	local $ENV{PGOPTIONS} = join " ",
	  map { "-c $_=$params->{$_}" } keys %$params;

	my $log = $node->logfile();
	my $offset = -s $log;

	$node->safe_psql("postgres", $sql);

	return slurp_file($log, $offset);
}

# Returns the sorted, de-duplicated list of fixture identifiers found in $log.
# Mirrors zsec_leaks() in src/test/regress/sql/explain_redact.sql, including
# the marker prefix: "zsec_" is four characters because a bare "z" prefix
# collides with "zone" in "timestamp with time zone".
# Strips the Query Text property from a log chunk.
#
# auto_explain emits Query Text in every record, so the statement's own text is
# in the log before any plan property is considered.  Any assertion of the form
# "this identifier appears in the log" is therefore satisfied by the query text
# alone, whether or not the plan property under test was emitted at all.  Three
# assertions in this file were written that way.
sub without_query_text
{
	my ($log) = @_;
	$log =~ s/^.*Query Text:.*$//mg;
	return $log;
}

sub leaked
{
	my ($log) = @_;
	my %seen;
	# Two markers: zsec_ on identifiers, zsecdata- on stored values.  Values
	# need their own alternative because a leaked value is not an identifier and
	# would otherwise be invisible to this grep.
	#
	# Case-insensitive, mirroring the SQL detector: a marked name routed
	# through upper() arrives as ZSEC_CUSTOMERS, which a case-sensitive
	# pattern reads as clean.  Results are lower-cased so callers compare
	# exactly.
	$seen{ lc($1) } = 1
	  while $log =~ /(zsec_[a-z0-9_]*|zsecdata-[a-z0-9-]*)/gi;
	return sort keys %seen;
}

my $node = PostgreSQL::Test::Cluster->new('redact');
$node->init;
$node->append_conf('postgresql.conf',
	"session_preload_libraries = 'pg_overexplain,auto_explain'");
$node->append_conf('postgresql.conf', "auto_explain.log_min_duration = 0");
$node->append_conf('postgresql.conf', "compute_query_id = on");
$node->start;

# ---------------------------------------------------------------------------
# Fixture schema.
#
# This is deliberately NOT the same schema as the regression file's, and the two
# are not kept in lockstep.  They test different channels and need different
# objects: the regression file needs a collation, an enum, a domain, a composite
# type and partitioned tables to reach the deparse paths that print type and
# collation names, none of which this file asserts on; this file needs triggers,
# which the regression file cannot reach because the trigger section requires
# ANALYZE plus log_triggers.  Forcing parity would mean carrying objects in each
# file that its own assertions never touch.
#
# What IS shared, and what actually matters, is the marker convention: zsec_ on
# every identifier and zsecdata- on every stored value.  That invariant is
# enforced in both files by the assertion below, so neither can drift into
# holding an unmarked object -- which is the failure that would make a leak
# invisible.  Schema divergence is fine; marker divergence is not.
# ---------------------------------------------------------------------------
$node->safe_psql(
	'postgres', q{
CREATE SCHEMA zsec_ns;
SET search_path = zsec_ns, public;

CREATE TABLE zsec_customers (
    zsec_id     int GENERATED BY DEFAULT AS IDENTITY,
    zsec_ssn    text,
    zsec_bal    numeric
);

-- Marked DATA as well as marked schema.  The detector greps for the marker,
-- which finds leaked identifiers; it is blind to leaked *values*, because a real
-- value is not an identifier and matches nothing.  Making the stored values
-- self-identifying closes that gap without needing a classifier that recognises
-- arbitrary sensitive data.  It also means ANALYZE-mode records report non-zero
-- row counts, so plan shapes that need real data actually occur.
INSERT INTO zsec_customers (zsec_ssn, zsec_bal)
SELECT 'zsecdata-ssn-' || lpad(i::text, 4, '0'), (i * 100)::numeric
  FROM generate_series(1, 20) AS i;
ANALYZE zsec_customers;

CREATE FUNCTION zsec_trigfunc() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;

-- Two triggers, deliberately distinguishable.  report_triggers() prints the
-- trigger name only when VERBOSE is set or when the trigger has no associated
-- constraint; otherwise it prints just the constraint name.  Naming them
-- differently is what lets the assertions below tell which of the two leaked.
CREATE TRIGGER zsec_plaintrig AFTER INSERT ON zsec_customers
    FOR EACH ROW EXECUTE FUNCTION zsec_trigfunc();

CREATE CONSTRAINT TRIGGER zsec_ctrig AFTER INSERT ON zsec_customers
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION zsec_trigfunc();
});

# ---------------------------------------------------------------------------
# Marking discipline.  The same invariant the regression file enforces, applied
# to this file's own schema.  Returns any object or stored value missing its
# marker; must be empty, or this file has a permanent blind spot.
# ---------------------------------------------------------------------------
my $unmarked = $node->safe_psql(
	'postgres', q{
SELECT coalesce(string_agg(kind || ':' || name, ', '), '') FROM (
    SELECT 'relation' AS kind, c.relname::text AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zsec_ns'
    UNION ALL
    SELECT 'column', a.attname::text
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zsec_ns' AND a.attnum > 0 AND NOT a.attisdropped
       AND c.relkind NOT IN ('S', 'i')
    UNION ALL
    SELECT 'function', p.proname::text
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'zsec_ns'
    UNION ALL
    SELECT 'type', t.typname::text
      FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'zsec_ns'
    UNION ALL
    SELECT 'trigger', tg.tgname::text
      FROM pg_trigger tg
      JOIN pg_class c ON c.oid = tg.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zsec_ns' AND NOT tg.tgisinternal
    UNION ALL
    SELECT 'value', zsec_ssn FROM zsec_ns.zsec_customers
) obj
 WHERE name !~ '^_?zsec' });

is($unmarked, '', 'every fixture object and stored value carries the marker');

# ---------------------------------------------------------------------------
# FR-23: Query Text carries the whole statement verbatim.
# ---------------------------------------------------------------------------
my $log = query_log($node,
	"SET search_path = zsec_ns, public; SELECT * FROM zsec_customers;");

like(
	$log,
	qr/Query Text: SELECT \* FROM zsec_customers;/,
	'FR-23: query text is logged verbatim today');

# ---------------------------------------------------------------------------
# FR-22: Query Parameters carries parameter VALUES, which are user data rather
# than schema.  Note the value below is not an identifier, so the "zsec_"
# detector would not catch it -- parameter values need their own assertion.
# ---------------------------------------------------------------------------
$log = query_log(
	$node,
	q{SET search_path = zsec_ns, public;
	  PREPARE zsec_p(text) AS SELECT * FROM zsec_customers WHERE zsec_ssn = $1;
	  EXECUTE zsec_p('zsecdata-ssn-0007');});

like(
	$log,
	qr/Query Parameters: \$1 = 'zsecdata-ssn-0007'/,
	'FR-22: parameter values are logged today');

# The parameter value now carries the marker too, so the generic detector sees
# it -- previously this was the one leak class the grep was structurally blind
# to, and it needed the hand-written assertion above to be caught at all.
my @param_leaks = leaked($log);
ok( scalar(grep { /^zsecdata-ssn-0007$/ } @param_leaks) > 0,
	'FR-22: marked parameter VALUE is visible to the generic detector');

# ---------------------------------------------------------------------------
# FR-17: the trigger section.  Reachable only with log_analyze AND
# log_triggers; this is the assertion that would silently never run if the
# test matrix omitted ANALYZE.
# ---------------------------------------------------------------------------
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; INSERT INTO zsec_customers (zsec_ssn) VALUES ('x');",
	{
		'auto_explain.log_analyze' => 'on',
		'auto_explain.log_triggers' => 'on'
	});

# A plain trigger has no constraint, so its own name is printed.
like(
	$log,
	qr/Trigger zsec_plaintrig/,
	'FR-17: plain trigger name is logged today');

# A constraint trigger without VERBOSE prints ONLY the constraint name --
# the trigger name is deliberately suppressed by report_triggers().  So the
# trigger name and the constraint name are disclosed under *different*
# conditions, and a test fixed at one verbosity misses one of them.
like(
	$log,
	qr/Trigger for constraint zsec_ctrig/,
	'FR-17: constraint name is logged today (trigger name suppressed without VERBOSE)'
);

my @trig_leaks = leaked(without_query_text($log));
ok( scalar(grep { /^zsec_plaintrig$|^zsec_ctrig$/ } @trig_leaks) > 0,
	"FR-17: detector fires on a trigger NAME in the trigger section (@trig_leaks)"
);

# With VERBOSE, the constraint trigger discloses BOTH names.
my $vlog = query_log(
	$node,
	"SET search_path = zsec_ns, public; INSERT INTO zsec_customers (zsec_ssn) VALUES ('v');",
	{
		'auto_explain.log_analyze' => 'on',
		'auto_explain.log_triggers' => 'on',
		'auto_explain.log_verbose' => 'on'
	});

like(
	$vlog,
	qr/Trigger zsec_ctrig for constraint zsec_ctrig/,
	'FR-17: VERBOSE discloses the trigger name as well as the constraint name'
);

# Confirm the converse, which is the reason FR-17 needs its own configuration:
# without log_triggers the section is absent entirely.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; INSERT INTO zsec_customers (zsec_ssn) VALUES ('y');",
	{ 'auto_explain.log_analyze' => 'on' });

unlike($log, qr/Trigger/,
	'FR-17: trigger section absent without log_triggers, so a matrix without it proves nothing'
);

# ---------------------------------------------------------------------------
# NEGATIVE CONTROLS for ANALYZE mode: FR-30 to FR-38.
#
# Every other assertion in this file checks that something IS disclosed, and
# will later be inverted to check that it is NOT.  That direction alone is
# satisfiable by a redaction implementation that prints nothing at all -- a
# record stripped of every counter would pass a suite made only of absence
# checks, while destroying the entire diagnostic value the feature exists to
# preserve.
#
# These assert the opposite direction, and unlike the rest of the file they must
# hold UNCHANGED at every stage of the project, before and after redaction.  They
# are the reason redaction cannot quietly become deletion.
#
# ANALYZE mode is where the counters live, so this is the only place they can be
# checked.  It is also why the fixture table is seeded: with an empty table the
# row counts would all be zero and these assertions would be vacuous.
# ---------------------------------------------------------------------------
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT count(*) FROM zsec_customers WHERE zsec_bal > 500;",
	{
		'auto_explain.log_analyze' => 'on',
		'auto_explain.log_buffers' => 'on',
		'auto_explain.log_timing' => 'on'
	});

# Note the fractional row count: this version reports ACTUAL rows to two decimal
# places ("rows=15.00"), while the planner ESTIMATE stays an integer
# ("rows=16").  An integer-only pattern therefore matches the estimate and
# passes without testing the actual count at all -- which is what the first
# draft of these assertions did.  Both are anchored to "actual time=" so they
# cannot drift onto the cost estimate.
like(
	$log,
	qr/actual time=[\d.]+\.\.[\d.]+ rows=[\d.]+ loops=\d+/,
	'FR-32: actual rows, loops and timing are present');
like(
	$log,
	qr/actual time=[\d.]+\.\.[\d.]+ rows=1[0-9]\.\d+/,
	'FR-32: actual row counts reflect the seeded data, not an empty table');
like(
	$log,
	qr/Rows Removed by Filter: \d+/,
	'FR-31: Rows Removed by Filter is present');
like($log, qr/Buffers: shared/, 'FR-33: buffer usage is present');
like(
	$log,
	qr/cost=[\d.]+\.\.[\d.]+ rows=\d+ width=\d+/,
	'FR-31: planner estimates are present');

# FR-36, with a correction found here.  auto_explain does NOT emit the Planning
# Time or Execution Time properties: those come from ExplainOnePlan, and
# auto_explain calls ExplainPrintPlan directly.  The whole-query duration
# reaches the log through the ereport message prefix instead.  So within the
# auto_explain channel FR-36 is about that prefix, and the two properties it
# names exist only in the EXPLAIN (ANALYZE) channel.
like(
	$log,
	qr/duration: [\d.]+ ms  plan:/,
	'FR-36: whole-query duration is present, via the log message prefix');
unlike(
	$log,
	qr/Execution Time:/,
	'FR-36: auto_explain does not emit the Execution Time property at all');

# ---------------------------------------------------------------------------
# FR-26 / FR-37: the Settings section and Query Identifier.
# ---------------------------------------------------------------------------
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT * FROM zsec_customers;",
	{
		'auto_explain.log_settings' => 'on',
		'auto_explain.log_verbose' => 'on'
	});

like($log, qr/Settings:.*search_path/s,
	'FR-26: Settings section discloses search_path today');
like(
	$log,
	qr/Query Identifier: -?\d+/,
	'FR-37: Query Identifier is logged today');

# ---------------------------------------------------------------------------
# FR-29: extension output via auto_explain.log_extension_options.  This is the
# highest-severity finding of the code audit -- pg_overexplain dumps the whole
# range table, including every column name of every RTE.  Asserting it here
# means T04's suppression has something concrete to be measured against.
# ---------------------------------------------------------------------------
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT * FROM zsec_customers;",
	{ 'auto_explain.log_extension_options' => 'range_table' });

like(
	$log,
	qr/RTI 1 \(relation/,
	'FR-29: extension range-table dump is logged today');
like(
	$log,
	qr/Relation: zsec_customers/,
	'FR-29: extension dump discloses the relation name');

# The worst of it: Eref lists EVERY column of the relation, whether or not the
# query referenced them.  A single-column SELECT still discloses the full column
# list.  This is the concrete measure T04's suppression has to erase.
like(
	$log,
	qr/Eref: zsec_customers \(zsec_id, zsec_ssn, zsec_bal\)/,
	'FR-29: extension dump discloses every column name of the relation via Eref'
);

# ---------------------------------------------------------------------------
# Build-dependent fixtures.  Skipped, not failed, when the feature is absent:
# FR-95 (XML construction names) and part of FR-98d (IS NORMALIZED) cannot be
# reached at all without --with-libxml / --with-icu.  A build without them
# leaves those requirements unverified, which is a fact worth surfacing in the
# test output rather than hiding behind a pass.
# ---------------------------------------------------------------------------
# Detected from the build configuration, not from the catalog.
#
# Two earlier attempts were both wrong, in opposite directions.  Probing pg_proc
# for 'xmlelement' always returned 0, because xmlelement is grammar and has no
# catalog row -- so FR-95 skipped on every build, and a TAP skip counts as a
# pass.  Probing for 'xmlcomment' always returns 1, because the catalog row
# exists whether or not libxml was compiled in; only the runtime fails.  Neither
# probe can answer the question, because the question is about the build.
#
# check_pg_config() reads USE_LIBXML out of the installed pg_config.h, which is
# the thing that actually determines whether the feature works.
my $has_libxml = check_pg_config('#define USE_LIBXML 1');

SKIP:
{
	skip "build lacks libxml support; FR-95 is unverified here", 1
	  unless $has_libxml;

	$log = query_log(
		$node,
		q{SET search_path = zsec_ns, public;
		  SELECT zsec_id FROM zsec_customers
		   WHERE xmlelement(name zsec_elem,
		                    xmlattributes(zsec_ssn AS zsec_attr)) IS NOT NULL;});

	my @xml_leaks = leaked(without_query_text($log));
	ok( scalar(grep { /^zsec_elem$|^zsec_attr$/ } @xml_leaks) > 0,
		"FR-95: XML construction names reach the PLAN, not just the query text (@xml_leaks)"
	);
}

my $has_icu = $node->safe_psql('postgres',
		"SELECT current_setting('server_version_num')::int > 0 AND "
	  . "EXISTS (SELECT 1 FROM pg_collation WHERE collprovider = 'i')") eq
  't';

SKIP:
{
	skip "build lacks ICU support; FR-98d IS NORMALIZED is unverified here", 1
	  unless $has_icu;

	$log = query_log(
		$node,
		q{SET search_path = zsec_ns, public;
		  SELECT zsec_id FROM zsec_customers WHERE zsec_ssn IS NFC NORMALIZED;});

	like(
		$log,
		qr/Filter: \(zsec_ssn IS NFC NORMALIZED\)/,
		'FR-98d: IS NORMALIZED reaches the Filter property, not just the query text'
	);
}

# ---------------------------------------------------------------------------
# Detector self-check.  A detector that matched anything would make every
# later "clean" assertion vacuous.
# ---------------------------------------------------------------------------
$log = query_log($node, "SELECT now() AT TIME ZONE 'UTC';");

my @false_positives = leaked($log);
is(scalar(@false_positives), 0,
	'detector reports nothing for a query with no fixture objects, including "time zone"'
);

done_testing();
