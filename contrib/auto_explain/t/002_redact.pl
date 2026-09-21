
# Copyright (c) 2021-2026, PostgreSQL Global Development Group

# 002_redact.pl -- log-side leak detection for auto_explain output redaction.
#
#
# PURPOSE OF THIS FILE
#
# This test establishes, and then guards, exactly which parts of auto_explain's
# log output disclose an application's schema and data.
#
# It works by running ordinary queries against a live cluster with auto_explain
# enabled, capturing the log records they produce, and searching those records
# for the fixture's deliberately marked object names and values.  Every name in
# the fixture schema begins with "zsec_" and every stored value with
# "zsecdata-", so a leak of any kind reduces to one question: did either marker
# reach the log?
#
# It serves two purposes in sequence.  Today, before any redaction code exists,
# it is an executable inventory of the leaks -- each assertion names a property
# of the log output and the identifier that property discloses -- and it proves
# the detector can actually find them.  Once the redaction GUC lands, the same
# fixtures run with it enabled and the assertions invert, at which point this
# file becomes the regression test that the leaks stay closed.
#
# Its scope is the log specifically.  Properties that a client-side EXPLAIN can
# produce are tested in src/test/regress/sql/explain_redact.sql; what remains
# here is output that only auto_explain emits, only emits under one of its GUCs,
# or that depends on an optional build feature.  The division is spelled out
# under WHY A TAP TEST below.
#
# Run it with:  make -C contrib/auto_explain check
#
#
# WHAT THE FEATURE IS
#
# auto_explain writes query plans to the server log, and those plans contain the
# application's schema and data verbatim: table and column names, function names,
# literal values, bind parameter values, and the full text of the query.  Anything
# that can read the log -- a log shipper, an observability vendor, a support
# ticket -- therefore sees all of it.  Organisations that cannot allow that today
# have no option but to switch auto_explain off entirely.
#
# The feature under construction adds a mode in which those names and values are
# replaced by opaque pseudonyms ("t1", "f2", "?"), while everything needed for
# performance diagnosis -- plan shape, costs, row counts, timings, buffer usage --
# is preserved.  See design/auto-explain-redaction-requirements.md for the
# contract and design/auto-explain-redaction-task-plan.md for the build order.
#
#
# WHY THIS TEST ASSERTS THAT SECRETS *ARE* PRESENT
#
# This is the part that looks wrong at first glance, so it is worth stating
# plainly: every assertion below checks that a sensitive identifier IS in the log.
# That is deliberate, and it is the reason this file exists before the feature
# does.
#
# Redaction is verified by absence, and absence is treacherous to test.  An
# assertion that "the table name does not appear" passes when redaction works --
# and equally when the test looks in the wrong place, greps for the wrong string,
# or examines output that never contained the name to begin with.  A broken
# detector reports success forever and nobody finds out until a customer reads a
# log file.
#
# So the detector is built first and proved against unredacted output, where the
# secrets are known to be present.  If it can find them now, it can be trusted to
# report their absence later.  When the redaction GUC lands, these same fixtures
# run with it enabled and the assertions inverted.
#
#
# HOW LEAKS ARE DETECTED
#
# Every object in the fixture schema is named with the prefix "zsec_", and every
# stored value with "zsecdata-".  Detection is then a single question -- does
# either marker appear anywhere in the log? -- with no need to enumerate which
# property a name might surface in.
#
# Both markers are needed.  An identifier-only pattern is structurally blind to
# leaked *data*: a real value is not an identifier and matches nothing.  Marking
# the values makes them self-identifying, which covers that class without needing
# a classifier for arbitrary sensitive data.
#
# The prefix is four characters rather than a bare "z" because "timestamp with
# time zone" contains "zone", which a /z[a-z_]+/ detector reports as a leak on
# every timestamptz column.
#
#
# WHY A TAP TEST AND NOT A REGRESSION FILE
#
# Most of the redaction contract is checked by src/test/regress/sql/
# explain_redact.sql, which runs EXPLAIN and inspects the result rows.  This file
# covers what that one structurally cannot: output that exists only in the server
# log, or only under an auto_explain GUC.
#
#   FR-23  Query Text          the whole statement, emitted by auto_explain only;
#                              no client EXPLAIN produces this property
#   FR-22  Query Parameters    bind parameter VALUES -- the one leak class that is
#                              data rather than schema
#   FR-17  the trigger section reachable only with log_analyze AND log_triggers,
#                              so a matrix of non-ANALYZE plans never executes
#                              report_triggers() at all
#   FR-26  the Settings block  needs log_settings; discloses search_path
#   FR-37  Query Identifier    needs log_verbose and compute_query_id; its value
#                              varies per build, so an expected-output file
#                              cannot match it but a regex can
#   FR-29  extension output    pg_overexplain via log_extension_options, which
#                              dumps the entire range table including every
#                              column name of every relation
#
# It also holds the fixtures that depend on optional build features, because TAP
# can skip them on a capability probe.  A regression file would need alternative
# expected-output files for every combination of libxml and ICU.
#
# Lastly, this file asserts that the diagnostic content SURVIVES redaction
# (actual rows, loops, timings, buffers).  Those assertions must hold unchanged
# at every stage of the project, before and after the feature exists: without
# them, a redaction implementation that emitted an empty record would pass a
# suite made entirely of absence checks.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Runs one or more statements and returns only the log output they produced.
#
# The byte offset taken before the statement runs is what makes each assertion
# independent: it yields exactly the log this call appended, not the whole file.
#
# $params is an optional hash of GUC name => value, passed to the backend through
# PGOPTIONS.  Several of the properties tested here appear only under a specific
# auto_explain setting, so the same statement is often run more than once with
# different GUCs -- that is how the trigger section is shown to be absent without
# log_triggers and present with it.
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

# Removes the Query Text property from a log chunk.
#
# auto_explain emits Query Text in every record, so the statement's own text
# reaches the log before any plan property is considered.  An assertion of the
# form "this identifier appears somewhere in the log" is therefore satisfied by
# the query text alone -- whether or not the plan property under test was emitted
# at all.  Three assertions in this file were written that way and passed for
# that reason.
#
# Callers testing a plan property should strip the query text first, or anchor
# their regex on the specific property line.
sub without_query_text
{
	my ($log) = @_;
	$log =~ s/^.*Query Text:.*$//mg;
	return $log;
}

# Returns only the auto_explain plan records from a log chunk.
#
# Needed because this cluster -- like every cluster PostgreSQL::Test::Cluster
# creates -- runs with "log_statement = all" and a log_line_prefix containing
# "%q" (Cluster.pm:713-714).  Both put the verbatim statement into the same log
# file, so a chunk always contains the marked names whatever auto_explain did
# with them.  "No marker appears in this log" is therefore not a provable
# assertion, and a claim about redaction has to be scoped to the record
# redaction is responsible for.
#
# That the standard test harness is configured this way is not incidental: it is
# the very hazard FR-75 warns operators about, reproduced by the framework's own
# defaults.
#
# Relies on how a multi-line ereport is written: the first line carries the
# log_line_prefix and the remainder are tab-indented continuations.  The first
# line is kept because the duration prefix is asserted on.
sub plan_record
{
	my ($log) = @_;
	my @kept;
	my $in_record = 0;

	foreach my $line (split /\n/, $log)
	{
		# The "ref:" field appears only on redacted records, so it is optional
		# here.  Getting this pattern wrong is unusually dangerous: matching
		# nothing returns an empty string, leaked("") finds no markers, and every
		# "nothing leaked" assertion built on this helper then passes while
		# examining nothing at all.  That is why the check below is a hard
		# failure rather than an empty return.
		if ($line =~ /duration: [\d.]+ ms  (?:ref: [0-9a-f]+  )?plan:/)
		{
			$in_record = 1;
			push @kept, $line;
			next;
		}
		if ($in_record)
		{
			if ($line =~ /^\t/)
			{
				push @kept, $line;
				next;
			}
			$in_record = 0;
		}
	}

	# A caller only asks for the record because it is about to assert something
	# about its contents.  Returning empty would turn each of those assertions
	# into a tautology, so refuse instead.
	die "plan_record() found no auto_explain record in this log chunk; "
	  . "has the record's message format changed?"
	  unless @kept;

	return join("\n", @kept) . "\n";
}

# Returns the sorted, de-duplicated marker strings found in $log -- that is, the
# fixture identifiers and values that leaked.  An empty list means no leak.
#
# Returning the names rather than a count is what makes a failure diagnosable,
# and it matters for a second reason: an assertion that merely counts leaks
# passes as long as SOMETHING leaked, which in a schema where every fixture
# touches zsec_customers.zsec_ssn is nearly always true.  Callers should check
# for the specific identifier their fixture exists to produce.
#
# This mirrors zsec_leaks() in src/test/regress/sql/explain_redact.sql; the two
# must stay in step, since a leak found by one should be reproducible by the
# other.
#
# Matching is case-insensitive and results are lower-cased.  A marked name routed
# through upper() arrives as ZSEC_CUSTOMERS, and a case-sensitive pattern would
# read that as clean -- harmless while these assertions are positive, exactly
# wrong once they invert.
sub leaked
{
	my ($log) = @_;
	my %seen;

	$seen{ lc($1) } = 1
	  while $log =~ /(zsec_[a-z0-9_]*|zsecdata-[a-z0-9-]*)/gi;
	return sort keys %seen;
}

# A dedicated cluster, configured so that every statement produces a log record.
#
#   log_min_duration = 0   log every statement regardless of how fast it was;
#                          the default of -1 disables auto_explain entirely
#   compute_query_id = on  without it queryId stays 0 and the Query Identifier
#                          property is never emitted, so FR-37 could not be tested
#   pg_overexplain         an in-tree extension that registers EXPLAIN options and
#                          prints the whole range table.  Loaded because FR-29 is
#                          about exactly that: extension output that the redaction
#                          contract has to suppress.  It is inert unless one of
#                          its options is enabled.
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
# FR-23: the Query Text property.
#
# auto_explain prints the statement verbatim, so this single property discloses
# every name and literal the query mentions -- schema, tables, columns, and any
# inlined values -- regardless of what the plan itself reveals.  The redaction
# contract omits it outright rather than trying to sanitise it.
#
# This property comes from auto_explain, not from core EXPLAIN, which is why it
# cannot be tested from the regression file.
# ---------------------------------------------------------------------------
my $log = query_log($node,
	"SET search_path = zsec_ns, public; SELECT * FROM zsec_customers;");

like(
	$log,
	qr/Query Text: SELECT \* FROM zsec_customers;/,
	'FR-23: query text is logged verbatim today');

# ---------------------------------------------------------------------------
# FR-22: the Query Parameters property.
#
# This is the one place where what leaks is DATA rather than schema: the actual
# values a client bound to a prepared statement.  A real deployment would have
# social security numbers or card numbers here.
#
# It is also why the fixture data carries its own marker.  An identifier-shaped
# detector cannot see a leaked value -- a value is not an identifier and matches
# no naming pattern -- so the stored values are made self-identifying instead,
# and the generic detector then finds them like any other leak.  The assertion
# below checks both: the literal string, and that the detector sees it.
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
# FR-17: the trigger section.
#
# report_triggers() prints the trigger name, the constraint name, and the
# relation the trigger is on.  Reaching it needs log_analyze AND log_triggers
# together, which makes it the clearest example of a leak that a plausible test
# matrix misses completely: with either GUC off the section is not emitted at
# all, so a suite of non-ANALYZE plans would report full coverage while these
# three names went entirely untested.
#
# The two names are also disclosed under DIFFERENT conditions, which is why there
# are two triggers here and two verbosity settings below.
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
# FR-26 and FR-37: the Settings section, and Query Identifier.
#
# Settings lists every planner GUC whose value differs from the built-in default
# -- including search_path, which names schemas directly.  Note the property NAME
# is itself a GUC name here, the one place in EXPLAIN output where that is true.
#
# Query Identifier is a hash rather than a name, which sounds safe and is not:
# the algorithm is deterministic and public, so anyone holding a guess at the
# query text can confirm it offline.  That makes it a membership oracle, and the
# contract omits it for that reason rather than pseudonymising it.
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

# ---------------------------------------------------------------------------
# PHASE 2 (T04): the same channels with redaction enabled.
#
# Everything above ran with auto_explain.log_redact off and asserted that the
# markers ARE present, which is what proves the detector works.  From here the
# same detector runs against redacted records and the assertions invert: the
# markers must be absent.
#
# The switch is written to postgresql.conf and applied with a reload rather than
# passed through PGOPTIONS, because the GUC is PGC_SIGHUP (D9) and a per-session
# assignment is refused by design -- a superuser session must not be able to turn
# redaction off for itself.  So this also tests that the GUC has the intended
# level: were it PGC_SUSET, the reload would be unnecessary and PGOPTIONS would
# have worked.
# ---------------------------------------------------------------------------
$node->append_conf('postgresql.conf', "auto_explain.log_redact = on");
$node->reload;

# Prove the reload took effect before asserting anything about absence.  Without
# this, every check below would also pass if the setting had been ignored.
is( $node->safe_psql('postgres', 'SHOW auto_explain.log_redact'),
	'on',
	'T04: auto_explain.log_redact is settable by reload, as PGC_SIGHUP requires'
);

# FR-23: the query text goes entirely.
$log = query_log($node,
	"SET search_path = zsec_ns, public; SELECT * FROM zsec_customers;");
unlike(
	$log,
	qr/Query Text:/,
	'FR-23 redacted: the Query Text property is omitted, not sanitised');
is_deeply([ leaked(plan_record($log)) ],
	[], 'FR-23 redacted: no marker survives anywhere in the record');

# FR-22: parameters go, values and count alike.
$log = query_log(
	$node,
	q{SET search_path = zsec_ns, public;
	  PREPARE zsec_p2(text) AS SELECT * FROM zsec_customers WHERE zsec_ssn = $1;
	  EXECUTE zsec_p2('zsecdata-ssn-0007');});
unlike(
	$log,
	qr/Query Parameters/,
	'FR-22 redacted: the property is omitted outright (D10), not reduced to names'
);
is_deeply([ leaked(plan_record($log)) ],
	[],
	'FR-22 redacted: the bound parameter value does not reach the record');

# FR-17: the trigger section keeps its counters and loses its three names.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; INSERT INTO zsec_customers (zsec_ssn) VALUES ('zsecdata-t04');",
	{
		'auto_explain.log_analyze' => 'on',
		'auto_explain.log_triggers' => 'on'
	});
is_deeply(
	[ leaked(plan_record($log)) ],
	[],
	'FR-17 redacted: trigger, constraint and relation names are all withheld'
);
like(
	$log,
	qr{Trigger: (?:time=[\d.]+ )?calls=\d+},
	'FR-17 redacted: the firing count still prints -- redaction is not deletion'
);

# FR-37: queryId goes.  compute_query_id is on for this cluster, so the property
# would otherwise be emitted whenever log_verbose is.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;",
	{ 'auto_explain.log_verbose' => 'on' });
unlike(
	$log,
	qr/Query Identifier/,
	'FR-37 redacted: queryId is omitted, being a membership oracle (D5)');

# FR-26: the Settings section goes.  search_path carries GUC_EXPLAIN, so this
# section really does disclose schema names.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;",
	{ 'auto_explain.log_settings' => 'on' });
unlike($log, qr/Settings:/,
	'FR-26 redacted: the Settings section is omitted');
is_deeply([ leaked(plan_record($log)) ],
	[],
	'FR-26 redacted: search_path does not reach the record by this route');

# FR-29/FR-73: auto_explain ignores extension options rather than failing the
# statement, and says so once per session.  The interactive path raises an error
# instead; that asymmetry is deliberate and is tested in the regression file.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;",
	{ 'auto_explain.log_extension_options' => 'range_table' });
unlike(
	$log,
	qr/RTI \d+|Eref:/,
	'FR-73 redacted: pg_overexplain range table is not emitted');
like(
	$log,
	qr/log_redact is enabled, but auto_explain\.log_extension_options is also active/,
	'FR-73 redacted: skipping the extension output is reported, not silent');

# FR-2: a nested statement is redacted too.  The function body runs below the
# top-level statement, and log_nested_statements is what makes it logged at all.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; DO \$\$ BEGIN PERFORM count(*) FROM zsec_customers WHERE zsec_ssn > 'a'; END \$\$;",
	{ 'auto_explain.log_nested_statements' => 'on' });
like(
	$log,
	qr/duration: [\d.]+ ms  ref: [0-9a-f]+  plan:/,
	'FR-2 redacted: the nested statement really was logged');
is_deeply([ leaked(plan_record($log)) ],
	[], 'FR-2 redacted: nested statements carry no marker either');

# Negative controls.  Without these the phase above passes by deleting the
# record wholesale, which would satisfy every "absent" assertion at once.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT count(*) FROM zsec_customers WHERE zsec_bal > 0;",
	{
		'auto_explain.log_analyze' => 'on',
		'auto_explain.log_buffers' => 'on'
	});
like(
	$log,
	qr/duration: [\d.]+ ms/,
	'negative control: the duration prefix still prints under redaction');
# log_timing defaults to on, which makes the text "actual time=A..B rows=N"
# with no "actual rows=" substring anywhere -- the same trap the FR-32
# assertions above document.
like(
	$log,
	qr/actual (?:time=[\d.]+\.\.[\d.]+ )?rows=[\d.]+ loops=\d+/,
	'negative control: actual row counts still print under redaction');
like(
	$log,
	qr/Buffers: shared/,
	'negative control: buffer usage still prints under redaction');
like($log, qr/Aggregate/,
	'negative control: node types still print under redaction');
like(
	$log,
	qr/cost=[\d.]+\.\.[\d.]+ rows=\d+ width=\d+/,
	'negative control: planner estimates still print under redaction');

# ---------------------------------------------------------------------------
# T05: the correlation token.
#
# A redacted record contains nothing identifying the statement it came from,
# which is the intent -- but on its own that makes the feature awkward enough to
# invite the one workaround that undoes it.  errhidestmt(true) removes the
# STATEMENT: line, and auto_explain otherwise relies on surrounding context to
# say which statement a record describes.  An operator unable to correlate will
# reach for log_min_duration_statement, which puts every statement into this very
# log.
#
# So each redacted record carries a random reference token, and the mapping from
# token to statement goes into a separate DEBUG1 entry that a site can route
# elsewhere, or never enable at all.
# ---------------------------------------------------------------------------
$log = query_log($node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;"
);
like(
	$log,
	qr/duration: [\d.]+ ms  ref: [0-9a-f]{16}  plan:/,
	'FR-76: a redacted record carries a 64-bit reference token');

# The companion entry must not appear at the default log level.  If it did, the
# statement would sit in the same log as the plan and the separation would be
# pointless.
unlike(
	$log,
	qr/auto_explain ref/,
	'FR-76: the token-to-statement entry is not written at the default log level'
);
is_deeply([ leaked(plan_record($log)) ],
	[], 'FR-76: adding the token does not itself leak anything');

# Two records must carry different tokens, or the token identifies a statement
# rather than a record.
my $log2 = query_log($node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;"
);
my ($tok1) = $log =~ /ref: ([0-9a-f]{16})/;
my ($tok2) = $log2 =~ /ref: ([0-9a-f]{16})/;
isnt($tok1, $tok2,
	'FR-76: two records carry different tokens, even for the same statement');

# That pair is also the test that the token is not derived from queryId, and it
# is a stronger test than comparing the token against a rendering of queryId.
# Both records ran the identical statement, so their queryId is identical, and a
# token computed from the statement by any function at all -- not merely the ones
# a test author thought to try -- would have come out the same.  They differ, so
# the token cannot be a function of the statement.
#
# This matters because a queryId-derived token would rebuild the guessing attack
# that dropping Query Identifier removed: a reader could hash a candidate
# statement and compare.

# With DEBUG1 enabled the companion entry appears, and its token has to be the
# one in the record, or correlation does not actually work.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT zsec_ssn FROM zsec_customers WHERE zsec_bal > 0;",
	{ 'log_min_messages' => 'debug1' });
my ($rec_token) = $log =~ /ref: ([0-9a-f]{16})/;
like(
	$log,
	qr/auto_explain ref \Q$rec_token\E: SELECT zsec_ssn FROM zsec_customers/,
	'FR-76: the companion entry maps the record token to the real statement');

# And the operator is told that enabling it placed the statements in this log.
like(
	$log,
	qr/log_redact is enabled, but a log level of debug1 or lower is also active/,
	'FR-76: writing the reference entries is reported by the envelope check');

# FR-75: the envelope warning.  Redaction governs this record only; a setting
# that logs the statement in full into the same file gives it all back, and the
# operator is told once per session.
$log = query_log(
	$node,
	"SET search_path = zsec_ns, public; SELECT zsec_bal FROM zsec_customers;",
	{ 'log_min_duration_statement' => '0' });
like(
	$log,
	qr/log_redact is enabled, but log_min_duration_statement is also active/,
	'FR-75: a logging setting that bypasses redaction is reported');

done_testing();
