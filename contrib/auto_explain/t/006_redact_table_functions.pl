# Copyright (c) 2021-2026, PostgreSQL Global Development Group
# 006_redact_table_functions.pl -- auto_explain leaves out the plan of a
# statement that uses XMLTABLE or JSON_TABLE under redaction (FR-101).
#
#
# PURPOSE OF THIS FILE
#
# Interactive EXPLAIN (REDACT) collapses a table function to XMLTABLE(...) or
# JSON_TABLE(...).  auto_explain goes further: under auto_explain.log_redact it
# writes no plan at all for such a statement, only a stub record with the
# duration and the reference token.  This file checks both halves of that and
# the boundary between them:
#
#   - the stub is written, and nothing of the plan is;
#   - it is written however the table function is reached (view, subquery, CTE,
#     sub plan, nested statement) and for a scan the planner removed;
#   - a statement without a table function, in the same configuration, still
#     gets its full redacted plan;
#   - with redaction off the plan is logged in full, unchanged;
#   - the DEBUG1 companion entry still pairs the stub's token with the statement;
#   - interactive EXPLAIN (REDACT) on the same server keeps the collapse.
#
# Every assertion that something is absent is paired with one that the record
# exists, so an empty log cannot pass.
#
# Run it with:  make -C contrib/auto_explain check
#
#
# FIXTURES
#
# Every user name carries the "zsec" marker, so a leak reduces to grepping the
# log for it.  log_statement is turned off for the cluster (Cluster.pm sets it to
# "all"), so the only lines that can carry the marker are the ones auto_explain
# writes, and the companion entry when the DEBUG1 phase asks for it.
#
# The XMLTABLE fixtures read from a table with no rows.  Without libxml,
# XMLTABLE plans and deparses but raises an error the first time it is
# evaluated, even over NULL, and a statement that fails never reaches
# ExecutorEnd.  Over an empty outer table the table function is never
# evaluated, so the statement completes with or without libxml and the plan is
# the same either way.
use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('redact_table_functions');
$node->init;
$node->append_conf(
	'postgresql.conf', qq{
shared_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
auto_explain.log_analyze = on
auto_explain.log_verbose = on
auto_explain.log_redact = on
log_statement = none
});
$node->start;

$node->safe_psql(
	'postgres', q{
CREATE SCHEMA zsec_s;
CREATE TABLE zsec_s.zsec_docs (zsec_id int, zsec_j jsonb);
INSERT INTO zsec_s.zsec_docs VALUES (1, '{"zsec_a": [1, 2]}');
CREATE TABLE zsec_s.zsec_xdocs (zsec_x xml);
CREATE VIEW zsec_s.zsec_jview AS
  SELECT zsec_jc FROM zsec_s.zsec_docs d,
    JSON_TABLE(d.zsec_j, '$.zsec_a[*]' AS zsec_root
               COLUMNS (zsec_jc int PATH '$')) AS zsec_jt;
CREATE FUNCTION zsec_s.zsec_fn() RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM zsec_s.zsec_xdocs d,
    XMLTABLE('/zsec_r' PASSING d.zsec_x COLUMNS zsec_fc text PATH 'zsec_p') AS zsec_ft;
  RETURN n;
END $$;
});

my $xmltable_query = q{SELECT zsec_c FROM zsec_s.zsec_xdocs d,
  XMLTABLE(XMLNAMESPACES('http://zsec.example' AS zsec_ns), '/zsec_r'
           PASSING d.zsec_x COLUMNS zsec_c text PATH 'zsec_ns:zsec_p') AS zsec_t};
my $json_table_query = q{SELECT zsec_jc FROM zsec_s.zsec_docs d,
  JSON_TABLE(d.zsec_j, '$.zsec_a[*]' AS zsec_root
             COLUMNS (zsec_jc int PATH '$')) AS zsec_jt};
my $plain_query = q{SELECT zsec_id FROM zsec_s.zsec_docs WHERE zsec_id = 1};

my $ts = qr/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/;
my $stub_re =
  qr/LOG:  duration: \d+\.\d+ ms  ref: ([0-9a-f]{16})  plan omitted: statement uses (XMLTABLE or JSON_TABLE|XMLTABLE|JSON_TABLE), whose contents cannot be redacted$/;

# Runs SQL and returns the log entries it produced, one string per entry
# (a line starting with a timestamp plus its continuation lines).
sub run_logged
{
	my ($sql, $params) = @_;
	$params ||= {};
	local $ENV{PGOPTIONS} = join ' ',
	  map { "-c $_=$params->{$_}" } sort keys %$params;
	my $log = $node->logfile;
	my $offset = -s $log;
	$node->safe_psql('postgres', $sql);
	my @entries;
	for my $line (split /\n/, slurp_file($log, $offset))
	{
		if ($line =~ $ts || !@entries)
		{
			push @entries, $line;
		}
		else
		{
			$entries[-1] .= "\n$line";
		}
	}
	return @entries;
}

# auto_explain records among the entries: stubs and plans alike.
sub records
{
	return
	  grep { /LOG:  duration: \d+\.\d+ ms  (ref: [0-9a-f]{16}  )?plan/ } @_;
}

# Checks one statement that must produce exactly one stub naming $what.
sub check_stub
{
	my ($name, $sql, $what, $params) = @_;
	my @entries = run_logged($sql, $params);
	my @recs = records(@entries);
	is(scalar(@recs), 1, "$name: one record");
	like($recs[0] // '', $stub_re, "$name: record is the stub");
	my $fn = (($recs[0] // '') =~ $stub_re)[1];
	is($fn, $what, "$name: stub names $what");
	unlike($recs[0] // '',
		qr/plan:|Scan|Output|\n/, "$name: no plan text in the record");
	is(join("\n", grep { /zsec/ } @entries),
		'', "$name: no fixture name anywhere in the log");
	return $recs[0];
}

# 1. The two table functions, reached directly.
check_stub('XMLTABLE', $xmltable_query, 'XMLTABLE');
check_stub('JSON_TABLE', $json_table_query, 'JSON_TABLE');

# 2. Partner: same configuration, no table function, full redacted plan.
{
	my @recs = records(run_logged($plain_query));
	is(scalar(@recs), 1, 'plain: one record');
	like(
		$recs[0] // '',
		qr/ref: [0-9a-f]{16}  plan:\n\s*Seq Scan on t1 .*Output: t1_c1/s,
		'plain: full redacted plan is written');
	unlike(
		$recs[0] // '',
		qr/plan omitted|zsec/,
		'plain: not a stub, and redacted');
}

# 3. However the table function is reached.
check_stub('view', 'SELECT * FROM zsec_s.zsec_jview', 'JSON_TABLE');
check_stub('subquery not pulled up',
	"SELECT * FROM ($xmltable_query OFFSET 0) AS zsec_sub", 'XMLTABLE');
check_stub(
	'materialized CTE',
	"WITH zsec_cte AS MATERIALIZED ($json_table_query) SELECT * FROM zsec_cte",
	'JSON_TABLE');
check_stub(
	'correlated sub plan',
	q{SELECT (SELECT count(*) FROM JSON_TABLE(d.zsec_j, '$.zsec_a[*]'
	   COLUMNS (zsec_sc int PATH '$')) AS zsec_st) FROM zsec_s.zsec_docs d},
	'JSON_TABLE');
check_stub(
	'init plan',
	q{SELECT zsec_id FROM zsec_s.zsec_docs
	   WHERE zsec_id = (SELECT max(zsec_ic) FROM JSON_TABLE('{"zsec_k": 1}'::jsonb, '$'
	   COLUMNS (zsec_ic int PATH '$.zsec_k')) AS zsec_it)},
	'JSON_TABLE');

# A scan the planner removed: nothing of it would be printed, but the range
# table still holds the entry and the rule errs toward leaving the plan out.
# setrefs.c has cleared which function it was, so the stub says either.
{
	my @recs = records(run_logged("$xmltable_query WHERE false"));
	is(scalar(@recs), 1, 'removed scan: one record');
	like($recs[0] // '', $stub_re, 'removed scan: record is the stub');
	like(
		$recs[0] // '',
		qr/uses XMLTABLE or JSON_TABLE,/,
		'removed scan: stub names either function');
}

# 4. A nested statement inside a function is tested on its own: the inner
# statement gets the stub, the calling statement (which uses no table function)
# gets its plan.
{
	my @recs = records(
		run_logged(
			'SELECT zsec_s.zsec_fn()',
			{ 'auto_explain.log_nested_statements' => 'on' }));
	is(scalar(@recs), 2, 'nested: two records');
	my @stubs = grep { $_ =~ $stub_re } @recs;
	is(scalar(@stubs), 1, 'nested: inner statement is a stub');
	like($stubs[0] // '', qr/uses XMLTABLE,/, 'nested: stub names XMLTABLE');
	my @plans = grep { /plan:\n/ } @recs;
	is(scalar(@plans), 1, 'nested: outer statement has its plan');
	unlike(join("\n", @recs), qr/zsec/, 'nested: no fixture name in records');
}

# 5. The stub has one form whatever the plan format would have been.
check_stub('json format', $xmltable_query, 'XMLTABLE',
	{ 'auto_explain.log_format' => 'json' });

# 6. The companion entry still names the statement, under the stub's token.
{
	my @entries =
	  run_logged($xmltable_query, { log_min_messages => 'debug1' });
	my @recs = records(@entries);
	is(scalar(@recs), 1, 'companion: one record');
	my ($token) = ($recs[0] // '') =~ $stub_re;
	ok(defined $token, 'companion: record is the stub');
	my @companions =
	  grep { defined $token && /auto_explain ref \Q$token\E: SELECT zsec_c/ }
	  @entries;
	is(scalar(@companions), 1,
		'companion: DEBUG1 entry pairs the token with the statement');
}

# 7. Interactive EXPLAIN (REDACT) on the same server keeps the collapse.
{
	my $out = $node->safe_psql('postgres',
		"EXPLAIN (COSTS OFF, VERBOSE, REDACT) $xmltable_query");
	like(
		$out,
		qr/Table Function Call: XMLTABLE\(\.\.\.\)/,
		'interactive: XMLTABLE collapsed');
	unlike($out, qr/zsec/, 'interactive: no fixture name');
	$out = $node->safe_psql('postgres',
		"EXPLAIN (COSTS OFF, VERBOSE, REDACT) $json_table_query");
	like(
		$out,
		qr/Table Function Call: JSON_TABLE\(\.\.\.\)/,
		'interactive: JSON_TABLE collapsed');
}

# 8. Partner: with redaction off the plan is logged in full, as before.
$node->append_conf('postgresql.conf', 'auto_explain.log_redact = off');
$node->reload;
is($node->safe_psql('postgres', 'SHOW auto_explain.log_redact'),
	'off', 'redaction off after reload');
for my $case (
	[ 'XMLTABLE', $xmltable_query, qr/zsec_ns/ ],
	[ 'JSON_TABLE', $json_table_query, qr/zsec_root/ ])
{
	my ($name, $sql, $fixture) = @$case;
	my @recs = records(run_logged($sql));
	is(scalar(@recs), 1, "off, $name: one record");
	like(
		$recs[0] // '',
		qr/LOG:  duration: \d+\.\d+ ms  plan:\n.*Table Function Scan.*Table Function Call: $name\(/s,
		"off, $name: full plan written");
	like($recs[0]   // '', $fixture, "off, $name: names printed");
	unlike($recs[0] // '', qr/plan omitted|ref: /, "off, $name: no stub");
}

$node->stop;
done_testing();
