# Copyright (c) 2021-2026, PostgreSQL Global Development Group
# 007_redact_log_file.pl -- auto_explain.redact_log_file (FR-102).
#
#
# PURPOSE OF THIS FILE
#
# The server log cannot be shared however well its plan records are redacted:
# it also holds failed statements, error messages quoting values, the companion
# entries and the per-line envelope.  redact_log_file sends redacted records to
# a file of their own, which is what gets shared.  This file checks that the
# file holds those records and nothing else, and that the records leave the
# server log:
#
#   - each line of the file is one JSON record with exactly the documented
#     fields, and the plan in it is redacted;
#   - no fixture name, statement text or error text reaches the file, while the
#     server log of the same run shows that each of them was produced;
#   - the record is not in the server log; the DEBUG1 companion still is, with
#     the token found in the file;
#   - the XMLTABLE stub goes to the file too;
#   - concurrent sessions never mix two records on one line;
#   - a renamed file is replaced on the next record (rotation);
#   - a write that fails drops the record, never falls back to the server log,
#     and is reported once;
#   - with redaction off the file is not written and the server log is as
#     before.
#
# Run it with:  make -C contrib/auto_explain check
use strict;
use warnings FATAL => 'all';
use JSON::PP;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('redact_log_file');
$node->init;
$node->append_conf(
	'postgresql.conf', qq{
shared_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
auto_explain.log_analyze = on
auto_explain.log_verbose = on
auto_explain.log_redact = on
auto_explain.redact_log_file = 'redacted_plans.log'
});
$node->start;

my $file = $node->data_dir . '/redacted_plans.log';

$node->safe_psql(
	'postgres', q{
CREATE TABLE zsec_customers (zsec_id int PRIMARY KEY, zsec_ssn text);
INSERT INTO zsec_customers VALUES (1, 'zsec_val_111');
CREATE TABLE zsec_xdocs (zsec_x xml);
});

# Run SQL; return (new server log text, new file lines).
sub run_both
{
	my ($sql, %opt) = @_;
	local $ENV{PGOPTIONS} = join ' ',
	  map { "-c $_=$opt{params}{$_}" } sort keys %{ $opt{params} || {} };
	my $log = $node->logfile;
	my $log_off = -s $log;
	my $file_off = (-e $file) ? -s $file : 0;
	if ($opt{may_fail})
	{
		$node->psql('postgres', $sql);
	}
	else
	{
		$node->safe_psql('postgres', $sql);
	}
	my $text = (-e $file) ? slurp_file($file, $file_off) : '';
	return (slurp_file($log, $log_off), [ split /\n/, $text ]);
}

my $json = JSON::PP->new;

# Parses each line; fails the test for any line that is not exactly one
# record with the documented fields.
sub records_ok
{
	my ($name, $lines) = @_;
	my @recs;
	for my $line (@$lines)
	{
		my $r = eval { $json->decode($line) };
		if (!ref $r)
		{
			fail("$name: line is one JSON record: $line");
			next;
		}
		my $keys = join ',', sort keys %$r;
		ok( $keys eq 'duration_ms,plan,ref,timestamp'
			  || $keys eq 'duration_ms,plan_omitted,ref,timestamp',
			"$name: record has exactly the documented fields ($keys)");
		like($r->{ref}, qr/^[0-9a-f]{16}$/, "$name: ref is a token");
		like(
			$r->{timestamp},
			qr/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/,
			"$name: timestamp is UTC");
		push @recs, $r;
	}
	return @recs;
}

# 1. A plain statement: record in the file, not in the server log.
{
	my ($log, $lines) = run_both(
		q{SELECT zsec_ssn FROM zsec_customers WHERE zsec_ssn = 'zsec_val_111'},
		params => { log_min_messages => 'debug1' });
	is(scalar(@$lines), 1, 'plain: one line in the file');
	my ($r) = records_ok('plain', $lines);
	like(
		$r->{plan} // '',
		qr/Seq Scan on t1 .*Filter: \(\S*t1_c2 = \?::text\)/s,
		'plain: file holds the redacted plan');
	unlike(join("\n", @$lines),
		qr/zsec/, 'plain: no fixture name in the file');
	unlike(
		$log,
		qr/duration: .* plan/,
		'plain: record is not in the server log');
	like(
		$log,
		qr/auto_explain ref \Q$r->{ref}\E: SELECT zsec_ssn/,
		'plain: companion with the same token is in the server log');
	like(
		$log,
		qr/statement: SELECT zsec_ssn/,
		'plain: the server log does carry the statement (log_statement)');
	unlike(
		$log,
		qr/auto_explain.log_redact is enabled, but/,
		'plain: no "same log stream" warnings in file mode');
}

# 2. A failed statement: its text and its error stay in the server log.
{
	my ($log, $lines) =
	  run_both(q{INSERT INTO zsec_customers VALUES (1, 'zsec_val_dup')},
		may_fail => 1);
	like($log, qr/zsec_val_dup/,
		'error: server log carries the failed statement');
	like(
		$log,
		qr/Key \(zsec_id\)=\(1\) already exists/,
		'error: server log carries the error detail');
	unlike(
		join("\n", @$lines),
		qr/zsec|already exists/,
		'error: nothing of it reaches the file');
}

# 3. The XMLTABLE stub goes to the file too.
{
	my ($log, $lines) = run_both(
		q{SELECT zsec_c FROM zsec_xdocs d,
		  XMLTABLE('/zsec_r' PASSING d.zsec_x COLUMNS zsec_c text PATH 'zsec_p') AS zsec_t}
	);
	is(scalar(@$lines), 1, 'stub: one line in the file');
	my ($r) = records_ok('stub', $lines);
	is( $r->{plan_omitted},
		'statement uses XMLTABLE, whose contents cannot be redacted',
		'stub: reason recorded');
	unlike($log, qr/plan omitted/, 'stub: not in the server log');
}

# 4. A name with a newline cannot start a forged record.  The schema is
# allowlisted so its name prints; the record must still be one line.  The
# configuration file spells the newline as the escape \n, which the GUC file
# parser turns into the character; a literal newline cannot be written there.
{
	$node->safe_psql('postgres',
		qq{CREATE SCHEMA "nl\nfake"; CREATE TABLE "nl\nfake".tbl (c int);});
	$node->append_conf('postgresql.conf',
		q{auto_explain.redact_allow_schemas = '"nl\nfake"'});
	$node->reload;
	my ($log, $lines) = run_both(qq{SELECT c FROM "nl\nfake".tbl});
	is(scalar(@$lines), 1, 'newline name: still one line');
	my ($r) = records_ok('newline name', $lines);
	like($r->{plan} // '',
		qr/nl\nfake/,
		'newline name: allowlisted name printed, newline inside the field');
	$node->append_conf('postgresql.conf',
		q{auto_explain.redact_allow_schemas = ''});
	$node->reload;
}

# 5. Concurrent sessions: every line is one whole record.
{
	my $file_off = -s $file;
	$node->pgbench(
		'--no-vacuum --client=8 --transactions=50',
		0,
		[qr{processed: 400/400}],
		[qr{^$}],
		'concurrent: pgbench',
		{
			'007_concurrent' =>
			  q{SELECT zsec_ssn FROM zsec_customers WHERE zsec_id = 1;}
		});
	my @lines = split /\n/, slurp_file($file, $file_off);
	is(scalar(@lines), 400, 'concurrent: one line per statement');
	my $bad = grep {
		!eval { $json->decode($_); 1 }
	} @lines;
	is($bad, 0, 'concurrent: every line parses as one record');
}

# 6. Rotation: rename the file; the next record creates a new one.
{
	rename($file, "$file.1") or die "rename: $!";
	my ($log, $lines) = run_both(q{SELECT 1});
	ok(-e $file, 'rotation: new file created');
	is(scalar(@$lines), 1, 'rotation: record written to the new file');
	my $mode = (stat($file))[2] & 07777;
	is(sprintf('%04o', $mode), '0600',
		'rotation: file mode is log_file_mode');
}

# 7. A write that fails: no record anywhere, one report.
{
	$node->append_conf('postgresql.conf',
		q{auto_explain.redact_log_file = 'no_such_dir/plans.log'});
	$node->reload;
	my $log_off = -s $node->logfile;
	$node->safe_psql('postgres',
		q{SELECT zsec_ssn FROM zsec_customers; SELECT zsec_ssn FROM zsec_customers}
	);
	my $log = slurp_file($node->logfile, $log_off);
	my @reports =
	  ($log =~ /could not write to auto_explain.redact_log_file/g);
	is(scalar(@reports), 1, 'failure: reported once');
	unlike(
		$log,
		qr/duration: .*plan/,
		'failure: no fall back to the server log');
	unlike(
		$log,
		qr/could not write.*\n(?:.*\n)*?.*(?:STATEMENT|CONTEXT):/,
		'failure: report carries no statement or context');
	$node->append_conf('postgresql.conf',
		q{auto_explain.redact_log_file = 'redacted_plans.log'});
	$node->reload;
}

# 8. Redaction off: the file is not written, the server log is as before.
{
	$node->append_conf('postgresql.conf', 'auto_explain.log_redact = off');
	$node->reload;
	my ($log, $lines) = run_both(q{SELECT zsec_ssn FROM zsec_customers});
	is(scalar(@$lines), 0, 'off: nothing written to the file');
	like(
		$log,
		qr/LOG:  duration: \d+\.\d+ ms  plan:\n.*Seq Scan on public.zsec_customers/s,
		'off: unredacted plan in the server log');
}

$node->stop;
done_testing();
