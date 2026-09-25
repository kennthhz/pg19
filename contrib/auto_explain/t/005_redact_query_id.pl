
# Copyright (c) 2026, PostgreSQL Global Development Group

# FR-37 on the redacted record's own log line.
#
# FR-37 leaves Query Identifier out of a redacted plan: the identifier is a
# publicly specified hash of the parse tree, so anyone holding a guessed
# statement can compute it and confirm that the guess ran.  Omitting the plan
# property is not the whole of it.  %Q in log_line_prefix and the query_id field
# of csvlog and jsonlog read the backend's current query identifier at the moment
# a line is written, and with compute_query_id on that is the value the plan
# withholds.  auto_explain therefore clears it for the one ereport that writes a
# redacted record, and puts it back afterwards.
#
# A file of its own rather than more of 002_redact.pl, because jsonlog needs
# logging_collector, and once the collector runs the server log no longer goes to
# the file PostgreSQL::Test::Cluster->logfile names -- the file every helper in
# 002 reads.  Here the log is read from the collector's files, as listed in
# current_logfiles, and each read waits for the collector to catch up.
#
# Every assertion that an identifier is absent is paired with one showing that
# the same identifier is present where redaction does not apply.  Without that,
# compute_query_id quietly not taking effect would make each of them pass.
#
# FR-100 is here too, at the end: no CONTEXT on a redacted record or on
# auto_explain's warnings.  It needs what this file already has -- jsonlog, so
# that "no context field" can be asserted of a field rather than a line, and a
# function whose nested statements are logged -- and its assertions scan whole
# entries, which stderr alone cannot delimit as reliably.

use strict;
use warnings FATAL => 'all';

use JSON::PP;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;
use Time::HiRes qw(usleep);

# The collector's current files, by destination.  current_logfiles is written by
# the collector once it is running, so it may not exist yet right after start.
sub log_files
{
	my ($node) = @_;
	my $path = $node->data_dir . '/current_logfiles';

	foreach (1 .. 10 * $PostgreSQL::Test::Utils::timeout_default)
	{
		if (-f $path)
		{
			my %files;
			foreach my $line (split /\n/, slurp_file($path))
			{
				$files{$1} = $node->data_dir . "/$2"
				  if $line =~ /^(\S+) (.*)$/;
			}
			return \%files if $files{stderr} && $files{jsonlog};
		}
		usleep(100_000);
	}
	die "current_logfiles never listed both a stderr and a jsonlog file";
}

my $end_seq = 0;

# Runs $sql in one session and returns the psql output together with the part of
# each log that the session wrote.
#
# The collector writes asynchronously, so returning from psql does not mean the
# log is complete.  The session therefore ends with a marker statement, and each
# log is read until log_statement's line for the marker has arrived.  One
# backend's messages reach the collector in order, so everything the session
# logged before the marker is then present.  The chunk is cut after the marker's
# line, which also guarantees that no partially written entry is parsed.
#
# $params: GUC name => value, passed through PGOPTIONS as in 002_redact.pl.
sub run_logged
{
	my ($node, $sql, $params) = @_;
	$params ||= {};

	my $files = log_files($node);
	my %offset = map { $_ => (-s $files->{$_}) || 0 } qw(stderr jsonlog);
	my $end = 'zq-end-' . ++$end_seq;

	local $ENV{PGOPTIONS} = join ' ',
	  map { "-c $_=$params->{$_}" } sort keys %$params;
	my $out = $node->safe_psql('postgres', "$sql\nSELECT '$end';");

	foreach (1 .. 10 * $PostgreSQL::Test::Utils::timeout_default)
	{
		my %chunk = (out => $out);
		my $complete = 1;
		foreach my $dest (qw(stderr jsonlog))
		{
			my $text = slurp_file($files->{$dest}, $offset{$dest});
			if ($text =~ /\A(.*?statement: SELECT '\Q$end\E';[^\n]*\n)/s)
			{
				$chunk{$dest} = $1;
			}
			else
			{
				$complete = 0;
			}
		}
		return \%chunk if $complete;
		usleep(100_000);
	}
	die "the logs never showed the end marker $end";
}

# The jsonlog entries in a chunk.
sub json_entries
{
	my ($chunk) = @_;
	return map { decode_json($_) } grep { /^\{/ } split /\n/, $chunk;
}

# Redacted records in a jsonlog chunk: token => query_id.
sub json_redacted_records
{
	my ($chunk) = @_;
	my %rec;
	foreach my $e (json_entries($chunk))
	{
		$rec{$1} = "$e->{query_id}"
		  if $e->{message} =~
		  /^duration: [\d.]+ ms  ref: ([0-9a-f]{16})  plan:/;
	}
	return %rec;
}

# Redacted records in a stderr chunk: token => the value %Q printed.
sub stderr_redacted_records
{
	my ($chunk) = @_;
	my %rec;
	$rec{$2} = $1
	  while $chunk =~
	  /^[^\n]* qid=(-?\d+) [^\n]*LOG:  duration: [\d.]+ ms  ref: ([0-9a-f]{16})  plan:$/mg;
	return %rec;
}

# The one plan line the whole file is keyed on.
my $probe = 'SELECT b FROM zq_t WHERE a = 3;';

# compute_query_id = on    the leak exists only when an identifier is computed
# logging_collector, jsonlog  jsonlog's query_id field is one of the two carriers
# log_line_prefix with %Q  the other carrier.  %q is kept in it, as the test
#                          harness has it, because FR-75 used to warn about %q
#                          and the removal of that warning is tested below.
# log_rotation_*  = 0      a rotation mid-test would move the log from under an
#                          offset taken on the previous file
my $node = PostgreSQL::Test::Cluster->new('redact_query_id');
$node->init;
$node->append_conf(
	'postgresql.conf', q{
session_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
compute_query_id = on
logging_collector = on
log_destination = 'stderr, jsonlog'
log_rotation_age = 0
log_rotation_size = 0
lc_messages = 'C'
log_line_prefix = '%m [%p] qid=%Q %q%a '
});
$node->start;

# run_logged() finds the end of a session's output through log_statement.
is($node->safe_psql('postgres', 'SHOW log_statement'),
	'all', 'log_statement = all, which run_logged() relies on');

$node->safe_psql(
	'postgres', q{
CREATE TABLE zq_t (a int, b text);
INSERT INTO zq_t SELECT g, 'x' || g FROM generate_series(1, 10) g;

-- Reads this backend's query_id before and after running nested statements.
-- pg_stat_activity is read through a per-transaction snapshot, hence the
-- pg_stat_clear_snapshot() between the two reads; without it the second read
-- would return the first one's cached value whatever the backend now holds.
CREATE FUNCTION zq_nested_then_qid(OUT before_qid bigint, OUT after_qid bigint)
LANGUAGE plpgsql AS $$
BEGIN
  SELECT query_id INTO before_qid FROM pg_stat_activity
    WHERE pid = pg_backend_pid();
  PERFORM pg_stat_clear_snapshot();
  PERFORM count(*) FROM zq_t WHERE a > 0;
  SELECT query_id INTO after_qid FROM pg_stat_activity
    WHERE pid = pg_backend_pid();
END $$;
});

# The identifiers the statements under test really have, from EXPLAIN VERBOSE.
# Interactive EXPLAIN is not affected by auto_explain.log_redact.
sub explain_query_id
{
	my ($sql) = @_;
	my $plan =
	  $node->safe_psql('postgres', "EXPLAIN (VERBOSE, COSTS OFF) $sql");
	$plan =~ /^Query Identifier: (-?\d+)$/m
	  or die "EXPLAIN VERBOSE printed no Query Identifier for $sql";
	return $1;
}
my $probe_qid = explain_query_id($probe);
my $outer_sql = 'SELECT before_qid, after_qid FROM zq_nested_then_qid();';
my $outer_qid = explain_query_id($outer_sql);
isnt($probe_qid, '0', 'the probe statement has a query identifier');

# ---------------------------------------------------------------------------
# Redaction off.  These are the anti-vacuity halves: the same configuration, the
# same statement, and the identifier is on the record's line in both carriers.
# They also show that off-mode does not clear it (FR-62).
# ---------------------------------------------------------------------------
my $chunk = run_logged($node, $probe, { 'auto_explain.log_verbose' => 'on' });

my ($off_prefix_qid) = $chunk->{stderr} =~
  /^[^\n]* qid=(-?\d+) [^\n]*LOG:  duration: [\d.]+ ms  plan:\n\tQuery Text: \Q$probe\E\n/m;
is($off_prefix_qid, $probe_qid,
	'unredacted: %Q prints the query identifier on the record line');

my @off_json =
  grep {
	$_->{message} =~ /^duration: [\d.]+ ms  plan:\nQuery Text: \Q$probe\E\n/
  } json_entries($chunk->{jsonlog});
is(scalar(@off_json), 1, 'unredacted: one jsonlog record for the probe');
is("$off_json[0]{query_id}", $probe_qid,
	'unredacted: the jsonlog record carries the query identifier');

# ---------------------------------------------------------------------------
# Redaction on.
# ---------------------------------------------------------------------------
$node->append_conf('postgresql.conf', 'auto_explain.log_redact = on');
$node->reload;
$node->poll_query_until('postgres', 'SHOW auto_explain.log_redact', 'on')
  or die 'auto_explain.log_redact did not become on after reload';

# DEBUG1 turns on the companion entry, which is what ties a redacted record to
# the probe: it pairs the record's token with the statement.  It also supplies
# an anti-vacuity half inside the very same session -- the companion is written
# by the same backend, for the same statement, immediately before the record,
# and it keeps its identifier.
$chunk = run_logged(
	$node, $probe,
	{
		'auto_explain.log_verbose' => 'on',
		'log_min_messages' => 'debug1'
	});

my ($token, $companion_json_qid);
foreach my $e (json_entries($chunk->{jsonlog}))
{
	if ($e->{message} =~ /^auto_explain ref ([0-9a-f]{16}): \Q$probe\E$/)
	{
		$token = $1;
		$companion_json_qid = "$e->{query_id}";
	}
}
ok(defined $token, 'redacted: the companion entry names the probe');

my %json_rec = json_redacted_records($chunk->{jsonlog});
is($json_rec{$token}, '0',
	'redacted: the record\'s jsonlog entry carries no query identifier');
is($companion_json_qid, $probe_qid,
	'redacted: the companion entry in the same session still carries it');
is_deeply([ grep { $_ ne '0' } values %json_rec ],
	[], 'redacted: no redacted jsonlog record carries a nonzero query_id');

my %stderr_rec = stderr_redacted_records($chunk->{stderr});
is($stderr_rec{$token}, '0',
	'redacted: %Q prints no query identifier on the record line');
my ($companion_prefix_qid) =
  $chunk->{stderr} =~
  /^[^\n]* qid=(-?\d+) [^\n]*DEBUG:  auto_explain ref \Q$token\E: /m;
is($companion_prefix_qid, $probe_qid,
	'redacted: %Q still prints it on the companion line of the same session');

# ---------------------------------------------------------------------------
# Restore.  Under log_nested_statements a nested record is written while the
# outer statement is still running, and the identifier cleared for it is the
# outer statement's.  The function reads its own backend's query_id before and
# after its nested statements; both reads must return the outer statement's.
#
# before_qid alone would not show much: it is read before any nested record is
# written.  after_qid is the one that fails without a correct restore, and not
# as zero: a clear left in place is overwritten by the next nested statement's
# ExecutorStart, since a zero identifier reads as "no top-level statement yet".
# So after_qid is compared against the outer statement's own identifier, not
# merely against zero.
# ---------------------------------------------------------------------------
$chunk = run_logged($node, $outer_sql,
	{ 'auto_explain.log_nested_statements' => 'on' });

my ($before, $after) = $chunk->{out} =~ /^(-?\d+)\|(-?\d+)$/m;
is($before, $outer_qid,
	'restore: the function sees the outer statement\'s query identifier');
is($after, $outer_qid,
	'restore: after redacted nested records, the outer identifier is back');

# Anti-vacuity: nested records really were written, redacted, with the
# identifier cleared on their lines.  The records that must exist are the outer
# statement's, the second SELECT INTO's, and at least one written before the
# second read -- otherwise nothing was cleared that a restore could have got
# wrong.  Hence at least three.  (This tree logs five: each of the four
# statements in the body, the PERFORM of pg_stat_clear_snapshot() included, and
# the outer one.  The bound is the logical minimum rather than that count, so
# that a change in how PL/pgSQL runs simple expressions does not break it.)
%stderr_rec = stderr_redacted_records($chunk->{stderr});
cmp_ok(scalar(keys %stderr_rec), '>=', 3,
	'restore: the nested and outer statements were logged as redacted records'
);
is_deeply([ grep { $_ ne '0' } values %stderr_rec ],
	[], 'restore: every one of them was written with %Q cleared');

# ---------------------------------------------------------------------------
# track_activities = off.  pgstat_report_query_id() then does nothing and the
# backend entry holds no identifier at all, so the save and restore are both
# no-ops.  The statement must still succeed and log its record.
# ---------------------------------------------------------------------------
$chunk = run_logged($node, $probe, { 'track_activities' => 'off' });
%stderr_rec = stderr_redacted_records($chunk->{stderr});
%json_rec = json_redacted_records($chunk->{jsonlog});
cmp_ok(scalar(keys %stderr_rec),
	'>=', 1, 'track_activities off: the redacted record is still written');
is_deeply([ grep { $_ ne '0' } (values %stderr_rec, values %json_rec) ],
	[], 'track_activities off: no identifier on the record line either');

# ---------------------------------------------------------------------------
# FR-75 no longer warns about %q.  %q prints nothing, so a warning that it
# "carries the current statement" was false.  Asserted against a session where
# the envelope check demonstrably ran and reported the other three settings, so
# the absence is of this one warning and not of the check.
# ---------------------------------------------------------------------------
like($node->safe_psql('postgres', 'SHOW log_line_prefix'),
	qr/%q/, 'log_line_prefix contains %q');

$chunk = run_logged(
	$node, $probe,
	{
		'log_min_duration_statement' => '0',
		'log_min_messages' => 'debug1'
	});
like(
	$chunk->{stderr},
	qr/log_redact is enabled, but log_statement is also active/,
	'FR-75: log_statement is still reported');
like(
	$chunk->{stderr},
	qr/log_redact is enabled, but log_min_duration_statement is also active/,
	'FR-75: log_min_duration_statement is still reported');
like(
	$chunk->{stderr},
	qr/log_redact is enabled, but a log level of debug1 or lower is also active/,
	'FR-75: companion entries being logged are still reported');
unlike(
	$chunk->{stderr},
	qr/log_redact is enabled, but a log_line_prefix|carries the current statement/,
	'FR-75: a log_line_prefix containing %q is not reported');

# ---------------------------------------------------------------------------
# The remaining blocks set up what they need themselves, rather than relying on
# the state the blocks above leave behind, and put it back afterwards.
# ---------------------------------------------------------------------------

# Sets a PGC_SIGHUP parameter through postgresql.conf and a reload, and waits
# until a new session sees it.  Returns the value it replaced.
sub set_by_reload
{
	my ($name, $value) = @_;
	my $old = $node->safe_psql('postgres', "SHOW $name");
	$node->append_conf('postgresql.conf', "$name = '$value'");
	$node->reload;
	$node->poll_query_until('postgres', "SHOW $name", $value)
	  or die "$name did not become '$value' after reload";
	return $old;
}

# Runs $code with the PGC_SIGHUP parameters in %$settings in effect, then
# restores each one to the value it had before.
sub with_reloaded
{
	my ($settings, $code) = @_;
	my %old = map { $_ => set_by_reload($_, $settings->{$_}) }
	  sort keys %$settings;
	$code->();
	set_by_reload($_, $old{$_}) foreach sort keys %old;
	return;
}

# Companion entries in a stderr chunk: token => the value %Q printed.
sub stderr_companions
{
	my ($chunk) = @_;
	my %comp;
	$comp{$2} = $1
	  while $chunk =~
	  /^[^\n]* qid=(-?\d+) [^\n]*DEBUG:  auto_explain ref ([0-9a-f]{16}): /mg;
	return %comp;
}

# Companion entries in a jsonlog chunk: token => query_id.
sub json_companions
{
	my ($chunk) = @_;
	my %comp;
	foreach my $e (json_entries($chunk))
	{
		$comp{$1} = "$e->{query_id}"
		  if $e->{message} =~ /^auto_explain ref ([0-9a-f]{16}): /;
	}
	return %comp;
}

# auto_explain's own warning about $setting: [ %Q on its stderr line, jsonlog
# query_id ].  Either is undef if that carrier has no such line.
sub warning_qids
{
	my ($chunk, $setting) = @_;
	my $msg =
	  "auto_explain.log_redact is enabled, but $setting is also active";
	my ($prefix_qid) =
	  $chunk->{stderr} =~ /^[^\n]* qid=(-?\d+) [^\n]*LOG:  \Q$msg\E$/m;
	my @json =
	  map { "$_->{query_id}" }
	  grep { $_->{message} eq $msg } json_entries($chunk->{jsonlog});
	return [ $prefix_qid, $json[0] ];
}

# ---------------------------------------------------------------------------
# track_activities turned off partway through a statement.  It is a superuser
# setting, so a function can SET LOCAL it.  pgstat_report_query_id() then does
# nothing at all, while pgstat_get_my_query_id() -- which is what %Q and the
# csvlog/jsonlog field read -- goes on returning the identifier stored for the
# outer statement before the setting changed.  A clear made through
# pgstat_report_query_id() was therefore a no-op, and every record written
# after the SET LOCAL printed the outer statement's identifier.
#
# The present half is in the same session: each record's companion entry,
# written by the same backend immediately before it, still carries the outer
# identifier.  That shows the backend really was holding it when the record was
# written, so the zero on the record's line is the clear and not merely a
# consequence of track_activities being off.
#
# The function also reads its own query_id before and after the nested
# statements, as the restore test above does.  Here a restore that went through
# pgstat_report_query_id() would leave the clear in place for good, since no
# later nested statement reports anything either, so after_qid would read NULL.
# ---------------------------------------------------------------------------
with_reloaded(
	{ 'auto_explain.log_redact' => 'on' },
	sub {
		$node->safe_psql(
			'postgres', q{
CREATE FUNCTION zq_untracked_then_qid(OUT tracking text,
    OUT before_qid bigint, OUT after_qid bigint)
LANGUAGE plpgsql AS $$
BEGIN
  SET LOCAL track_activities = off;
  tracking := current_setting('track_activities');
  SELECT query_id INTO before_qid FROM pg_stat_activity
    WHERE pid = pg_backend_pid();
  PERFORM pg_stat_clear_snapshot();
  PERFORM count(*) FROM zq_t WHERE a > 1;
  SELECT query_id INTO after_qid FROM pg_stat_activity
    WHERE pid = pg_backend_pid();
END $$;
});
		my $sql =
		  'SELECT tracking, before_qid, after_qid FROM zq_untracked_then_qid();';
		my $qid = explain_query_id($sql);

		my $chunk = run_logged(
			$node, $sql,
			{
				'auto_explain.log_nested_statements' => 'on',
				'log_min_messages' => 'debug1'
			});

		my ($tracking, $before, $after) =
		  $chunk->{out} =~ /^(\w+)\|(-?\d*)\|(-?\d*)$/m;
		is($tracking, 'off',
			'untracked: SET LOCAL turned track_activities off in the function'
		);

		my %rec = stderr_redacted_records($chunk->{stderr});
		my %comp = stderr_companions($chunk->{stderr});
		cmp_ok(scalar(keys %rec), '>=', 3,
			'untracked: the nested and outer statements were logged redacted'
		);
		is_deeply([ grep { $_ ne '0' } values %rec ],
			[], 'untracked: %Q prints 0 on every redacted record line');
		is_deeply(
			[ sort keys %comp ],
			[ sort keys %rec ],
			'untracked: every redacted record has its companion entry');
		is_deeply(
			[ grep { $_ ne $qid } values %comp ],
			[],
			'untracked: %Q still prints the outer identifier on every companion line'
		);

		my %jrec = json_redacted_records($chunk->{jsonlog});
		my %jcomp = json_companions($chunk->{jsonlog});
		cmp_ok(scalar(keys %jrec),
			'>=', 3, 'untracked: jsonlog has the redacted records too');
		is_deeply([ grep { $_ ne '0' } values %jrec ],
			[], 'untracked: every redacted jsonlog record has query_id 0');
		is_deeply(
			[ grep { !defined $jcomp{$_} || $jcomp{$_} ne $qid } keys %jrec ],
			[],
			'untracked: every jsonlog companion still carries the outer identifier'
		);

		is($before, $qid,
			'untracked: the function sees the outer statement\'s query identifier'
		);
		is($after, $qid,
			'untracked: after redacted nested records, the outer identifier is back'
		);
	});

# ---------------------------------------------------------------------------
# auto_explain's own warnings.  They are written during the statement whose
# record follows, so they carried its identifier.  For most of them that told
# nothing new -- the setting they name already logs the whole statement -- but
# the allowlist and log_extension_options warnings put one identifier in the
# log with nothing else to account for it.  Every warning is cleared the same
# way, so all of them are checked here, not only those two.
#
# The present half is the probe's companion entry in the same session: it is
# written after the warnings and before the record, and keeps the identifier.
# ---------------------------------------------------------------------------
with_reloaded(
	{
		'auto_explain.log_redact' => 'on',
		'auto_explain.redact_allow_schemas' => 'public'
	},
	sub {
		my $chunk =
		  run_logged($node, $probe, { 'log_min_messages' => 'debug1' });

		my $w = warning_qids($chunk,
			'"public" in auto_explain.redact_allow_schemas');
		is($w->[0], '0',
			'allowlist warning: %Q prints 0 on the warning line');
		is($w->[1], '0', 'allowlist warning: its jsonlog query_id is 0');

		my %comp = json_companions($chunk->{jsonlog});
		my %scomp = stderr_companions($chunk->{stderr});
		is_deeply(
			[ values %comp ],
			[$probe_qid],
			'allowlist warning: the companion in the same session carries the identifier (jsonlog)'
		);
		is_deeply(
			[ values %scomp ],
			[$probe_qid],
			'allowlist warning: the companion in the same session carries the identifier (%Q)'
		);

		# The uniform rule: every warning in the session, whatever it names.
		my @all = $chunk->{stderr} =~
		  /^[^\n]* qid=(-?\d+) [^\n]*LOG:  auto_explain\.log_redact is enabled, but /mg;
		cmp_ok(scalar(@all), '>=', 3,
			'all warnings: log_statement, debug1 and the allowlist were reported'
		);
		is_deeply([ grep { $_ ne '0' } @all ],
			[], 'all warnings: %Q prints 0 on every one of them');
	});

# The log_extension_options warning.  pg_overexplain registers the option, and
# is loaded ahead of auto_explain for this session only so that the option
# passes auto_explain's check hook; nothing else in the file loads it.
with_reloaded(
	{ 'auto_explain.log_redact' => 'on' },
	sub {
		my $chunk = run_logged(
			$node, $probe,
			{
				'session_preload_libraries' => 'pg_overexplain,auto_explain',
				'auto_explain.log_extension_options' => 'range_table',
				'log_min_messages' => 'debug1'
			});

		my $w = warning_qids($chunk, 'auto_explain.log_extension_options');
		is($w->[0], '0',
			'extension options warning: %Q prints 0 on the warning line');
		is($w->[1], '0',
			'extension options warning: its jsonlog query_id is 0');

		my %comp = json_companions($chunk->{jsonlog});
		my %scomp = stderr_companions($chunk->{stderr});
		is_deeply(
			[ values %comp ],
			[$probe_qid],
			'extension options warning: the companion in the same session carries the identifier (jsonlog)'
		);
		is_deeply(
			[ values %scomp ],
			[$probe_qid],
			'extension options warning: the companion in the same session carries the identifier (%Q)'
		);
	});


# ---------------------------------------------------------------------------
# FR-100: no CONTEXT on a redacted record or on auto_explain's warnings.
#
# Under log_nested_statements a nested plan is logged while PL/pgSQL's
# error-context callback is active, and the callback attaches the nested
# statement's SQL, verbatim, and the function's name to whatever is reported.
# That arrived on the CONTEXT: line in stderr and in the context field of
# jsonlog, inside the record that was meant to be redacted.  Nothing noticed,
# because the checks examined only the plan lines.
#
# Here, then, whole entries are examined: every line of a stderr entry and
# every field of a jsonlog entry.  The markers are the fixture's own names, all
# of which begin "zq_".  Each absence is paired with a presence in the same
# configuration, so that PL/pgSQL no longer setting context, or the entry
# reader cutting entries short, would fail the test rather than pass it.
# ---------------------------------------------------------------------------

# Fixture names found in $text: sorted, lower-cased, de-duplicated.
sub zq_names
{
	my ($text) = @_;
	my %seen;
	$seen{ lc($1) } = 1 while $text =~ /(zq_[a-z0-9_]*)/gi;
	return [ sort keys %seen ];
}

# The whole stderr entries in a chunk, each with every line it wrote.  An entry
# starts on a prefixed line whose severity is a message level; prefixed lines
# naming a secondary field (DETAIL, CONTEXT, ...) and tab-indented
# continuations belong to the entry above them.
sub stderr_entries
{
	my ($chunk) = @_;
	my @entries;
	foreach my $line (split /\n/, $chunk)
	{
		if ($line =~
			/^\S+ \S+ \S+ \[\d+\] qid=-?\d+ [^\n]*? ([A-Z]+[0-9]?):  /
			&& $1 =~
			/^(?:DEBUG[1-5]?|LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC)$/)
		{
			push @entries, "$line\n";
		}
		elsif (@entries)
		{
			$entries[-1] .= "$line\n";
		}
	}
	return @entries;
}

# The one jsonlog entry whose message matches $re, and the one stderr entry
# whose text matches $re.  Exactly one, because a pattern that matched none
# would turn every assertion on the result into one about nothing.
sub json_entry
{
	my ($chunk, $re) = @_;
	my @e = grep { $_->{message} =~ $re } json_entries($chunk);
	die "expected one jsonlog entry matching $re, found " . scalar(@e)
	  unless @e == 1;
	return $e[0];
}

sub stderr_entry
{
	my ($chunk, $re) = @_;
	my @e = grep { $_ =~ $re } stderr_entries($chunk);
	die "expected one stderr entry matching $re, found " . scalar(@e)
	  unless @e == 1;
	return $e[0];
}

my $nested_sql = 'SELECT count(*) FROM zq_t WHERE a > 0';
my $warning_re = qr/auto_explain\.log_redact is enabled, but /;

# Redaction off: the anti-vacuity halves.  The same function, the same nested
# statement, and CONTEXT names both.  This is also FR-62 for the unredacted
# record: it keeps its CONTEXT.
with_reloaded(
	{ 'auto_explain.log_redact' => 'off' },
	sub {
		my $chunk = run_logged($node, $outer_sql,
			{ 'auto_explain.log_nested_statements' => 'on' });

		my $re =
		  qr/^duration: [\d.]+ ms  plan:\nQuery Text: \Q$nested_sql\E\n/;
		my $json = json_entry($chunk->{jsonlog}, $re);
		like(
			$json->{context} // '',
			qr/^SQL statement "\Q$nested_sql\E"\nPL\/pgSQL function zq_nested_then_qid\(\) line \d+ at PERFORM$/,
			'FR-100 off: the nested record\'s jsonlog context names the SQL and the function'
		);

		my $entry =
		  stderr_entry($chunk->{stderr}, qr/\tQuery Text: \Q$nested_sql\E\n/);
		like(
			$entry,
			qr/^[^\n]* CONTEXT:  SQL statement "\Q$nested_sql\E"\n\tPL\/pgSQL function zq_nested_then_qid\(\) line \d+ at PERFORM$/m,
			'FR-100 off: the nested record\'s stderr entry has a CONTEXT line naming both'
		);
		is_deeply(
			zq_names(encode_json($json)),
			[ 'zq_nested_then_qid', 'zq_t' ],
			'FR-100 off: the whole-entry scan finds both fixture names');
		unlike($chunk->{stderr}, $warning_re,
			'FR-100 off: no redaction warnings are written');
	});

# Redaction on.  DEBUG1 turns on the companion entries, which identify the
# nested statement's record by its token and supply the same-session presence
# halves: each companion is written by the same backend, in the same context,
# immediately before its record.
with_reloaded(
	{ 'auto_explain.log_redact' => 'on' },
	sub {
		my $chunk = run_logged(
			$node,
			$outer_sql,
			{
				'auto_explain.log_nested_statements' => 'on',
				'log_min_messages' => 'debug1'
			});
		my @json = json_entries($chunk->{jsonlog});
		my @stderr = stderr_entries($chunk->{stderr});

		# The nested statement's companion, and through its token the record.
		my $comp = json_entry($chunk->{jsonlog},
			qr/^auto_explain ref [0-9a-f]{16}: \Q$nested_sql\E$/);
		my ($token) = $comp->{message} =~ /^auto_explain ref ([0-9a-f]{16}):/;
		my $rec = json_entry($chunk->{jsonlog},
			qr/^duration: [\d.]+ ms  ref: \Q$token\E  plan:/);
		my $rec_stderr =
		  stderr_entry($chunk->{stderr}, qr/ref: \Q$token\E  plan:/);

		ok( !exists $rec->{context},
			'FR-100 on: the nested record\'s jsonlog entry has no context field'
		);
		unlike($rec_stderr, qr/CONTEXT:/,
			'FR-100 on: the nested record\'s stderr entry has no CONTEXT line'
		);

		# The companion keeps its CONTEXT, deliberately.  Also the presence
		# half for the two assertions above: the context stack was live at
		# the moment the record was written.
		like(
			$comp->{context} // '',
			qr/^SQL statement "\Q$nested_sql\E"\nPL\/pgSQL function zq_nested_then_qid\(\) line \d+ at PERFORM$/,
			'FR-100 on: the companion entry still carries the nested CONTEXT (jsonlog)'
		);
		like(
			stderr_entry(
				$chunk->{stderr}, qr/DEBUG:  auto_explain ref \Q$token\E: /),
			qr/^[^\n]* CONTEXT:  SQL statement "\Q$nested_sql\E"\n\tPL\/pgSQL function zq_nested_then_qid\(\) line \d+ at PERFORM$/m,
			'FR-100 on: the companion entry still carries the nested CONTEXT (stderr)'
		);

		# No fixture name anywhere in any redacted record's whole entry:
		# message, detail, context, every jsonlog field, every stderr line.
		my @rec_json =
		  grep {
			$_->{message} =~ /^duration: [\d.]+ ms  ref: [0-9a-f]{16}  plan:/
		  } @json;
		my @rec_stderr =
		  grep {
			/\A[^\n]*LOG:  duration: [\d.]+ ms  ref: [0-9a-f]{16}  plan:$/m
		  } @stderr;
		cmp_ok(scalar(@rec_json), '>=', 3,
			'FR-100 on: the nested and outer statements were logged redacted'
		);
		is(scalar(@rec_stderr), scalar(@rec_json),
			'FR-100 on: stderr has the same redacted records as jsonlog');
		is_deeply(zq_names(join "\n", map { encode_json($_) } @rec_json),
			[], 'FR-100 on: no fixture name in any redacted jsonlog entry');
		is_deeply(zq_names(join '', @rec_stderr),
			[], 'FR-100 on: no fixture name in any redacted stderr entry');

		# The presence half of the scan, same session: the companions hold
		# both names, one in the message and one in the context.
		is_deeply(
			zq_names(
				join "\n",
				map    { encode_json($_) }
				  grep { $_->{message} =~ /^auto_explain ref / } @json),
			[ 'zq_nested_then_qid', 'zq_t' ],
			'FR-100 on: the same scan finds both names in the companions');

		# The warnings.  The session's first redacted record is the function's
		# first nested statement, so they are written inside its PL/pgSQL
		# context: the entry right after the last of them is that statement's
		# companion, and its context names the function.
		my @warn_idx = grep { $json[$_]{message} =~ $warning_re } 0 .. $#json;
		cmp_ok(scalar(@warn_idx), '>=', 2,
			'FR-100 on: log_statement and debug1 were both warned about');
		my $after = $json[ $warn_idx[-1] + 1 ];
		like(
			$after->{message} . "\n" . ($after->{context} // ''),
			qr/^auto_explain ref [0-9a-f]{16}: .*\nSQL statement ".*"\nPL\/pgSQL function zq_nested_then_qid\(\) line \d+ at /s,
			'FR-100 on: the warnings were written inside the nested statement\'s context'
		);
		is_deeply([ grep { exists $json[$_]{context} } @warn_idx ],
			[], 'FR-100 on: no warning\'s jsonlog entry has a context field');
		my @warn_stderr = grep { /\A[^\n]*LOG:  $warning_re/ } @stderr;
		is(scalar(@warn_stderr), scalar(@warn_idx),
			'FR-100 on: stderr has the same warnings as jsonlog');
		is_deeply([ grep { /CONTEXT:/ } @warn_stderr ],
			[], 'FR-100 on: no warning\'s stderr entry has a CONTEXT line');
		is_deeply(
			zq_names(
				join "\n", (map { encode_json($json[$_]) } @warn_idx),
				@warn_stderr),
			[],
			'FR-100 on: no fixture name in any warning entry');
	});

done_testing();
