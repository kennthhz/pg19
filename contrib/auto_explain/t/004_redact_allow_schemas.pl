# Copyright (c) 2021-2026, PostgreSQL Global Development Group

# 004_redact_allow_schemas.pl -- auto_explain.redact_allow_schemas (T22, FR-51).
#
#
# PURPOSE OF THIS FILE
#
# Every other test in this feature checks that redaction WITHHOLDS something.
# This one checks the single setting that gives something back: an administrator
# names a schema, and objects in that schema print their real names again, while
# everything else stays redacted (FR-51/D7).
#
# That direction is why the file exists separately and why its assertions are
# shaped the way they are.  A test for "the real name is printed" is satisfied by
# a plan that never mentions the object at all -- the name is absent, the regex
# for the pseudonym does not match either, and nothing notices.  So every
# assertion here is a CONTRAST inside ONE record: the allowlisted relation by its
# real name, beside a non-allowlisted relation of the same query printed as a
# pseudonym.  If either half is missing the pair fails.
#
# Run it with:  make -C contrib/auto_explain check
#
#
# WHY THE ALLOWLISTED FIXTURE CARRIES NO MARKER
#
# The other files in this directory name every fixture object "zsec_*" so that a
# leak reduces to grepping for the marker.  The allowlisted objects here are
# deliberately NOT marked, and that is forced rather than stylistic: in an
# assert-enabled build the tripwire in explain_redact.c raises an ERROR the moment
# a marked string reaches output under redaction, and an allowlisted object's real
# name reaching output is exactly what this file is testing.  A marked allowlist
# fixture therefore does not produce a record to assert on; it produces a failed
# statement.
#
# The marker discipline is kept where it still works: the non-allowlisted side of
# every query is marked, so leaked() must come back EMPTY even in the widened
# case, and the widening is asserted by name instead.  That split is also the
# stronger claim -- "the allowlist exempted this schema and nothing else".
#
#
# PGC_SIGHUP
#
# The setting is PGC_SIGHUP (D9), so every change below is written to
# postgresql.conf and applied with a reload; PGOPTIONS would be refused.  That is
# load-bearing for the same reason it is for log_redact: a session that could
# widen its own allowlist could disclose its own schema into the log, through a
# setting whose name does not mention redaction.  Each phase proves the reload
# took effect with SHOW before asserting anything, because a silently ignored
# setting would make the "still redacted" assertions pass for the wrong reason.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Runs one or more statements and returns only the log output they produced.
# Shares its shape with 002_redact.pl: the byte offset taken before the statement
# runs is what makes each assertion independent of the rest of the file.
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

# Returns only the auto_explain plan records from a log chunk.
#
# As in 002_redact.pl: the cluster logs every statement in full (Cluster.pm sets
# log_statement = all), so an assertion about what redaction did has to be
# scoped to the record redaction produced.  Dies
# rather than returning empty, because an empty return would turn every
# assertion built on it into a tautology -- which is the specific failure this
# file is most exposed to.
sub plan_record
{
	my ($log) = @_;
	my @kept;
	my $in_record = 0;

	foreach my $line (split /\n/, $log)
	{
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

	die "plan_record() found no auto_explain record in this log chunk; "
	  . "has the record's message format changed?"
	  unless @kept;

	return join("\n", @kept) . "\n";
}

# The marker strings that leaked.  Mirrors leaked() in 002_redact.pl.
sub leaked
{
	my ($log) = @_;
	my %seen;

	$seen{ lc($1) } = 1
	  while $log =~ /(zsec_[a-z0-9_]*|zsecdata-[a-z0-9-]*)/gi;
	return sort keys %seen;
}

# Rewrites the allowlist in postgresql.conf and reloads.
#
# Written as one helper because the three steps belong together: a phase that
# changed the file without reloading, or reloaded without checking, would assert
# against the previous setting.  Returns SHOW's answer so the caller can prove
# the change landed.
sub set_allowlist
{
	my ($node, $value) = @_;

	$node->append_conf('postgresql.conf',
		"auto_explain.redact_allow_schemas = '$value'");
	$node->reload;

	return $node->safe_psql('postgres',
		'SHOW auto_explain.redact_allow_schemas');
}

# ---------------------------------------------------------------------------
# The cluster.  Redaction on from the start -- the allowlist does nothing without
# it, and this file has nothing to say about the unredacted channel.
# ---------------------------------------------------------------------------
my $node = PostgreSQL::Test::Cluster->new('redact_allow');
$node->init;
$node->append_conf(
	'postgresql.conf', qq{
session_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
auto_explain.log_redact = on
});
$node->start;

# ---------------------------------------------------------------------------
# Fixture.  Two schemas, so that one query produces one record naming an object
# from each.
#
#   trustedext  stands in for the trusted extension schema FR-51 exists to serve.
#               Its objects are UNMARKED, for the reason in the header comment.
#   zsec_app    stands in for the application.  Marked, so leaked() can see it.
#
# Seeded on both sides: a join of two empty tables can be planned without a hash
# and the two-relation record the contrast assertions need would not appear.
# ---------------------------------------------------------------------------
$node->safe_psql(
	'postgres', q{
CREATE SCHEMA trustedext;
CREATE SCHEMA zsec_app;

CREATE TABLE trustedext.trusted_tbl (trusted_col int);
CREATE TABLE zsec_app.zsec_app_tbl (zsec_app_col int);

INSERT INTO trustedext.trusted_tbl SELECT g FROM generate_series(1, 50) g;
INSERT INTO zsec_app.zsec_app_tbl SELECT g FROM generate_series(1, 50) g;
ANALYZE trustedext.trusted_tbl;
ANALYZE zsec_app.zsec_app_tbl;
});

# The two-relation query every phase runs.  Kept in one variable so that the
# phases differ only in the setting, which is what makes the comparison between
# them mean anything.
my $join_query = q{
SELECT e.trusted_col, a.zsec_app_col
  FROM trustedext.trusted_tbl e
  JOIN zsec_app.zsec_app_tbl a ON e.trusted_col = a.zsec_app_col
 WHERE e.trusted_col > 5};

# The marked side really is marked, so the "no marker survived" assertions below
# have something to fail on.  Without this the whole file could pass against a
# fixture whose app table was named without the prefix.
my $unmarked = $node->safe_psql(
	'postgres', q{
SELECT coalesce(string_agg(kind || ':' || name, ', '), '') FROM (
    SELECT 'relation' AS kind, c.relname::text AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zsec_app'
    UNION ALL
    SELECT 'column', a.attname::text
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zsec_app' AND a.attnum > 0 AND NOT a.attisdropped
) obj
 WHERE name !~ '^zsec_' });
is($unmarked, '',
	'the non-allowlisted fixture carries the marker, so leaked() can see it');

# ---------------------------------------------------------------------------
# PHASE 0: the default.  Empty, and therefore exempting nothing.
#
# This phase is what makes every later "the real name printed" assertion
# attributable to the allowlist rather than to some unrelated property of the
# relation: the same query, the same record shape, and the name is a pseudonym.
# ---------------------------------------------------------------------------
is( $node->safe_psql('postgres', 'SHOW auto_explain.redact_allow_schemas'),
	'',
	'FR-51: the allowlist is empty by default, so T22 widens nothing until asked'
);

my $log = query_log($node, $join_query);
my $rec = plan_record($log);

unlike($rec, qr/trusted_tbl/,
	'default: the trusted schema is not exempt, so its relation is a pseudonym'
);
is_deeply([ leaked($rec) ],
	[], 'default: the application relation is redacted too');

# Anti-vacuity for both of the above: the record must actually name two
# relations.  Without this the pair passes against a record that mentions no
# relation at all -- which is precisely what a broken plan_record() or a
# mis-specified query would produce.
my @pseudo_scans = ($rec =~ /Seq Scan on (t\d+)/g);
is(scalar(@pseudo_scans), 2,
	"default: both relations are named, as pseudonyms (@pseudo_scans)");

# ---------------------------------------------------------------------------
# PHASE 1: the allowlist proper.  One schema exempt, the other not, in one
# record.
# ---------------------------------------------------------------------------
is(set_allowlist($node, 'trustedext'),
	'trustedext',
	'FR-51/D9: the allowlist is settable by reload, as PGC_SIGHUP requires');

$log = query_log($node, $join_query);
$rec = plan_record($log);

like(
	$rec,
	qr/Seq Scan on trusted_tbl /,
	'FR-51: an allowlisted schema\'s relation prints its real name');

# The other half of the same record.  Asserted separately from the line above so
# a failure says which half went wrong, and asserted at all because "the real
# name printed" on its own is also satisfied by redaction having stopped working.
like(
	$rec,
	qr/Seq Scan on t\d+ /,
	'FR-51: a non-allowlisted relation in the SAME record is still a pseudonym'
);
unlike($rec, qr/zsec_app_tbl|zsec_app_col/,
	'FR-51: the non-allowlisted relation and column names do not appear');
is_deeply([ leaked($rec) ],
	[], 'FR-51: the allowlist exempts the schema it names and nothing else');

# The strongest single assertion in the file: both namings on one line, so the
# contrast cannot be an artefact of comparing two different records or two
# different runs.  The exempt relation's column is real, the other relation's is
# an opaque per-relation counter, and the aliases are pseudonyms on both sides --
# a user's alias is the user's text whatever schema the relation lives in.
like(
	$rec,
	qr/Hash Cond: \(a\d+\.trusted_col = a\d+\.a\d+_c\d+\)/,
	'FR-51: one expression carries the exempt real name beside a pseudonymized one'
);

# The allowlist exempts NAMES, never DATA: the literal in the filter is still
# suppressed on the exempt relation.  Anchored on the exempt relation's own
# column so it cannot match the other side's filter.
like(
	$rec,
	qr/Filter: \(trusted_col > \?::integer\)/,
	'FR-51: constants are still redacted on an exempt relation');

# ---------------------------------------------------------------------------
# PHASE 2: normalisation.  The engine compares schema names to catalog names with
# strcmp(), so the GUC parser has to produce catalog-normalised names -- which is
# why the check hook uses SplitIdentifierString() rather than splitting on commas.
#
# The pair is the test: unquoted UPPER must exempt (it downcases, as the catalog
# did), and quoted UPPER must NOT (the catalog holds no such schema).  Either
# assertion alone is weak -- the first passes if normalisation is skipped for
# everything, the second passes if the allowlist is broken entirely.
# ---------------------------------------------------------------------------
is(set_allowlist($node, 'TRUSTEDEXT'),
	'TRUSTEDEXT', 'normalisation: the value is stored as written');

$rec = plan_record(query_log($node, $join_query));
like(
	$rec,
	qr/Seq Scan on trusted_tbl /,
	'normalisation: an unquoted name is downcased, so TRUSTEDEXT exempts trustedext'
);
like(
	$rec,
	qr/Seq Scan on t\d+ /,
	'normalisation: the other relation is still a pseudonym');

is(set_allowlist($node, '"TRUSTEDEXT"'),
	'"TRUSTEDEXT"',
	'normalisation: a quoted element survives the round trip');

$rec = plan_record(query_log($node, $join_query));
unlike($rec, qr/trusted_tbl/,
	'normalisation: a quoted name is taken verbatim, so "TRUSTEDEXT" matches no schema'
);
@pseudo_scans = ($rec =~ /Seq Scan on (t\d+)/g);
is(scalar(@pseudo_scans), 2,
	"normalisation: with nothing exempt both relations are pseudonyms (@pseudo_scans)"
);

# ---------------------------------------------------------------------------
# PHASE 3: removal re-redacts (FR-60, and §1.1 of the task plan).
#
# The allowlist is the one part of this feature that widens disclosure, so the
# property that matters is that taking a schema back OUT closes it again -- with
# no restart, and with no dependence on when the pseudonym map was last built.
# ---------------------------------------------------------------------------
is(set_allowlist($node, 'trustedext'),
	'trustedext', 'removal: exempt again, to have something to remove');
like(
	plan_record(query_log($node, $join_query)),
	qr/Seq Scan on trusted_tbl /,
	'removal: the real name is printed immediately before the removal');

is(set_allowlist($node, ''),
	'', 'removal: the allowlist is emptied by reload');

$rec = plan_record(query_log($node, $join_query));
unlike($rec, qr/trusted_tbl/,
	'FR-60: removing a schema from the allowlist re-redacts its objects');
@pseudo_scans = ($rec =~ /Seq Scan on (t\d+)/g);
is(scalar(@pseudo_scans), 2,
	"FR-60: and the record still names both relations, as pseudonyms (@pseudo_scans)"
);

# The removal phase is also where the warning must be absent, which the next
# phase relies on.  Checked here rather than asserted from memory.
my $quiet_log = query_log($node, $join_query);
unlike(
	$quiet_log,
	qr/in auto_explain\.redact_allow_schemas is also active/,
	'no allowlist warning is emitted when the allowlist holds no user schema'
);

# ---------------------------------------------------------------------------
# PHASE 4: the documented warning for a user schema (FR-51).
#
# Allowlisting a schema exempts everything created in it LATER as well, so
# "public" is the one entry that can turn redaction off for most of a database
# without looking like it did.  It is permitted -- a site may keep only trusted
# extensions there -- but not silently: the operator is told once per session, in
# the same log the records go to, through the same channel as the FR-75 envelope
# warnings.
# ---------------------------------------------------------------------------
is(set_allowlist($node, 'public'),
	'public', 'the warning case: public is accepted, not refused');

$log = query_log($node, $join_query);
like(
	$log,
	qr/log_redact is enabled, but "public" in auto_explain\.redact_allow_schemas is also active/,
	'FR-51: allowlisting public is reported in the log');
like(
	$log,
	qr/Objects in an allowlisted schema print their real names, including objects created in it later/,
	'FR-51: the report says what allowlisting a user schema costs');

# Anti-vacuity, and the reason PHASE 3 ends the way it does: the same regex found
# nothing before public was listed, so this is the setting being reported and not
# a message the module emits unconditionally.
$rec = plan_record($log);
unlike($rec, qr/trusted_tbl/,
	'the warning case: listing public does not exempt some other schema');
is_deeply([ leaked($rec) ],
	[], 'the warning case: the fixture schemas are still redacted');

# ---------------------------------------------------------------------------
# PHASE 5: the check hook.
#
# A check hook cannot ereport, so a malformed list has to be rejected through
# GUC_check_errdetail() and a false return.  Tested through ALTER SYSTEM, which
# runs the hook in the session and so can be observed; a bad value in
# postgresql.conf would only produce a complaint in the log at reload.
#
# Both directions, because a hook that rejects everything would pass the negative
# test alone.
# ---------------------------------------------------------------------------
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	q{ALTER SYSTEM SET auto_explain.redact_allow_schemas = 'good,"unclosed'});
isnt($ret, 0, 'check hook: a malformed list is refused');
like(
	$stderr,
	qr/List syntax is invalid/,
	'check hook: the refusal says what was wrong with the value');

($ret, $stdout, $stderr) = $node->psql('postgres',
	q{ALTER SYSTEM SET auto_explain.redact_allow_schemas = 'trustedext, "Mixed Case"'}
);
is($ret, 0,
	'check hook: a well-formed list, including a quoted element, is accepted'
);
$node->safe_psql('postgres',
	'ALTER SYSTEM RESET auto_explain.redact_allow_schemas');

# D9 from the other side: a session cannot set it for itself at all.  The GUC
# level is the whole protection here -- a SUSET allowlist would let any superuser
# session exempt its own schema into a log someone else reads.
($ret, $stdout, $stderr) = $node->psql('postgres',
	q{SET auto_explain.redact_allow_schemas = 'trustedext'});
isnt($ret, 0, 'D9: the allowlist cannot be set per session');
like(
	$stderr,
	qr/cannot be changed now|cannot be set after connection start|permission denied/,
	'D9: and the refusal is the GUC level, not a parse failure');

done_testing();
