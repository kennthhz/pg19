# Copyright (c) 2021-2026, PostgreSQL Global Development Group

# 003_redact_scan.pl -- run PostgreSQL's own regression suite with redaction on,
# then check the resulting log against the live catalog.
#
#
# PURPOSE OF THIS FILE
#
# The other two redaction tests share two hand-built inputs, and each is a
# completeness risk.  002_redact.pl and the explain_redact regression file both
# rely on a fixture list somebody wrote (did we think of every leak path?) and on
# a naming convention somebody applied (did we mark every object?).  Neither can
# say anything about a path no fixture reaches.
#
# This test removes both inputs.
#
#   - The corpus becomes PostgreSQL's own regression suite -- 241 test files run
#     under redaction, covering partitioning, inheritance, every join strategy,
#     window functions, recursive CTEs, foreign tables, custom scans, row-level
#     security and node types no hand-written fixture will ever produce.  This
#     file contributes no queries of its own, deliberately; writing more fixtures
#     is the thing it is meant to replace.
#
#   - The oracle becomes the catalog.  Rather than grepping for a marker, it asks
#     the database for every user-defined name and checks the log for those.  The
#     database already knows every name, so nothing has to be tagged and nothing
#     can be forgotten.
#
# It is the highest-value check in the plan and the most expensive, which is why
# it is gated behind PG_TEST_EXTRA.
#
#   make check-world PG_TEST_EXTRA=redact_scan
#
#
# WHAT IT CANNOT TELL YOU
#
# Two limits, both worth knowing before trusting a pass.
#
# The catalog is read after the suite finishes, so objects the suite created and
# then dropped are not in it and their names are not searched for.  That is a
# reduction in coverage rather than a blind spot: what is under test is emission
# *paths*, and a path that leaks a dropped table's name would leak a surviving
# table's name through the same code.  Thousands of names survive to the end.
#
# And a leak reachable only by a plan shape that appears in no test suite anywhere
# still goes unseen.  That is unfalsifiable and accepted.  What this test changes
# is the residual risk: from "our fixture list might be incomplete", which is a
# bet on one person's thoroughness, to "PostgreSQL's own suite does not cover this
# shape", which is a materially better place to stand.
#
#
# WHY THE LOG MUST BE READ SELECTIVELY
#
# Only auto_explain's plan records are scanned, not the whole log file, and that
# is not an optimisation.  Three other things put user names into the same file
# and would make the scan report leaks that redaction never caused:
#
#   - PostgreSQL::Test::Cluster sets log_statement = all and a log_line_prefix
#     containing %q, so every statement would appear verbatim.  This test
#     overrides both, and asserts the overrides took effect, because if they
#     silently did not the scan would drown in false positives.
#   - The regression suite provokes errors on purpose, and an error message names
#     the object it is about ("relation ... does not exist"), followed by a
#     STATEMENT: line carrying the whole query.  Redaction does not govern error
#     messages and is not meant to.
#   - The companion reference entries from T05 contain statements by design.  They
#     are off here, since log_min_messages stays at its default.
#
# So the scan extracts records the way a reader would: the "duration: ... plan:"
# header line and the tab-indented continuation lines that follow it.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

if (!$ENV{PG_TEST_EXTRA} || $ENV{PG_TEST_EXTRA} !~ /\bredact_scan\b/)
{
	plan skip_all =>
	  'test not enabled in PG_TEST_EXTRA (add "redact_scan" to run it)';
}

# ---------------------------------------------------------------------------
# Words that legitimately appear in a redacted plan record.
#
# A redacted record still prints node types, property labels, units and fixed
# vocabulary such as "Forward" or "quicksort".  The regression suite contains
# objects whose names collide with some of those words -- it has tables and
# columns called things like "text" and "time" -- so a catalog name that is also
# plan vocabulary cannot be distinguished from a leak by this method and would
# report a false positive on every record.
#
# This list is therefore part of the test's contract, not an afterthought, and it
# is the file to read when judging how much the pass is worth.  Every entry is
# here because the word appears in plan output regardless of the query, and each
# one narrows what the scan can see.  Keep it short, and never add a name merely
# to make the test pass.
# ---------------------------------------------------------------------------
my %plan_vocabulary = map { lc($_) => 1 } qw(
  actual aggregate all and append async average batches before between
  bitmap blocks bucket buckets buffers by cache calls capacity copy cost
  cte current custom deforming delete direction dirtied disabled disk
  distinct emission estimated estimates evictions exact executed execution
  expressions fetches filter for forward full functions gather gating
  generation group groups hash hashaggregate hashed heap hit hits
  incremental index inlining insert join keys kb launched limit local
  lockrows logical lookups lossy materialize memoize memory merge method
  misses mixed mode ms nested never on one-time only optimization options
  original overflows parallel partial partitioned peak percent plain
  planned planning presorted projectset quicksort range read reads
  recheck recursive removed result rows sample scan searches seq set setop
  shared simple single sort sorted space storage strategy subplan subquery
  temp time timing tid top-n total tuples tuplestore union unique
  update usage used values width window windowagg worker workers write
  writes written loops true false none partition
);

# ---------------------------------------------------------------------------
# Allowlist: names the scan is permitted to find.
#
# Empty, and it should stay that way.  The plan calls for this file to exist and
# to carry a written reason per entry, because the easiest way to make this test
# pass is to grow it -- so it is meant to be read as carefully as the code, and
# an entry with no reason is a bug report waiting to be filed.
#
# An entry belongs here only if the disclosure is genuinely unavoidable.  Anything
# else is a leak to fix.
# ---------------------------------------------------------------------------
my %allowlist = (

	# (no entries)
);

# ---------------------------------------------------------------------------
# The cluster.
# ---------------------------------------------------------------------------
my $node = PostgreSQL::Test::Cluster->new('redact_scan');
$node->init;
$node->append_conf(
	'postgresql.conf', qq{
session_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
auto_explain.log_analyze = on
auto_explain.log_redact = on

# Overriding Cluster.pm's defaults, which would otherwise write every statement
# into the log and make the scan meaningless.  Asserted below rather than
# assumed.
log_statement = none
log_line_prefix = '%m [%p] '
});
$node->start;

is($node->safe_psql('postgres', 'SHOW log_statement'),
	'none',
	'log_statement override took effect (otherwise the scan is vacuous)');
is($node->safe_psql('postgres', 'SHOW auto_explain.log_redact'),
	'on', 'redaction is enabled for the suite run');

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

# Extract only auto_explain plan records from a log chunk.  See the header for
# why the rest of the file must not be scanned.
sub plan_records
{
	my ($log) = @_;
	my @kept;
	my $in_record = 0;

	foreach my $line (split /\n/, $log)
	{
		if ($line =~ /duration: [\d.]+ ms  (?:ref: [0-9a-f]+  )?plan:/)
		{
			$in_record = 1;
			next;
		}
		if ($in_record)
		{
			if ($line =~ /^\t/) { push @kept, $line; next; }
			$in_record = 0;
		}
	}
	return \@kept;
}

# Every user-defined name the database currently knows about.
#
# Asked of the catalog rather than assembled from the test sources, which is the
# whole point: the database cannot forget an object it holds.
sub catalog_names
{
	my ($node, $dbname) = @_;

	my $sql = q{
		SELECT DISTINCT lower(name) FROM (
		  SELECT c.relname::text AS name FROM pg_class c
		    JOIN pg_namespace n ON n.oid = c.relnamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		     AND n.nspname NOT LIKE 'pg_toast%'
		  UNION ALL
		  SELECT a.attname::text FROM pg_attribute a
		    JOIN pg_class c ON c.oid = a.attrelid
		    JOIN pg_namespace n ON n.oid = c.relnamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		     AND n.nspname NOT LIKE 'pg_toast%'
		     AND a.attnum > 0 AND NOT a.attisdropped
		  UNION ALL
		  SELECT p.proname::text FROM pg_proc p
		    JOIN pg_namespace n ON n.oid = p.pronamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		  UNION ALL
		  SELECT t.typname::text FROM pg_type t
		    JOIN pg_namespace n ON n.oid = t.typnamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		  UNION ALL
		  SELECT cl.collname::text FROM pg_collation cl
		    JOIN pg_namespace n ON n.oid = cl.collnamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		  UNION ALL
		  SELECT con.conname::text FROM pg_constraint con
		    JOIN pg_namespace n ON n.oid = con.connamespace
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		  UNION ALL
		  SELECT tg.tgname::text FROM pg_trigger tg WHERE NOT tg.tgisinternal
		  UNION ALL
		  SELECT n.nspname::text FROM pg_namespace n
		   WHERE n.nspname NOT IN ('pg_catalog','information_schema','public')
		     AND n.nspname NOT LIKE 'pg_%'
		) o
		WHERE name ~ '^[a-z_][a-z0-9_]*$' AND length(name) >= 3};

	my %names;
	my @suppressed;
	foreach my $n (split /\n/, $node->safe_psql($dbname, $sql))
	{
		next if $n eq '';
		if ($plan_vocabulary{$n} || $allowlist{$n})
		{
			push @suppressed, $n;
			next;
		}
		$names{$n} = 1;
	}

	# Report the blind spot rather than leaving it implicit.  Every name here is
	# one this method cannot see, because it collides with a word that appears in
	# plan output regardless of the query.  The number is the honest measure of
	# how much the pass is worth, and a sudden jump in it means the vocabulary is
	# being grown to keep the test quiet.
	note(   "names this scan cannot distinguish from plan vocabulary ("
		  . scalar(@suppressed) . "): "
		  . join(' ', sort @suppressed))
	  if @suppressed;

	return (\%names, exempt_names($node, $dbname, \%names));
}

# Names of pg_catalog and information_schema objects, for scan() to recognise in
# the positions where such a name is allowed to print.
#
# Since T21b a redacted record prints expressions again, and with them the names
# of exempt objects: the type after "::", a built-in function, a catalog column.
# Many of those collide with some user object in the regression database -- it
# has objects called "text", "sum" and "relname" -- and the scan cannot tell
# pg_catalog.text printed as a cast from a user column called text leaking.
#
# The answer is not the vocabulary.  Folding "text" into %plan_vocabulary would
# blind the scan to a user object of that name everywhere, including exactly the
# column position where it would be a leak.  Instead scan() skips a token only
# where it is in a position an exempt name may occupy *and* it is an exempt name
# of the kind that position holds; see there.
#
# Columns are the exception, because no position distinguishes them: a user
# column called relname leaking would print exactly like pg_class.relname behind
# a pseudonym alias.  Those names are a second blind spot, reported next to the
# vocabulary one and for the same reason.
sub exempt_names
{
	my ($node, $dbname, $names) = @_;
	my %exempt;
	my $in_exempt = q{IN ('pg_catalog','information_schema')};

	# A type is matched by its catalog name and by the spelling format_type()
	# gives it, which is what ruleutils prints: "timestamp with time zone" for
	# timestamptz, "bit varying" for varbit, "char" in quotes.  Qualifiers and
	# quotes are stripped here and allowed for in scan().
	my $types_sql = qq{
		SELECT lower(t.typname) FROM pg_type t
		  JOIN pg_namespace n ON n.oid = t.typnamespace
		 WHERE n.nspname $in_exempt
		UNION
		SELECT lower(regexp_replace(replace(format_type(t.oid, NULL), '"', ''),
		                            '^(pg_catalog|information_schema)[.]', ''))
		  FROM pg_type t
		  JOIN pg_namespace n ON n.oid = t.typnamespace
		 WHERE n.nspname $in_exempt};
	my $funcs_sql = qq{
		SELECT DISTINCT lower(p.proname) FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname $in_exempt};
	my $columns_sql = qq{
		SELECT DISTINCT lower(a.attname) FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname $in_exempt
		   AND c.relkind IN ('r','v','m','p','f')
		   AND a.attnum > 0 AND NOT a.attisdropped};

	$exempt{types} = {
		map { $_ => 1 } grep { $_ ne '' && !/\[/ }
		  split /\n/,
		$node->safe_psql($dbname, $types_sql)
	};
	$exempt{funcs} = {
		map { $_ => 1 } grep { $_ ne '' }
		  split /\n/,
		$node->safe_psql($dbname, $funcs_sql)
	};

	# Only the columns that collide with a user name matter, and only they are a
	# blind spot, so only they are kept.
	$exempt{columns} = {
		map { $_ => 1 } grep { $names->{$_} }
		  split /\n/,
		$node->safe_psql($dbname, $columns_sql)
	};

	# The second honest number.  Every name here is a user name the scan cannot
	# see in an expression property, because it is also the name of a catalog
	# column that property may legitimately print.  It still sees them in node
	# header lines, where columns never print.  A jump in this number means the
	# catalog or the suite changed and is worth a look; it cannot be grown to
	# keep the test quiet, because nothing in this file lists its members.
	my @cols = sort keys %{ $exempt{columns} };
	note(   "names this scan cannot see in expression properties, because "
		  . "they are also columns of pg_catalog or information_schema "
		  . "relations ("
		  . scalar(@cols) . "): "
		  . join(' ', @cols))
	  if @cols;

	return \%exempt;
}

# Report which catalog names appear in the given plan-record lines.
#
# One pass over the records, pulling out identifier-shaped tokens and testing set
# membership, rather than one search per name: with thousands of names and a log
# this size, per-name searching does not finish in reasonable time.
# Properties whose value comes from a fixed set of code constants.
#
# These lines are skipped whole, rather than having their words folded into
# %plan_vocabulary, and the difference matters.  "Conflict Resolution" can print
# "SELECT FOR KEY SHARE", and the regression suite contains an object named
# "key"; adding "key" to the vocabulary would blind the scan to that name
# everywhere, including in properties where it would be a real leak.  Skipping the
# line costs nothing instead, because a line that can only hold code constants
# cannot hold a leak by construction.
#
# Anything listed here has to be verifiably a closed set in the source.  A
# property whose value merely looks fixed is not eligible.
my @fixed_value_properties = (
	'Conflict Resolution',   # switch on onConflictLockStrength
	'Cache Mode',            # "binary" or "logical"
	'Scan Direction',        # "Forward", "Backward"
	'Sort Method',           # "quicksort", "external merge", "top-N heapsort"
	'Node Type',             # node type names
	'Strategy',              # "Plain", "Sorted", "Hashed", "Mixed"
	'Partial Mode',          # "Simple", "Partial", "Finalize"
	'Join Type',             # "Inner", "Left", "Full", "Right", ...
	'Operation',             # "Insert", "Update", "Delete", "Merge"
	'Command',               # SetOp commands
	'Parent Relationship',   # "Outer", "Inner", "Member", "InitPlan", ...
	'Storage',               # "Memory", "Disk"
	'Subplan Name',          # under redaction: "CTE", "InitPlan", "SubPlan"
	'Replaces',              # under redaction: the replacement type alone
);
my $fixed_re = join '|', map { quotemeta } @fixed_value_properties;

# Positions where an exempt name may print.  See exempt_names() for why these
# exist; the rule for every one of them is that a token is removed only when it
# is in the position *and* is an exempt name of the kind the position holds.  A
# user name in the same position is still seen: "?::zsec_mytype" is reported,
# which is what stops "skip whatever follows ::" from passing this file while
# blinding it to the type-name leaks T11 exists to prevent.  The PHASE 0 cases
# below pin every rule in both directions.
#
#   - Property labels.  The text up to the first colon of a property line is a
#     code constant ("Sort Key", "Rows Removed by Filter", "Worker 0"), never
#     user text, so it is dropped before tokenizing; that is what lets "key" be
#     searched for everywhere else.  The pattern admits only capitalised words,
#     "by" and numbers, so it cannot run into a value or match a node header
#     line.  The one text-format line that puts a name before its colon is
#     "Trigger <name>: time=..." (explain.c, report_triggers), excluded by name.
#   - Types, after "::", optionally qualified by pg_catalog or
#     information_schema and optionally quoted.  The longest exempt spelling
#     wins, so "::timestamp with time zone" removes all four words while
#     "::timestamp" followed by some other word removes one.
#   - Functions, immediately followed by "(", which is how ruleutils prints a
#     call.  A call qualified by any other schema is not skipped.
#   - The tablesample method, the first word of a "Sampling:" value; ruleutils
#     prints it with a space before the "(".
#   - Syntax: IS [NOT] JSON, and ruleutils' own "colN" field label on a
#     multi-column sub-plan, "(SubPlan sp1).col1".
#   - Columns of exempt relations, on property lines only.  This is the blind
#     spot exempt_names() reports; node header lines never print a column, so
#     there the names stay visible.
my $ident = qr/[a-z_][a-z0-9_]*/;
my $exempt_qual = qr/(?:pg_catalog|information_schema)\./;
my $typmod = qr/\(\d+(?:,\d+)?\)/;
my $label_re =
  qr/^\s*(?!Trigger\b)([A-Z][A-Za-z\/-]*(?: (?:[A-Z][A-Za-z\/-]*|by|\d+))*):(?=\s|$)/;

# The spelling that follows "::", less the longest leading run of words that is
# an exempt type name; undef when no leading run is one.
sub strip_exempt_type
{
	my ($spelling, $types) = @_;
	(my $bare = $spelling) =~ s/$typmod//g;
	my @w = split / /, $bare;
	for (my $k = $#w; $k >= 0; $k--)
	{
		return join(' ', '', @w[ $k + 1 .. $#w ])
		  if $types->{ join(' ', @w[ 0 .. $k ]) };
	}
	return undef;
}

sub scan
{
	my ($records, $names, $exempt) = @_;
	my %found;

	foreach my $line (@$records)
	{
		next if $line =~ /^\s*(?:$fixed_re):/;

		my $v = $line;
		my $label;
		$label = $1 if $v =~ s/$label_re//;

		$v =~ s/\bIS (?:NOT )?\KJSON\b//g;
		$v =~ s/((?:SubPlan|InitPlan) \w+\))\.col\d+\b/$1/g;

		$v =~ s{::(?:$exempt_qual)?"?($ident(?:$typmod? $ident)*)}{
			my $all = $&;
			my $rest = strip_exempt_type($1, $exempt->{types});
			defined $rest ? "::$rest" : $all;
		}ge;

		$v =~ s{^(\s*)($ident)(?= \()}{$exempt->{funcs}{$2} ? $1 : $&}e
		  if defined $label && $label eq 'Sampling';
		$v =~ s{(?<![\w.])(?:$exempt_qual)?($ident)(?=\()}{
			$exempt->{funcs}{$1} ? '' : $&
		}ge;

		while ($v =~ /([A-Za-z_][A-Za-z0-9_]*)/g)
		{
			my $tok = lc($1);

			next if defined $label && $exempt->{columns}{$tok};

			# Keep the line each name first appeared on.  A bare list of names
			# cannot be acted on: the first question is always which property
			# printed it, and answering that from the name alone means
			# reproducing a whole suite run.
			$found{$tok} = $line if $names->{$tok} && !exists $found{$tok};
		}
	}
	return \%found;
}

# ---------------------------------------------------------------------------
# PHASE 0 -- the scanner's filter, against synthetic records.
#
# The positional rules above are what make the suite run pass, and a filter that
# makes a test pass is easy to write.  These cases show it still catches leaks:
# for each rule, an exempt name in its position is not reported, and a user name
# in the same line shape -- or the same name in another position -- is.  The
# names and exempt sets are hand-built, so this needs no catalog and runs in no
# time.
# ---------------------------------------------------------------------------
{
	my %t_names = map { $_ => 1 } qw(
	  text char zone key col1 json relname sum system
	  zsec_mytype zsec_fn zsec_tsm zsec_trig zsec_schema);
	my %t_exempt = (
		types => {
			map { $_ => 1 } (
				'text', 'char',
				'bit', 'bit varying',
				'timestamp', 'timestamp with time zone')
		},
		funcs => { map { $_ => 1 } qw(sum random system) },
		columns => { relname => 1 },);

	# [ group, record line, name, 1 if it must be found ]
	my @cases = (
		[ 1, 'Filter: (a1_c1 = ?::text)', 'text', 0 ],
		[ 1, 'Filter: (text = ?::text)', 'text', 1 ],
		[ 1, 'Filter: (a1_c1 = ?::pg_catalog.text)', 'text', 0 ],
		[ 1, 'Filter: (a1_c1 = ?::"char")', 'char', 0 ],
		[ 1, 'Sort Key: ((a1.a1_c1)::bit varying)', 'bit', 0 ],
		[ 1, 'Filter: (a1_c1 = ?::timestamp with time zone)', 'zone', 0 ],
		[ 1, 'Filter: (zone = ?::timestamp(3) with time zone)', 'zone', 1 ],
		[ 1, 'Filter: (a1_c1 = ?::zsec_mytype)', 'zsec_mytype', 1 ],
		[
			1, 'Filter: (a1_c1 = ?::information_schema.zsec_mytype)',
			'zsec_mytype', 1
		],
		[ 2, 'Filter: (sum(DISTINCT a1.a1_c4) > ?::integer)', 'sum', 0 ],
		[ 2, 'Filter: (sum = ?::integer)', 'sum', 1 ],
		[ 2, 'Filter: (zsec_schema.sum(a1_c1) > ?::integer)', 'sum', 1 ],
		[ 2, 'Filter: (zsec_fn(a1_c1) > ?::integer)', 'zsec_fn', 1 ],
		[ 2, 'Sampling: system (a1.a1_c2)', 'system', 0 ],
		[ 2, 'Sampling: zsec_tsm (a1.a1_c2)', 'zsec_tsm', 1 ],
		[ 3, 'Filter: (relname ~~ ?::text)', 'relname', 0 ],
		[
			3, '->  Seq Scan on relname a1  (cost=0.00..1.01 rows=1 width=4)',
			'relname', 1
		],
		[ 4, 'Sort Key: a1_c1', 'key', 0 ],
		[ 4, 'Filter: (key = ?::integer)', 'key', 1 ],
		[ 4, 'Trigger zsec_trig: time=0.012 calls=1', 'zsec_trig', 1 ],
		[ 5, 'Filter: (a1_c1 IS JSON)', 'json', 0 ],
		[ 5, 'Filter: (json IS NOT NULL)', 'json', 1 ],
		[ 5, 'Filter: (ANY (a1_c1 = (hashed SubPlan sp1).col1))', 'col1', 0 ],
		[ 5, 'Filter: (col1 > 0)', 'col1', 1 ],);

	foreach my $c (@cases)
	{
		my ($group, $line, $name, $want) = @$c;
		my $hits = scan(["\t  $line"], \%t_names, \%t_exempt);
		is( (exists $hits->{$name} ? 1 : 0),
			$want,
			"scan filter, group $group: \"$name\" "
			  . ($want ? 'found' : 'not found')
			  . " in: $line");
	}
}

# ---------------------------------------------------------------------------
# PHASE 1 -- positive control.
#
# Run the scanner against records produced with redaction OFF and require that it
# finds a great many names.  Without this the whole test is worthless: a scanner
# broken in any way -- a record pattern that matches nothing, a catalog query
# returning no rows, a log path that is wrong -- reports "no leaks" forever and
# looks like a pass.
#
# Redaction is switched off by reload, which the GUC's PGC_SIGHUP level requires.
# ---------------------------------------------------------------------------
$node->append_conf('postgresql.conf', 'auto_explain.log_redact = off');
$node->reload;
is($node->safe_psql('postgres', 'SHOW auto_explain.log_redact'),
	'off', 'redaction switched off for the positive control');

$node->safe_psql(
	'postgres', q{
	CREATE SCHEMA scan_ctl;
	CREATE TABLE scan_ctl.customer_account (account_number text, balance numeric);
	CREATE INDEX customer_account_idx ON scan_ctl.customer_account (account_number);
	INSERT INTO scan_ctl.customer_account
	  SELECT 'acct-' || i, i FROM generate_series(1, 200) i;
	ANALYZE scan_ctl.customer_account;
});

my $logfile = $node->logfile();
my $offset = -s $logfile;
$node->safe_psql(
	'postgres', q{
	SET search_path = scan_ctl, public;
	SET enable_seqscan = off;
	-- an index scan, so the index name is exercised as well as table and column
	SELECT account_number FROM customer_account WHERE account_number = 'acct-7';
	RESET enable_seqscan;
	-- a self-join, for aliases
	SELECT count(*) FROM customer_account a JOIN customer_account b USING (account_number);
	-- a CTE, for the sub-plan label
	WITH recent AS MATERIALIZED (SELECT account_number FROM customer_account)
	  SELECT * FROM recent;
	-- a sort and an aggregate, for key and output properties
	SELECT account_number, sum(balance) FROM customer_account
	   GROUP BY account_number ORDER BY account_number LIMIT 5;
});
my ($ctl_names, $ctl_exempt) = catalog_names($node, 'postgres');
my $ctl_hits =
  scan(plan_records(slurp_file($logfile, $offset)), $ctl_names, $ctl_exempt);
my @ctl_found = sort keys %$ctl_hits;

ok(scalar(keys %$ctl_names) > 0,
	'positive control: the catalog query returns names to look for');
# Named rather than counted.  A threshold passes as long as something was found,
# which is satisfied by a scanner that only ever sees table names; requiring one
# name per class -- relation, column, index -- is what shows the whole pipeline
# works, and it is the mistake this project already made once in T01.
my %ctl_expected = map { $_ => 1 } qw(
  customer_account account_number balance customer_account_idx
);
my @ctl_missing = grep { !$ctl_hits->{$_} } sort keys %ctl_expected;
is_deeply(\@ctl_missing, [],
	'positive control: the scanner finds the unredacted relation, column and index names ('
	  . join(' ', @ctl_found)
	  . ')');

# ---------------------------------------------------------------------------
# PHASE 2 -- the suite, redacted.
# ---------------------------------------------------------------------------
$node->append_conf('postgresql.conf', 'auto_explain.log_redact = on');
$node->reload;
is($node->safe_psql('postgres', 'SHOW auto_explain.log_redact'),
	'on', 'redaction switched back on for the suite run');

# The binary comes from PG_REGRESS, which the makefiles export for exactly this
# purpose.  top_srcdir is not exported to TAP tests, so the schedule and input
# directory are located relative to top_builddir; on a vpath build those differ,
# which is why the schedule is checked for rather than assumed.
my $pg_regress = $ENV{PG_REGRESS};
my $regress_dir = "$ENV{top_builddir}/src/test/regress";
my $schedule = "$regress_dir/parallel_schedule";
my $outputdir = PostgreSQL::Test::Utils::tempdir();

if (!defined $pg_regress || !-f $schedule || !-d "$regress_dir/sql")
{
	$node->stop;
	plan skip_all => "regression suite inputs not found under $regress_dir";
}


# --use-existing runs the suite against the cluster above instead of building one
# of its own, which is what lets this test own the configuration and read the
# catalog afterwards.  Failures in the suite itself are reported but not fatal:
# some tests are sensitive to non-default settings, and log_min_duration = 0 with
# log_analyze on is emphatically non-default.  What matters here is that the
# queries ran and produced records to scan, not that every expected file matched.
# --use-existing does not create the test database -- pg_regress skips both the
# drop and the create in that mode -- so it has to exist first.  The locale
# settings are the ones pg_regress would have applied itself.  They matter for
# expected-output stability, which this test does not depend on, but omitting
# them produces a torrent of diffs that would obscure a real problem.
$node->safe_psql('postgres', 'CREATE DATABASE regression');
$node->safe_psql(
	'postgres', q{
	ALTER DATABASE regression SET lc_messages TO 'C';
	ALTER DATABASE regression SET lc_monetary TO 'C';
	ALTER DATABASE regression SET lc_numeric TO 'C';
	ALTER DATABASE regression SET lc_time TO 'C';
	ALTER DATABASE regression SET timezone_abbreviations TO 'Default';
});

$offset = -s $logfile;

# No concurrency limit is passed.  --max-concurrent-tests=1 looks like the way
# to serialise the run, but it is a different setting: it caps how many tests a
# single schedule line may list, so pg_regress rejects the core schedule outright
# at its first parallel group.  The schedule's own grouping is left alone.
my $rc = system($pg_regress, "--use-existing",
	"--host=" . $node->host, "--port=" . $node->port,
	"--dbname=regression", "--inputdir=$regress_dir",
	"--outputdir=$outputdir", "--dlpath=$regress_dir",
	"--bindir=", "--schedule=$schedule");

note("pg_regress exited with $rc"
	  . ($rc == 0 ? '' : ' (not fatal; see the comment above)'));

my $records = plan_records(slurp_file($logfile, $offset));
ok( scalar(@$records) > 1000,
	'the suite produced plan records to scan ('
	  . scalar(@$records)
	  . ' lines)');

my ($names, $exempt) = catalog_names($node, 'regression');
ok( scalar(keys %$names) > 500,
	'the catalog yielded a large body of names to search for ('
	  . scalar(keys %$names) . ')');

my $hits = scan($records, $names, $exempt);
my @leaked = sort keys %$hits;

is_deeply(\@leaked, [],
	'no user-defined name from the catalog appears in any redacted record');

foreach my $name (@leaked)
{
	diag("found \"$name\" in a redacted record; first occurrence was\n  "
		  . $hits->{$name});
}

$node->stop;
done_testing();
