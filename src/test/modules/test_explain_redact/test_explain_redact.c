/*--------------------------------------------------------------------------
 *
 * test_explain_redact.c
 *		Unit tests for the EXPLAIN redaction pseudonym engine.
 *
 * The engine is exercised directly rather than through EXPLAIN, because at this
 * point nothing consumes it: EXPLAIN (REDACT) does not exist yet.  Testing it in
 * isolation is the point -- the properties below (deterministic numbering,
 * per-record counters, namespace-primary exemption, fail-closed lookups) are
 * much easier to pin down here than to infer later from plan text.
 *
 * Each function builds a fresh context in a private memory context and deletes
 * it before returning, which also demonstrates the lifetime property FR-45
 * relies on: discarding the context is all that is needed to discard the map.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		src/test/modules/test_explain_redact/test_explain_redact.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_type.h"
#include "commands/explain_redact.h"
#include "fmgr.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

/* Keep in step with RedactKind in commands/explain_redact.h. */
static const struct
{
	const char *name;
	RedactKind	kind;
}			kind_names[] =

{
	{"relation", REDACT_RELATION},
	{"index", REDACT_INDEX},
	{"function", REDACT_FUNCTION},
	{"operator", REDACT_OPERATOR},
	{"type", REDACT_TYPE},
	{"collation", REDACT_COLLATION},
	{"opclass", REDACT_OPCLASS},
	{"trigger", REDACT_TRIGGER},
	{"constraint", REDACT_CONSTRAINT},
	{"alias", REDACT_ALIAS},
	{"column", REDACT_COLUMN},
	{"cte", REDACT_CTE},
	{"enr", REDACT_ENR},
	{"subplan", REDACT_SUBPLAN},
	{"window", REDACT_WINDOW},
	{"field", REDACT_FIELD},
	{"argname", REDACT_ARGNAME},
	{"xmlname", REDACT_XMLNAME},
	{"pathname", REDACT_PATHNAME},
	{"cursor", REDACT_CURSOR},
};

static RedactKind
kind_from_name(const char *name)
{
	for (int i = 0; i < lengthof(kind_names); i++)
	{
		if (strcmp(name, kind_names[i].name) == 0)
			return kind_names[i].kind;
	}
	elog(ERROR, "unrecognized redact kind: \"%s\"", name);
	return REDACT_NKINDS;		/* keep compiler quiet */
}

/*
 * test_redact_oid_seq(kinds text[], oids oid[]) returns text[]
 *
 * Runs the whole request sequence against ONE context, in order, and returns
 * the pseudonyms.  Using one context is the point: it is what makes FR-40
 * (same object, same pseudonym) and FR-42 (numbering follows request order)
 * observable rather than assumed.
 */
PG_FUNCTION_INFO_V1(test_redact_oid_seq);
Datum
test_redact_oid_seq(PG_FUNCTION_ARGS)
{
	ArrayType  *kind_arr = PG_GETARG_ARRAYTYPE_P(0);
	ArrayType  *oid_arr = PG_GETARG_ARRAYTYPE_P(1);
	Datum	   *kind_datums;
	Datum	   *oid_datums;
	bool	   *kind_nulls;
	bool	   *oid_nulls;
	int			nkinds;
	int			noids;
	Datum	   *results;
	MemoryContext work;
	MemoryContext old;
	RedactCtx  *ctx;
	ArrayType  *out;

	/*
	 * STRICT rejects a null array, not a null element, and a null Datum
	 * reaching TextDatumGetCString() below crashes the backend.
	 */
	if (array_contains_nulls(kind_arr) || array_contains_nulls(oid_arr))
		elog(ERROR, "array arguments must not contain NULL elements");

	deconstruct_array(kind_arr, TEXTOID, -1, false, TYPALIGN_INT,
					  &kind_datums, &kind_nulls, &nkinds);
	deconstruct_array(oid_arr, OIDOID, sizeof(Oid), true, TYPALIGN_INT,
					  &oid_datums, &oid_nulls, &noids);

	if (nkinds != noids)
		elog(ERROR, "kinds and oids must have the same length");

	results = (Datum *) palloc(sizeof(Datum) * nkinds);

	work = AllocSetContextCreate(CurrentMemoryContext,
								 "test_redact work",
								 ALLOCSET_SMALL_SIZES);
	old = MemoryContextSwitchTo(work);
	ctx = explain_redact_create(NIL);

	for (int i = 0; i < nkinds; i++)
	{
		char	   *kname = TextDatumGetCString(kind_datums[i]);
		RedactKind	kind = kind_from_name(kname);
		Oid			oid = DatumGetObjectId(oid_datums[i]);
		const char *name = explain_redact_name(ctx, kind, oid);

		/* Copy out before the work context goes away. */
		MemoryContextSwitchTo(old);
		results[i] = CStringGetTextDatum(name);
		MemoryContextSwitchTo(work);
	}

	MemoryContextSwitchTo(old);
	MemoryContextDelete(work);	/* FR-45: the whole map dies with the context */

	out = construct_array_builtin(results, nkinds, TEXTOID);
	PG_RETURN_ARRAYTYPE_P(out);
}

/*
 * test_redact_local_seq(kinds text[], scopes int[], ordinals int[]) returns text[]
 *
 * As above, for the locally-keyed kinds.  The column cases are the interesting
 * ones: they are what FR-46 is about, since a (relid, attno) key cannot name the
 * columns of a range-table entry that has no relid.
 */
PG_FUNCTION_INFO_V1(test_redact_local_seq);
Datum
test_redact_local_seq(PG_FUNCTION_ARGS)
{
	ArrayType  *kind_arr = PG_GETARG_ARRAYTYPE_P(0);
	ArrayType  *scope_arr = PG_GETARG_ARRAYTYPE_P(1);
	ArrayType  *ord_arr = PG_GETARG_ARRAYTYPE_P(2);
	Datum	   *kind_datums;
	Datum	   *scope_datums;
	Datum	   *ord_datums;
	bool	   *n1;
	bool	   *n2;
	bool	   *n3;
	int			nk;
	int			ns;
	int			no;
	Datum	   *results;
	MemoryContext work;
	MemoryContext old;
	RedactCtx  *ctx;

	if (array_contains_nulls(kind_arr) || array_contains_nulls(scope_arr) ||
		array_contains_nulls(ord_arr))
		elog(ERROR, "array arguments must not contain NULL elements");

	deconstruct_array(kind_arr, TEXTOID, -1, false, TYPALIGN_INT,
					  &kind_datums, &n1, &nk);
	deconstruct_array(scope_arr, INT4OID, sizeof(int32), true, TYPALIGN_INT,
					  &scope_datums, &n2, &ns);
	deconstruct_array(ord_arr, INT4OID, sizeof(int32), true, TYPALIGN_INT,
					  &ord_datums, &n3, &no);

	if (nk != ns || nk != no)
		elog(ERROR, "all three arrays must have the same length");

	results = (Datum *) palloc(sizeof(Datum) * nk);

	work = AllocSetContextCreate(CurrentMemoryContext,
								 "test_redact work",
								 ALLOCSET_SMALL_SIZES);
	old = MemoryContextSwitchTo(work);
	ctx = explain_redact_create(NIL);

	for (int i = 0; i < nk; i++)
	{
		char	   *kname = TextDatumGetCString(kind_datums[i]);
		RedactKind	kind = kind_from_name(kname);
		const char *name = explain_redact_local(ctx, kind,
												DatumGetInt32(scope_datums[i]),
												DatumGetInt32(ord_datums[i]));

		MemoryContextSwitchTo(old);
		results[i] = CStringGetTextDatum(name);
		MemoryContextSwitchTo(work);
	}

	MemoryContextSwitchTo(old);
	MemoryContextDelete(work);

	PG_RETURN_ARRAYTYPE_P(construct_array_builtin(results, nk, TEXTOID));
}

/*
 * test_redact_counters_restart() returns bool
 *
 * Two independent contexts, given the same request, must both answer "t1".
 *
 * This is the test that catches an accidental file-scope counter, which is the
 * single most likely way to break FR-45: numbering that continued across records
 * would let a log reader order and join pseudonyms between unrelated statements,
 * and would grow without bound.  It would also be invisible in any single
 * record, which is why it needs its own assertion.
 */
PG_FUNCTION_INFO_V1(test_redact_counters_restart);
Datum
test_redact_counters_restart(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	char		first[NAMEDATALEN];
	char		second[NAMEDATALEN];
	MemoryContext work;
	MemoryContext old;

	work = AllocSetContextCreate(CurrentMemoryContext,
								 "test_redact work",
								 ALLOCSET_SMALL_SIZES);

	old = MemoryContextSwitchTo(work);
	strlcpy(first,
			explain_redact_name(explain_redact_create(NIL),
								REDACT_RELATION, relid),
			NAMEDATALEN);
	MemoryContextSwitchTo(old);
	MemoryContextReset(work);

	MemoryContextSwitchTo(work);
	strlcpy(second,
			explain_redact_name(explain_redact_create(NIL),
								REDACT_RELATION, relid),
			NAMEDATALEN);
	MemoryContextSwitchTo(old);
	MemoryContextDelete(work);

	PG_RETURN_BOOL(strcmp(first, second) == 0);
}

/*
 * test_redact_exempt(kind text, oid oid, allow text) returns text
 *
 * Single lookup against a fresh context, with an optional comma-separated
 * allowlist.  Returns the real name when the object is exempt and a pseudonym
 * when it is not, so a caller can tell which branch was taken by whether the
 * answer looks like a pseudonym.
 */
PG_FUNCTION_INFO_V1(test_redact_exempt);
Datum
test_redact_exempt(PG_FUNCTION_ARGS)
{
	char	   *kname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	Oid			oid = PG_GETARG_OID(1);
	List	   *allow = NIL;
	MemoryContext work;
	MemoryContext old;
	char		result[NAMEDATALEN];

	if (!PG_ARGISNULL(2))
	{
		char	   *raw = text_to_cstring(PG_GETARG_TEXT_PP(2));

		if (!SplitIdentifierString(raw, ',', &allow))
			elog(ERROR, "invalid allowlist: \"%s\"", raw);
	}

	work = AllocSetContextCreate(CurrentMemoryContext,
								 "test_redact work",
								 ALLOCSET_SMALL_SIZES);
	old = MemoryContextSwitchTo(work);

	strlcpy(result,
			explain_redact_name(explain_redact_create(allow),
								kind_from_name(kname), oid),
			NAMEDATALEN);

	MemoryContextSwitchTo(old);
	MemoryContextDelete(work);

	PG_RETURN_TEXT_P(cstring_to_text(result));
}

/*
 * test_redact_tripwire(str text) returns text
 *
 * Feeds a string to the tripwire.  Returns 'ok' when nothing fired, raises an
 * error naming the site when a marker is present.  In a build without
 * assertions the tripwire compiles away, so this always returns 'ok' -- the
 * regression test accounts for that rather than pretending otherwise.
 */
PG_FUNCTION_INFO_V1(test_redact_tripwire);
Datum
test_redact_tripwire(PG_FUNCTION_ARGS)
{
	char	   *str = text_to_cstring(PG_GETARG_TEXT_PP(0));
	MemoryContext work;
	MemoryContext old;

	work = AllocSetContextCreate(CurrentMemoryContext,
								 "test_redact work",
								 ALLOCSET_SMALL_SIZES);
	old = MemoryContextSwitchTo(work);

	explain_redact_tripwire(explain_redact_create(NIL), str, "test site");

	MemoryContextSwitchTo(old);
	MemoryContextDelete(work);

	PG_RETURN_TEXT_P(cstring_to_text("ok"));
}

/*
 * test_redact_destroy_roundtrip() returns bool
 *
 * Exercises explain_redact_destroy(), which had no caller and no coverage and
 * which used to delete the caller's own memory context: it handed that context
 * to hash_destroy() three times, and hash_destroy() frees a table by deleting
 * its hcxt outright.  The first call therefore freed the RedactCtx and the
 * second read clobbered memory.
 *
 * Names are taken before and after so the test also shows that destroy releases
 * the map rather than merely appearing to succeed: a fresh context must number
 * from 1 again.
 */
PG_FUNCTION_INFO_V1(test_redact_destroy_roundtrip);
Datum
test_redact_destroy_roundtrip(PG_FUNCTION_ARGS)
{
	RedactCtx  *ctx;
	char		before[NAMEDATALEN];
	char		after[NAMEDATALEN];

	ctx = explain_redact_create(NIL);
	strlcpy(before, explain_redact_name(ctx, REDACT_RELATION, 900000001),
			NAMEDATALEN);
	strlcpy(after, explain_redact_name(ctx, REDACT_RELATION, 900000002),
			NAMEDATALEN);

	/* Must not disturb the caller's context, and must not double-free. */
	explain_redact_destroy(ctx);

	/* A second full cycle, to catch damage the first one left behind. */
	ctx = explain_redact_create(NIL);
	if (strcmp(explain_redact_name(ctx, REDACT_RELATION, 900000007),
			   before) != 0)
	{
		explain_redact_destroy(ctx);
		PG_RETURN_BOOL(false);	/* numbering did not restart */
	}
	explain_redact_destroy(ctx);

	PG_RETURN_BOOL(strcmp(before, "t1") == 0 && strcmp(after, "t2") == 0);
}

/*
 * test_redact_tripwire_enabled() returns bool
 *
 * Whether the tripwire is compiled in, so the regression test can state plainly
 * which build it is running under instead of producing output that silently
 * means different things.
 */
PG_FUNCTION_INFO_V1(test_redact_tripwire_enabled);
Datum
test_redact_tripwire_enabled(PG_FUNCTION_ARGS)
{
#ifdef USE_ASSERT_CHECKING
	PG_RETURN_BOOL(true);
#else
	PG_RETURN_BOOL(false);
#endif
}
