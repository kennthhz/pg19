/*-------------------------------------------------------------------------
 *
 * explain_redact.h
 *	  Pseudonym engine for redacted EXPLAIN output.
 *
 * A RedactCtx maps objects and names appearing in a plan to opaque pseudonyms
 * ("t1", "a1_c1", "f2", ...) for the duration of producing exactly one
 * redacted record.  Nothing in it survives the record: see FR-45.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * src/include/commands/explain_redact.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef EXPLAIN_REDACT_H
#define EXPLAIN_REDACT_H

#include "nodes/pg_list.h"

/*
 * Pseudonym namespaces (FR-40).  Each kind has its own counter, so numbering
 * within a record is dense and per-kind: the first relation is always "t1"
 * whether or not a function was named before it.
 *
 * The kinds are split by what can be used to identify the object, because that
 * determines which entry point applies.  This split is the substance of FR-46:
 * a single OID key cannot name everything that gets printed.
 *
 * OID-keyed kinds have a catalog entry, so exemption can be decided by looking
 * up the object's namespace (D7).  Locally-keyed kinds have no catalog object
 * at all -- a subquery's column alias, a window name, a JSON path label -- so
 * they are always redacted, there being nothing to exempt them against.
 */
typedef enum RedactKind
{
	/* OID-keyed: exemption is decided by the object's namespace */
	REDACT_RELATION = 0,		/* t1, t2, ...   also sequences (FR-99) */
	REDACT_INDEX,				/* i1, ... */
	REDACT_FUNCTION,			/* f1, ... */
	REDACT_OPERATOR,			/* op1, ... */
	REDACT_TYPE,				/* ty1, ... */
	REDACT_COLLATION,			/* coll1, ... */
	REDACT_OPCLASS,				/* opc1, ... */
	REDACT_TRIGGER,				/* trg1, ... */
	REDACT_CONSTRAINT,			/* con1, ... */

	/* Locally-keyed: no catalog object, therefore never exempt */
	REDACT_ALIAS,				/* a1, ...   key: (rtindex, 0) */
	REDACT_COLUMN,				/* a1_c1, ... key: (varno, attno) */
	REDACT_CTE,					/* cte1, ... */
	REDACT_ENR,					/* enr1, ... */
	REDACT_SUBPLAN,				/* sp1, ...  FR-90 */
	REDACT_WINDOW,				/* w1, ...   FR-91 */
	REDACT_FIELD,				/* fld1, ... FR-93 */
	REDACT_ARGNAME,				/* arg1, ... FR-94 */
	REDACT_XMLNAME,				/* xml1, ... FR-95 */
	REDACT_PATHNAME,			/* path1, ... FR-96 */
	REDACT_CURSOR,				/* cur1, ... FR-97 */

	REDACT_NKINDS				/* must be last */
} RedactKind;

/* Opaque; defined in explain_redact.c */
typedef struct RedactCtx RedactCtx;

/*
 * Lifetime.  The context is allocated in the caller's current memory context
 * and is expected to be freed by that context's reset -- auto_explain switches
 * to the per-query context before generating output, which is what makes FR-45
 * automatic rather than a matter of discipline.  explain_redact_destroy() is
 * provided for callers that want to release the hash tables eagerly.
 *
 * allow_schemas is a list of schema-name strings exempted in addition to
 * pg_catalog and information_schema (FR-51); NIL is the normal case.  The list
 * is copied, so it need not outlive the context.  Names are compared exactly,
 * so they must already be normalised the way the catalog stores them -- see the
 * note in explain_redact_create().
 */
extern RedactCtx *explain_redact_create(List *allow_schemas);
extern void explain_redact_destroy(RedactCtx *ctx);

/*
 * Name an OID-keyed object.  Returns the object's real name when it is exempt
 * (D7: namespace is pg_catalog, information_schema, or allowlisted), otherwise
 * a stable pseudonym for this record.
 *
 * Never returns NULL and never raises an error: a failed catalog lookup yields
 * a pseudonym, because losing the whole record to an ERROR because an object
 * was concurrently dropped would be worse than redacting it (FR-60).
 *
 * LIFETIME: the returned string is owned by ctx and valid until ctx is
 * destroyed, for exempt real names as well as for pseudonyms.  Callers may
 * retain it for the duration of the record without copying.
 */
extern const char *explain_redact_name(RedactCtx *ctx, RedactKind kind, Oid oid);

/*
 * Name a locally-keyed object.  "scope" and "ordinal" together identify it
 * within the plan; their meaning is per-kind, documented against the enum
 * above.  Always returns a pseudonym -- these kinds have no catalog object and
 * so can never be exempt.
 *
 * For REDACT_COLUMN the result is qualified by the pseudonym of the owning
 * range-table entry, and the numeric part is an opaque per-relation counter,
 * never the attribute number (FR-12, FR-43).
 *
 * That qualifier is currently always the ALIAS pseudonym, so columns read
 * "a1_c1".  The requirements use "t1_c3" as their example, which this function
 * cannot yet produce: a column key is a range-table index, and nothing links
 * one to a relation OID until the name-assignment layer arrives in T07/T08.
 * After that a plain relation's columns can read "t1_c1" while a subquery's
 * still read "a1_c1".  Do not audit call sites against the "t1_c3" form until
 * then.
 *
 * LIFETIME: as for explain_redact_name().
 */
extern const char *explain_redact_local(RedactCtx *ctx, RedactKind kind,
										int scope, int ordinal);

/*
 * Tripwire (§2.1 of the task plan).  In assert-enabled builds, aborts if the
 * given string contains a test marker while redaction is active, naming the
 * emission site.  A no-op when ctx is NULL, and compiled out entirely
 * otherwise, so production builds pay nothing.
 *
 * The point is diagnostics and reach: the test harness greps the finished
 * record and can only say "something leaked", whereas this fires at the moment
 * of the write with a stack trace -- and it fires for any query touching marked
 * objects, not only for the fixtures in the catalog.
 */
#ifdef USE_ASSERT_CHECKING
extern void explain_redact_tripwire(RedactCtx *ctx, const char *str,
									const char *site);
#else

/*
 * The arguments are evaluated and discarded rather than dropped entirely, so
 * that a non-assert build does not produce "unused variable" warnings at call
 * sites whose only use of a value is this check.  Every argument is cheap to
 * compute by construction -- a context pointer, a buffer already built, and a
 * string literal -- so there is nothing to save by skipping them.
 */
#define explain_redact_tripwire(ctx, str, site) \
	((void) (ctx), (void) (str), (void) (site))
#endif

#endif							/* EXPLAIN_REDACT_H */
