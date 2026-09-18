/*-------------------------------------------------------------------------
 *
 * explain_redact.c
 *	  Pseudonym engine for redacted EXPLAIN output.
 *
 * Nothing in this file inspects a plan or emits anything.  It answers one
 * question -- "what should this object be called in a redacted record?" -- and
 * it is deliberately the only place that decides.  Callers in explain.c and
 * ruleutils.c route names through here; this file never calls back into them.
 *
 * Three properties are load-bearing and easy to break by accident:
 *
 * 1. All counters live in the RedactCtx, never at file scope.  A static counter
 *    would make numbering continue across records, which would let a log reader
 *    order and join pseudonyms between unrelated statements -- exactly what
 *    FR-45 exists to prevent -- and would grow without bound.
 *
 * 2. Numbers are handed out on first use, in request order, so the result is a
 *    pure function of the plan walk (FR-42).  Nothing here may seed numbering
 *    from a pointer value, an OID sort order, or a hash-table scan order, or the
 *    same plan would produce different records on different backends and the
 *    comparability that determinism buys would be lost.
 *
 * 3. Every name returned lives in ctx->cxt, whether it is a pseudonym or the
 *    real name of an exempt object.  Returning call-time memory for the exempt
 *    case would hand callers a pointer whose lifetime depends on catalog state,
 *    which is the worst shape for a defect: it would not reproduce against a
 *    fixture schema whose objects are all user-schema.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/commands/explain_redact.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "catalog/namespace.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_type.h"
#include "commands/explain_redact.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

/*
 * Pseudonym prefixes, indexed by RedactKind.  Must match the enum order and
 * must satisfy FR-41: lower-case ASCII only, so that prefix + counter always
 * matches ^[a-z]+[0-9]+$ and never requires quoting.
 */
static const char *const redact_prefix[REDACT_NKINDS] = {
	"t",						/* REDACT_RELATION */
	"i",						/* REDACT_INDEX */
	"f",						/* REDACT_FUNCTION */
	"op",						/* REDACT_OPERATOR */
	"ty",						/* REDACT_TYPE */
	"coll",						/* REDACT_COLLATION */
	"opc",						/* REDACT_OPCLASS */
	"trg",						/* REDACT_TRIGGER */
	"con",						/* REDACT_CONSTRAINT */
	"a",						/* REDACT_ALIAS */
	"c",						/* REDACT_COLUMN (qualified, see below) */
	"cte",						/* REDACT_CTE */
	"enr",						/* REDACT_ENR */
	"sp",						/* REDACT_SUBPLAN */
	"w",						/* REDACT_WINDOW */
	"fld",						/* REDACT_FIELD */
	"arg",						/* REDACT_ARGNAME */
	"xml",						/* REDACT_XMLNAME */
	"path",						/* REDACT_PATHNAME */
	"cur"						/* REDACT_CURSOR */
};

/* Key for OID-identified objects. */
typedef struct RedactOidKey
{
	RedactKind	kind;
	Oid			oid;
} RedactOidKey;

typedef struct RedactOidEntry
{
	RedactOidKey key;			/* must be first */
	char		name[NAMEDATALEN];
} RedactOidEntry;

/*
 * Key for objects with no catalog entry.  For REDACT_COLUMN this is
 * (varno, attno) -- see FR-46: subquery, join, function, VALUES, CTE, ENR and
 * tablefunc range-table entries have no relid and no catalog attribute number,
 * so (relid, attno) cannot name their columns at all.
 */
typedef struct RedactLocalKey
{
	RedactKind	kind;
	int			scope;
	int			ordinal;
} RedactLocalKey;

typedef struct RedactLocalEntry
{
	RedactLocalKey key;			/* must be first */
	char		name[NAMEDATALEN];
} RedactLocalEntry;

/* Per-relation column counter, so column numbers are dense per relation. */
typedef struct RedactColKey
{
	int			scope;
} RedactColKey;

typedef struct RedactColEntry
{
	RedactColKey key;			/* must be first */
	int			next;
} RedactColEntry;

struct RedactCtx
{
	MemoryContext cxt;			/* private child context owning everything
								 * here, including this struct */
	HTAB	   *oid_map;		/* RedactOidKey -> RedactOidEntry */
	HTAB	   *local_map;		/* RedactLocalKey -> RedactLocalEntry */
	HTAB	   *col_counters;	/* RedactColKey -> RedactColEntry */
	List	   *allow_schemas;	/* additional exempt schema names (FR-51),
								 * copied into cxt so the caller's list need
								 * not outlive us */
	Oid			info_schema_oid;	/* resolved once; see redact_is_exempt() */
	int			counter[REDACT_NKINDS];
};

static Oid	redact_object_namespace(RedactKind kind, Oid oid, bool *found);
static bool redact_is_exempt(RedactCtx *ctx, RedactKind kind, Oid oid);
static char *redact_real_name(RedactKind kind, Oid oid);

/*
 * explain_redact_create
 *		Set up a pseudonym context for exactly one record.
 */
RedactCtx *
explain_redact_create(List *allow_schemas)
{
	RedactCtx  *ctx;
	MemoryContext cxt;
	MemoryContext oldcxt;
	HASHCTL		hash_ctl;
	ListCell   *lc;

	/*
	 * Everything lives in a private child of the caller's context, for two
	 * reasons.
	 *
	 * The caller's contract is unchanged: resetting the context this was
	 * created in still frees the whole map, because the child dies with its
	 * parent.  That is what makes FR-45 automatic rather than a matter of
	 * discipline.
	 *
	 * The child also gives the hash tables a context they exclusively own,
	 * which dynahash requires -- hash_destroy() frees a table by deleting its
	 * hcxt outright ("so this hashtable must have its own context").  Handing
	 * the caller's own context to hash_create() and then calling
	 * hash_destroy() would delete the caller's context, including this
	 * struct, and the next hash_destroy() would read freed memory.
	 */
	cxt = AllocSetContextCreate(CurrentMemoryContext,
								"explain redact",
								ALLOCSET_SMALL_SIZES);
	oldcxt = MemoryContextSwitchTo(cxt);

	ctx = (RedactCtx *) palloc0(sizeof(RedactCtx));
	ctx->cxt = cxt;

	/*
	 * Copy the allowlist in, so the caller's list need not outlive the
	 * context.  The natural caller builds it from a GUC parse whose lifetime
	 * is not obviously longer than ours.
	 *
	 * Comparison is by exact string, so the list must already be normalised
	 * the way the catalog stores names.  SplitIdentifierString() does that
	 * (downcasing unquoted identifiers); the T04 GUC path must use it, or
	 * redact_allow_schemas = 'MySchema' will silently fail to exempt
	 * "MySchema".
	 */
	foreach(lc, allow_schemas)
		ctx->allow_schemas = lappend(ctx->allow_schemas,
									 pstrdup((const char *) lfirst(lc)));

	/*
	 * Resolve information_schema once, rather than string-comparing per
	 * lookup.  PostgreSQL pins no OID for it, so the exempt set does follow
	 * whatever schema currently holds that name; resolving here fixes the
	 * decision for the lifetime of one record instead of re-deciding per
	 * object.  A missing schema yields InvalidOid, which never matches.
	 */
	ctx->info_schema_oid = get_namespace_oid("information_schema", true);

	/*
	 * Sized for a small plan; these grow as needed.  Memory is bounded by the
	 * distinct object count of one plan (FR-81), which is what makes
	 * discarding the whole thing per record affordable.
	 */
	hash_ctl.keysize = sizeof(RedactOidKey);
	hash_ctl.entrysize = sizeof(RedactOidEntry);
	hash_ctl.hcxt = cxt;
	ctx->oid_map = hash_create("explain redact oid map", 32, &hash_ctl,
							   HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	hash_ctl.keysize = sizeof(RedactLocalKey);
	hash_ctl.entrysize = sizeof(RedactLocalEntry);
	hash_ctl.hcxt = cxt;
	ctx->local_map = hash_create("explain redact local map", 32, &hash_ctl,
								 HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	hash_ctl.keysize = sizeof(RedactColKey);
	hash_ctl.entrysize = sizeof(RedactColEntry);
	hash_ctl.hcxt = cxt;
	ctx->col_counters = hash_create("explain redact column counters", 16,
									&hash_ctl,
									HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	MemoryContextSwitchTo(oldcxt);

	/* Counters start at zero, so the first pseudonym of each kind is 1. */
	return ctx;
}

/*
 * explain_redact_destroy
 *		Release the context eagerly.
 *
 * Optional: resetting the context this was created in achieves the same thing,
 * and that is the normal path.
 *
 * Deleting the private context takes the hash tables and the RedactCtx itself
 * with it, so there are deliberately no hash_destroy() calls -- each would try
 * to delete that same context.  The pointer is dead on return.
 */
void
explain_redact_destroy(RedactCtx *ctx)
{
	if (ctx == NULL)
		return;

	MemoryContextDelete(ctx->cxt);
}

/*
 * redact_object_namespace
 *		Find the namespace OID of an object, for the exemption test.
 *
 * Sets *found to false when the namespace cannot be determined, which the
 * caller must treat as "not exempt" (FR-60, fail closed).  Reasons that happens
 * legitimately: the object was concurrently dropped, or its kind is one that is
 * not namespace-scoped in any useful sense.
 */
static Oid
redact_object_namespace(RedactKind kind, Oid oid, bool *found)
{
	HeapTuple	tup;
	Oid			result = InvalidOid;

	*found = false;

	if (!OidIsValid(oid))
		return InvalidOid;

	switch (kind)
	{
		case REDACT_RELATION:
		case REDACT_INDEX:
			result = get_rel_namespace(oid);
			*found = OidIsValid(result);
			break;

		case REDACT_FUNCTION:
			result = get_func_namespace(oid);
			*found = OidIsValid(result);
			break;

		case REDACT_TYPE:
			tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(oid));
			if (HeapTupleIsValid(tup))
			{
				result = ((Form_pg_type) GETSTRUCT(tup))->typnamespace;
				*found = true;
				ReleaseSysCache(tup);
			}
			break;

		case REDACT_OPERATOR:
			tup = SearchSysCache1(OPEROID, ObjectIdGetDatum(oid));
			if (HeapTupleIsValid(tup))
			{
				result = ((Form_pg_operator) GETSTRUCT(tup))->oprnamespace;
				*found = true;
				ReleaseSysCache(tup);
			}
			break;

		case REDACT_COLLATION:
			tup = SearchSysCache1(COLLOID, ObjectIdGetDatum(oid));
			if (HeapTupleIsValid(tup))
			{
				result = ((Form_pg_collation) GETSTRUCT(tup))->collnamespace;
				*found = true;
				ReleaseSysCache(tup);
			}
			break;

		case REDACT_OPCLASS:
			tup = SearchSysCache1(CLAOID, ObjectIdGetDatum(oid));
			if (HeapTupleIsValid(tup))
			{
				result = ((Form_pg_opclass) GETSTRUCT(tup))->opcnamespace;
				*found = true;
				ReleaseSysCache(tup);
			}
			break;

		default:

			/*
			 * Triggers and constraints are reached only through a user
			 * relation, so there is no exempt case to recognise and no reason
			 * to look one up.  Locally-keyed kinds have no catalog object at
			 * all.  Both fall through to "not found", i.e. always redacted.
			 */
			break;
	}

	return result;
}

/*
 * redact_is_exempt
 *		The D7 test: exempt iff the namespace is pg_catalog,
 *		information_schema, or allowlisted.
 *
 * Deliberately NOT the historical OID-range heuristic.  Provisioning an
 * application schema during initdb yields low-OID objects that the OID test
 * would print in full; the namespace test redacts them correctly (FR-50).
 *
 * Called once per object, on the first request for it -- explain_redact_name()
 * caches the outcome either way, so a plan naming one relation from twenty
 * sites pays for this once rather than twenty times.
 */
static bool
redact_is_exempt(RedactCtx *ctx, RedactKind kind, Oid oid)
{
	Oid			nspoid;
	bool		found;
	char	   *nspname;
	ListCell   *lc;

	nspoid = redact_object_namespace(kind, oid, &found);
	if (!found)
		return false;			/* fail closed */

	if (nspoid == PG_CATALOG_NAMESPACE)
		return true;

	if (OidIsValid(ctx->info_schema_oid) && nspoid == ctx->info_schema_oid)
		return true;

	if (ctx->allow_schemas == NIL)
		return false;			/* nothing else can match; skip the lookup */

	nspname = get_namespace_name(nspoid);
	if (nspname == NULL)
		return false;			/* concurrently dropped: fail closed */

	foreach(lc, ctx->allow_schemas)
	{
		if (strcmp(nspname, (const char *) lfirst(lc)) == 0)
			return true;
	}

	return false;
}

/*
 * redact_real_name
 *		The object's actual name, for the exempt case.  NULL if unavailable.
 */
static char *
redact_real_name(RedactKind kind, Oid oid)
{
	switch (kind)
	{
		case REDACT_RELATION:
		case REDACT_INDEX:
			return get_rel_name(oid);
		case REDACT_FUNCTION:
			return get_func_name(oid);
		case REDACT_OPERATOR:
			return get_opname(oid);
		case REDACT_COLLATION:
			return get_collation_name(oid);
		case REDACT_TYPE:
			{
				HeapTuple	tup = SearchSysCache1(TYPEOID,
												  ObjectIdGetDatum(oid));
				char	   *name = NULL;

				if (HeapTupleIsValid(tup))
				{
					name = pstrdup(NameStr(((Form_pg_type) GETSTRUCT(tup))->typname));
					ReleaseSysCache(tup);
				}
				return name;
			}
		case REDACT_OPCLASS:
			{
				HeapTuple	tup = SearchSysCache1(CLAOID,
												  ObjectIdGetDatum(oid));
				char	   *name = NULL;

				if (HeapTupleIsValid(tup))
				{
					name = pstrdup(NameStr(((Form_pg_opclass) GETSTRUCT(tup))->opcname));
					ReleaseSysCache(tup);
				}
				return name;
			}
		default:
			return NULL;
	}
}

/*
 * explain_redact_name
 *		Pseudonym (or real name, if exempt) for an OID-keyed object.
 */
const char *
explain_redact_name(RedactCtx *ctx, RedactKind kind, Oid oid)
{
	RedactOidKey key;
	RedactOidEntry *entry;
	bool		found;

	Assert(ctx != NULL);
	Assert(kind >= 0 && kind < REDACT_NKINDS);

	memset(&key, 0, sizeof(key));
	key.kind = kind;
	key.oid = oid;

	/*
	 * Look the object up before testing exemption, so the decision is made
	 * once per object rather than once per reference.
	 */
	entry = (RedactOidEntry *) hash_search(ctx->oid_map, &key,
										   HASH_ENTER, &found);
	if (found)
		return entry->name;

	if (redact_is_exempt(ctx, kind, oid))
	{
		char	   *real = redact_real_name(kind, oid);

		if (real != NULL)
		{
			/*
			 * Cached like a pseudonym, so every name this function returns
			 * has the same lifetime -- see property 3 in the file header.
			 * Real names are NameData, so they always fit.
			 *
			 * The exempt object consumes an entry but NOT a counter, so
			 * adding or removing one from a plan cannot shift the numbering
			 * of anything else.
			 */
			strlcpy(entry->name, real, sizeof(entry->name));
			pfree(real);
			return entry->name;
		}
		/* Lookup failed after all: fall through and redact (FR-60). */
	}

	snprintf(entry->name, sizeof(entry->name), "%s%d",
			 redact_prefix[kind], ++ctx->counter[kind]);

	return entry->name;
}

/*
 * explain_redact_local
 *		Pseudonym for an object identified by position rather than by OID.
 */
const char *
explain_redact_local(RedactCtx *ctx, RedactKind kind, int scope, int ordinal)
{
	RedactLocalKey key;
	RedactLocalEntry *entry;
	bool		found;

	Assert(ctx != NULL);
	Assert(kind >= 0 && kind < REDACT_NKINDS);

	memset(&key, 0, sizeof(key));
	key.kind = kind;
	key.scope = scope;
	key.ordinal = ordinal;

	entry = (RedactLocalEntry *) hash_search(ctx->local_map, &key,
											 HASH_ENTER, &found);
	if (found)
		return entry->name;

	if (kind == REDACT_COLUMN)
	{
		/*
		 * Columns are qualified by the pseudonym of the range-table entry
		 * they belong to, so a reader can see which relation a column came
		 * from without learning which relation it is.
		 *
		 * The qualifier is the ALIAS pseudonym, because a column key is a
		 * range-table index and that is the only pseudonym keyed the same
		 * way. Columns therefore read "a1_c1" today, NOT the "t1_c3" that the
		 * requirements use as their example -- this function has no way to
		 * reach that form, because nothing yet links a range-table index to a
		 * relation OID.  T07/T08 add that linkage, after which a plain
		 * relation's columns can read "t1_c1" while a subquery's still read
		 * "a1_c1".
		 *
		 * The numeric part is an opaque per-relation counter assigned on
		 * first use -- never the attribute number, which would leak the
		 * column's ordinal position and hence the table's shape (FR-12,
		 * FR-43).
		 *
		 * Recursing while holding "entry" is safe: dynahash splits buckets by
		 * relinking in place and never relocates elements, so the inner
		 * HASH_ENTER cannot invalidate this pointer.  The two keys differ in
		 * "kind" and so cannot alias.
		 */
		RedactColKey colkey;
		RedactColEntry *colent;
		const char *relname;
		bool		colfound;

		memset(&colkey, 0, sizeof(colkey));
		colkey.scope = scope;
		colent = (RedactColEntry *) hash_search(ctx->col_counters, &colkey,
												HASH_ENTER, &colfound);
		if (!colfound)
			colent->next = 0;

		relname = explain_redact_local(ctx, REDACT_ALIAS, scope, 0);

		snprintf(entry->name, sizeof(entry->name), "%s_%s%d",
				 relname, redact_prefix[REDACT_COLUMN], ++colent->next);
	}
	else
		snprintf(entry->name, sizeof(entry->name), "%s%d",
				 redact_prefix[kind], ++ctx->counter[kind]);

	return entry->name;
}

#ifdef USE_ASSERT_CHECKING

/*
 * Case-insensitive substring search.  PostgreSQL has no pg_strcasestr(), and
 * the harness's markers are lower case, so a marked identifier routed through
 * upper() would evade a case-sensitive check and read as clean.
 */
static bool
redact_contains_marker(const char *haystack, const char *needle)
{
	size_t		nlen = strlen(needle);

	for (const char *p = haystack; *p != '\0'; p++)
	{
		if (pg_strncasecmp(p, needle, nlen) == 0)
			return true;
	}
	return false;
}

/*
 * explain_redact_tripwire
 *		Abort if a test marker reaches output while redaction is active.
 *
 * Keyed on the regression-suite marker rather than on any general notion of
 * sensitivity, which is what makes it free of false positives: production data
 * never contains these strings, so this can never fire outside a test.
 *
 * Its value over the harness is reach and precision.  The harness greps the
 * finished record, so it reports "something leaked" for the fixtures it happens
 * to include; this fires at the moment of the write, names the site, and does so
 * for any query touching marked objects -- including code paths that no fixture
 * in the catalog exercises.
 *
 * Case-insensitive, matching the harness: a marked identifier arriving through
 * upper() must not read as clean.
 */
void
explain_redact_tripwire(RedactCtx *ctx, const char *str, const char *site)
{
	if (ctx == NULL || str == NULL)
		return;

	/*
	 * ERROR rather than PANIC deliberately.  PANIC would take down the
	 * cluster and make the rest of a test run uninterpretable; ERROR aborts
	 * the statement, which is loud, catchable and testable.  FR-60's
	 * preference for redacting over erroring governs production behaviour,
	 * and this code does not exist in production builds.
	 */
	if (redact_contains_marker(str, "zsec_") ||
		redact_contains_marker(str, "zsecdata-"))
		elog(ERROR,
			 "redaction leak at %s: emitted marked string \"%s\"",
			 site ? site : "(unknown site)", str);
}

#endif							/* USE_ASSERT_CHECKING */
