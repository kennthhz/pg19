/*-------------------------------------------------------------------------
 *
 * ruleutils.h
 *		Declarations for ruleutils.c
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/ruleutils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef RULEUTILS_H
#define RULEUTILS_H

#include "nodes/nodes.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"

typedef struct Plan Plan;		/* avoid including plannodes.h here */
typedef struct PlannedStmt PlannedStmt;

/* Flags for pg_get_indexdef_columns_extended() */
#define RULE_INDEXDEF_PRETTY		0x01
#define RULE_INDEXDEF_KEYS_ONLY		0x02	/* ignore included attributes */

extern char *pg_get_indexdef_string(Oid indexrelid);
extern char *pg_get_indexdef_columns(Oid indexrelid, bool pretty);
extern char *pg_get_indexdef_columns_extended(Oid indexrelid,
											  uint16 flags);
extern char *pg_get_querydef(Query *query, bool pretty);

extern char *pg_get_partkeydef_columns(Oid relid, bool pretty);
extern char *pg_get_partconstrdef_string(Oid partitionId, char *aliasname);

extern char *pg_get_constraintdef_command(Oid constraintId);

/*
 * Redaction-aware variants, for EXPLAIN records that must not disclose the
 * application's schema or data.  Each takes a RedactCtx; passing NULL means
 * "do not redact" and makes the variant behave exactly as its plain
 * counterpart, which is what every existing caller in the tree relies on.
 *
 * Named by struct tag rather than through the RedactCtx typedef so that this
 * header does not acquire a dependency on commands/explain_redact.h.  The type
 * is opaque either way.
 */
struct RedactCtx;

extern char *deparse_expression_redacted(Node *expr, List *dpcontext,
										 bool forceprefix, bool showimplicit,
										 struct RedactCtx *redact);
extern List *select_rtable_names_for_explain_redacted(List *rtable,
													  Bitmapset *rels_used,
													  struct RedactCtx *redact);
extern List *deparse_context_for_plan_tree_redacted(PlannedStmt *pstmt,
													List *rtable_names,
													struct RedactCtx *redact);

/*
 * The pseudonym map a deparse context carries, or NULL if it is not redacting.
 *
 * For code that holds a deparse context and has to fill in a deparse_context
 * of its own -- it can derive the map instead of being passed it, and so stays
 * correct for callers it has not met.  deparse_namespace is private to
 * ruleutils.c, so the handle cannot be reached any other way.
 */
extern struct RedactCtx *deparse_context_redaction(List *dpcontext);

/*
 * Whether any namespace in a deparse context carries a pseudonym map.
 *
 * For the two guards that have to tell a redacting deparse context from an
 * ordinary one without being able to see deparse_namespace, which is private
 * to ruleutils.c.
 */
extern bool deparse_context_is_redacting(List *dpcontext);

extern char *deparse_expression(Node *expr, List *dpcontext,
								bool forceprefix, bool showimplicit);
extern List *deparse_context_for(const char *aliasname, Oid relid);
extern List *deparse_context_for_plan_tree(PlannedStmt *pstmt,
										   List *rtable_names);
extern List *set_deparse_context_plan(List *dpcontext,
									  Plan *plan, List *ancestors);
extern List *select_rtable_names_for_explain(List *rtable,
											 Bitmapset *rels_used);
extern char *get_window_frame_options_for_explain(int frameOptions,
												  Node *startOffset,
												  Node *endOffset,
												  List *dpcontext,
												  bool forceprefix);
extern char *generate_collation_name(Oid collid);
extern char *generate_opclass_name(Oid opclass);
extern char *get_range_partbound_string(List *bound_datums);
extern void get_reloptions(StringInfo buf, Datum reloptions);

extern char *pg_get_statisticsobjdef_string(Oid statextid);

#endif							/* RULEUTILS_H */
