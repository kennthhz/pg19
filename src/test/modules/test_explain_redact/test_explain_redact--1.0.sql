/* src/test/modules/test_explain_redact/test_explain_redact--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION test_explain_redact" to load this file. \quit

CREATE FUNCTION test_redact_oid_seq(kinds text[], oids oid[])
RETURNS text[]
AS 'MODULE_PATHNAME', 'test_redact_oid_seq'
LANGUAGE C STRICT;

CREATE FUNCTION test_redact_local_seq(kinds text[], scopes int[], ordinals int[])
RETURNS text[]
AS 'MODULE_PATHNAME', 'test_redact_local_seq'
LANGUAGE C STRICT;

CREATE FUNCTION test_redact_counters_restart(relid oid)
RETURNS boolean
AS 'MODULE_PATHNAME', 'test_redact_counters_restart'
LANGUAGE C STRICT;

CREATE FUNCTION test_redact_exempt(kind text, objoid oid, allow text DEFAULT NULL)
RETURNS text
AS 'MODULE_PATHNAME', 'test_redact_exempt'
LANGUAGE C CALLED ON NULL INPUT;

CREATE FUNCTION test_redact_tripwire(str text)
RETURNS text
AS 'MODULE_PATHNAME', 'test_redact_tripwire'
LANGUAGE C STRICT;

CREATE FUNCTION test_redact_tripwire_enabled()
RETURNS boolean
AS 'MODULE_PATHNAME', 'test_redact_tripwire_enabled'
LANGUAGE C STRICT;

CREATE FUNCTION test_redact_destroy_roundtrip()
RETURNS boolean
AS 'MODULE_PATHNAME', 'test_redact_destroy_roundtrip'
LANGUAGE C STRICT;
