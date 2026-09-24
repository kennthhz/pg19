# src/test/modules/test_explain_redact/Makefile

MODULE_big = test_explain_redact
OBJS = \
	$(WIN32RES) \
	test_explain_redact.o
PGFILEDESC = "test_explain_redact - unit tests for the EXPLAIN redaction pseudonym engine"

EXTENSION = test_explain_redact
DATA = test_explain_redact--1.0.sql

REGRESS = test_explain_redact

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_explain_redact
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
