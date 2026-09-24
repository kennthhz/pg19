# src/test/modules/test_explain_redact/Makefile

MODULE_big = test_explain_redact
OBJS = \
	$(WIN32RES) \
	test_explain_redact.o
PGFILEDESC = "test_explain_redact - unit tests for the EXPLAIN redaction pseudonym engine"

EXTENSION = test_explain_redact
DATA = test_explain_redact--1.0.sql

REGRESS = test_explain_redact

# Two of T17's surfaces cannot be reached without an extension loaded: a
# user-installed TABLESAMPLE method (tsm_system_rows) and a CustomScan provider
# (test_extensible).  src/test/regress runs against a plain install and cannot
# take an EXTRA_INSTALL of its own without making a core regression test depend
# on contrib, so those two fixtures live here.  Precedent:
# contrib/auto_explain/Makefile does the same for pg_overexplain.
EXTRA_INSTALL = contrib/tsm_system_rows src/test/modules/test_extensible

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
