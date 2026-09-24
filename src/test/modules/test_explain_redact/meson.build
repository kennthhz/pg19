# Copyright (c) 2026, PostgreSQL Global Development Group

test_explain_redact_sources = files(
  'test_explain_redact.c',
)

if host_system == 'windows'
  test_explain_redact_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'test_explain_redact',
    '--FILEDESC', 'test_explain_redact - unit tests for the EXPLAIN redaction pseudonym engine',])
endif

test_explain_redact = shared_module('test_explain_redact',
  test_explain_redact_sources,
  kwargs: pg_test_mod_args,
)
test_install_libs += test_explain_redact

test_install_data += files(
  'test_explain_redact.control',
  'test_explain_redact--1.0.sql',
)

tests += {
  'name': 'test_explain_redact',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'test_explain_redact',
    ],
  },
}
