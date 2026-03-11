# Rebuild planning

The MVP now includes a compile-database-driven rebuild planner.

## Current capability

- ingest compile command entries
- extract translation-unit targets
- rewrite build argv to inject sanitizer flags
- prepare for multi-file target rebuilding
- audit/export summaries now report whether rebuild paths are ready, partially blocked, or failed

## Why it matters

This is the bridge from toy single-file demos to actual C/C++ projects compiled through a real build system.
