# compile_commands.json support

The MVP can now ingest a compilation database and surface a summary in the audit report.

## Why this matters

A compilation database is the bridge from simple file scanning to semantically aware analysis. It enables later work such as:

- targeted clang-based parsing
- better include-path awareness
- per-translation-unit analysis
- sanitizer-aware rebuild orchestration
