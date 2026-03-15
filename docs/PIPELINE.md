# Rebuild + verify pipeline

The MVP now includes a compact pipeline that can:

1. select a target from `compile_commands.json`
2. rebuild it with sanitizer flags
3. execute the rebuilt binary using a verification plan
4. capture both rebuild and verification evidence

## Why this matters

This is one bounded audit-mode validation path. It preserves rebuild and verification evidence without implying broader autonomy than the current implementation provides.
