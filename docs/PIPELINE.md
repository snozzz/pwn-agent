# Rebuild + verify pipeline

The MVP now includes a compact pipeline that can:

1. select a target from `compile_commands.json`
2. rebuild it with sanitizer flags
3. execute the rebuilt binary using a verification plan
4. capture both rebuild and verification evidence

## Why this matters

This is the first real end-to-end loop in the project. It moves the repository closer to an actual security analysis agent instead of a collection of standalone helpers.
