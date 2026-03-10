# Multi-file sanitizer rebuilds

The MVP can now rebuild targets derived from `compile_commands.json` with injected sanitizer flags.

## Current behavior

- selects a translation unit from the compile database
- rewrites its compiler argv with sanitizer flags
- executes the rebuilt command inside the recorded build directory

## Limitations

- translation-unit level only
- does not yet infer full link graphs across the project
- assumes the compile database entry is directly runnable as a compile+link command
