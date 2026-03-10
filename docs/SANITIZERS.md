# Sanitizer support

The MVP now includes a basic sanitizer build helper for single-file C targets.

## Current scope

- `clang`
- `-fsanitize=address,undefined`
- single-file compilation inside the workspace

## Why this is useful

This moves the project one step closer to verified findings instead of purely heuristic ones.

## Expected next steps

- support multi-file targets
- consume `compile_commands.json` for real rebuilds
- run generated binaries with controlled inputs
- capture sanitizer traces in reports
