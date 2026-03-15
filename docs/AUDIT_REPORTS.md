# Audit reports

Audit reports now aggregate three evidence classes:

1. heuristic source findings
2. compile database context
3. rebuild / verification evidence

They also summarize function-level focus when scanner findings or detected input surfaces can be mapped to an enclosing C/C++ function.

The `audit` command can now also emit a structured JSON artifact with `--audit-json`. That export keeps the markdown report as-is and collects the main workflow outputs in one place for downstream tooling:

- scan summary and finding counts
- classified findings
- file and function hotspots
- function coverage
- input surfaces
- compile database summary
- verification and rebuild+verify results
- trace events and a concise command summary

These runtime/build evidence sections are conditional:

- verification evidence is only collected when `verification-plan.json` exists and points to a present binary
- rebuild+verify evidence is only collected when `compile_commands.json` exists

That means `audit` is not strictly read-only in repositories that provide those inputs; it may execute bounded local verification or rebuild steps as part of the workflow.

## Why this matters

A useful security agent should not produce a flat wall of grep hits. It should preserve the path from suspicion to validation so a human reviewer can quickly decide what to trust and what to investigate next.
