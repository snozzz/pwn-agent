# Finding classification

The MVP now assigns a first-pass status to findings.

## Current labels

- `heuristic`: matched by source scanning only
- `verified`: elevated when runtime verification evidence supports a likely memory-safety issue

## Current metadata

- severity
- confidence
- score

## Why it matters

This helps human reviewers triage results quickly instead of treating every grep hit as equally important.
