# Orchestrator interface

The project now includes a minimal orchestration layer.

## What it does

- reads `audit.json`
- builds a compact assessment
- selects top risks
- emits structured next actions for a future model-driven planner/executor loop
- tracks whether each action is contextual, directly executable, or blocked on missing prerequisites
- optionally feeds those ready actions into a minimal bounded `run-plan` executor

## Current action kinds

- `focus_functions`
- `inspect_file`
- `trace_input_surface`
- `verify_binary`
- `run_rebuild_verify`
- `inspect_rebuild_failure`
- `explain_root_cause`

## Plan shape

Each planned action now carries:

- a stable `id`
- `status` as `context`, `ready`, or `blocked`
- human-readable `title` and `rationale`
- `prerequisites` and `blocked_by` details
- optional `suggested_cli` for directly runnable steps
- `expected_outcome` and structured `params`

The top-level plan also includes a `readiness` block so a downstream loop can quickly decide what is executable next.

## Minimal executor loop

`python3 -m src.main run-plan --plan out/plan.json --output out/exec.json`

Current behavior is intentionally narrow:

- only actions already marked `ready` and carrying `suggested_cli` are considered runnable
- commands must be internal `python3 -m src.main ...` invocations
- only a small allowlisted subcommand set is executable (`verify-run`, `rebuild-target`, `rebuild-verify`, `rebuild-plan`)
- execution is sequential and bounded by `--max-actions` (default `1`)
- `--dry-run` validates and reports what would execute without actually running it
- each run emits a structured execution summary for downstream tooling

This gives the orchestration layer an actionable next step without opening the door to arbitrary shell execution.

## Why this matters

This is the first explicit bridge between the tool layer and a future base model. The model can consume a compact plan surface instead of raw tool output, and now also has a safe, minimal way to advance one verified step at a time.
