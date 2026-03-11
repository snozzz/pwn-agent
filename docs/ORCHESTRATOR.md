# Orchestrator interface

The project now includes a minimal orchestration layer.

## What it does

- reads `audit.json`
- builds a compact assessment
- selects top risks
- emits structured next actions for a future model-driven planner/executor loop
- tracks whether each action is contextual, directly executable, or blocked on missing prerequisites

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

## Why this matters

This is the first explicit bridge between the tool layer and a future base model. The model can consume a compact plan surface instead of raw tool output.
