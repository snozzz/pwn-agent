# Orchestrator interface

The project now includes a staged orchestration layer.

## What it does

- reads `audit.json`
- builds a compact assessment
- selects top risks
- emits structured next actions for a future model-driven planner/executor loop
- tracks whether each action is contextual, directly executable, or blocked on missing prerequisites
- groups actions into explicit phases so a downstream loop can separate triage, execution, and synthesis work
- preserves runnable execution actions even after verification already produced a signal
- optionally feeds those ready actions into a minimal bounded `run-plan` executor

## Current action kinds

Context / synthesis:

- `focus_functions`
- `inspect_file`
- `trace_input_surface`
- `explain_root_cause`

Executable:

- `verify_binary`
- `list_rebuild_targets`
- `rebuild_target`
- `run_rebuild_verify`
- `inspect_rebuild_failure`

## Plan shape

Each planned action now carries:

- a stable `id`
- a `phase` (`triage`, `execution`, or `synthesis`)
- `status` as `context`, `ready`, or `blocked`
- human-readable `title` and `rationale`
- `depends_on`, `prerequisites`, and `blocked_by` details
- optional `suggested_cli` for directly runnable steps
- `expected_outcome` and structured `params`

The top-level plan also includes a `readiness` block with:

- counts for ready, runnable, blocked, and context actions
- phase counts
- verification/rebuild state
- missing prerequisites

Plans now also include a `stage_guidance` block with:

- `recommended_action_ids` for the next bounded loop turn
- `recommended_phase` so a controller can keep the audit staged
- `stage_heads` pointing at the highest-priority action in each phase
- `blocked_action_ids` so prerequisite work stays visible

That gives a downstream loop a tighter control surface than raw audit output.

## Minimal executor loop

`python3 -m src.main run-plan --plan out/plan.json --output out/exec.json`

Current behavior is intentionally narrow:

- only actions already marked `ready` and carrying `suggested_cli` are considered runnable
- commands must be internal `python3 -m src.main ...` invocations
- only a small allowlisted subcommand set is executable (`verify-run`, `rebuild-target`, `rebuild-verify`, `rebuild-plan`)
- execution is sequential and bounded by `--max-actions` (default `1`)
- `--phase execution` can filter to one stage when the caller only wants runnable tool work
- `depends_on` is respected during selection, so rebuild+verify can stay gated behind target enumeration/rebuild steps
- `--dry-run` validates and reports what would execute without actually running it
- each run emits a structured execution summary for downstream tooling
- execution summaries now include runnable/deferred action inventory so a controller can see what remains blocked only by ordering

## Why this matters

This is a better bridge between the tool layer and a future base model.

The model can now consume a compact phased plan surface instead of raw tool output, keep meaningful replayable tool actions around even after evidence exists, and advance the audit one bounded internal step at a time without opening the door to arbitrary shell execution.
