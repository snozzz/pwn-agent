# Executor

The executor now produces a richer execution summary and can persist bounded run state across turns.

## What it reports

- actions actually executed
- actions selected for execution
- actions completed successfully
- actions previewed in `--dry-run` (without marking them completed)
- actions previously completed in an earlier turn when a state file is resumed
- actions deferred because dependencies were not yet satisfied
- runnable action inventory after filters are applied
- remaining runnable actions after the current step
- `next_action_ids` so a controller can continue without recomputing dependency ordering
- status counts for downstream orchestration
- per-action state counts (`queued`, `deferred`, `running`, `completed`, `failed`, `previewed`, etc.)
- explicit transition entries showing how each selected action moved through the loop

## Resume support

`run-plan` now accepts an optional `--state out/state.json` path.

That file stores:

- current per-action states
- per-action signatures for reconciliation
- completed action ids
- the prior plan path/schema/fingerprint
- append-only transition history

If the file already exists, the executor resumes from it and skips actions already completed in a previous turn.
When the plan has been regenerated, the executor now reconciles the persisted state against the new plan by:

- carrying forward completed actions whose ids and signatures still match
- resetting actions whose ids were reused but whose runnable definition changed
- surfacing newly introduced action ids
- surfacing stale completed action ids that no longer exist in the plan

## Why it matters

This makes the `plan -> run-plan -> inspect results -> continue` loop easier to automate, because the next controller can see what remains runnable, what is still blocked by ordering, and what already completed in an earlier turn without recomputing everything from scratch.
