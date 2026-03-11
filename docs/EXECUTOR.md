# Executor

The executor now produces a richer execution summary and can persist bounded run state across turns.

## What it reports

- actions actually executed
- actions selected for execution
- actions completed successfully or hypothetically completed in `--dry-run`
- actions previously completed in an earlier turn when a state file is resumed
- actions deferred because dependencies were not yet satisfied
- runnable action inventory after filters are applied
- remaining runnable actions after the current step
- `next_action_ids` so a controller can continue without recomputing dependency ordering
- status counts for downstream orchestration
- per-action state counts (`queued`, `deferred`, `running`, `completed`, `failed`, `dry-run`, etc.)
- explicit transition entries showing how each selected action moved through the loop

## Resume support

`run-plan` now accepts an optional `--state out/state.json` path.

That file stores:

- current per-action states
- completed action ids
- append-only transition history

If the file already exists, the executor resumes from it and skips actions already completed in a previous turn.

## Why it matters

This makes the `plan -> run-plan -> inspect results -> continue` loop easier to automate, because the next controller can see what remains runnable, what is still blocked by ordering, and what already completed in an earlier turn without recomputing everything from scratch.
