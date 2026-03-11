# Executor

The executor now produces a richer execution summary.

## What it reports

- actions actually executed
- actions selected for execution
- actions completed successfully or hypothetically completed in `--dry-run`
- actions deferred because dependencies were not yet satisfied
- runnable action inventory after filters are applied
- remaining runnable actions after the current step
- `next_action_ids` so a controller can continue without recomputing dependency ordering
- status counts for downstream orchestration

## Why it matters

This makes the `plan -> run-plan -> inspect results -> continue` loop easier to automate, because the next controller can see what remains runnable versus what is still blocked by ordering.
