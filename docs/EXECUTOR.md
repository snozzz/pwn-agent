# Executor

The executor now produces a richer execution summary.

## What it reports

- actions actually executed
- actions selected for execution
- actions deferred because dependencies were not yet satisfied
- runnable action inventory after filters are applied
- status counts for downstream orchestration

## Why it matters

This makes the `plan -> run-plan -> inspect results -> continue` loop easier to automate, because the next controller can see what remains runnable versus what is still blocked by ordering.
