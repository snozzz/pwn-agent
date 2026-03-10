# Deduplication

The MVP now deduplicates findings during reporting and SARIF export.

## Current dedup key

- category
- file path
- line number

## Why it matters

As the agent grows more complex, the same issue can be surfaced by multiple passes. Deduplication keeps the output readable and avoids overwhelming reviewers.
