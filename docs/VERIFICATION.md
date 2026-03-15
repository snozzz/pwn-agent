# Verification support

The repo includes a bounded binary verification helper that can run a local target inside workspace bounds and emit a `pwn-agent.binary-verify.v1` artifact.

## Current scope

- local binary execution inside workspace bounds
- simple argv injection
- detection of common AddressSanitizer / UBSan markers
- normalized runtime result fields including return code, timeout, and signal name when available
- binary-planner consumption of verify artifacts as bounded replanning evidence
- audit/export summaries now distinguish `ready`, `blocked-missing-binary`, and completed verification states

## Why this matters

This starts separating:

- heuristic suspicion
- tool-backed verification evidence

That distinction is essential for making the agent useful to an actual security team.
