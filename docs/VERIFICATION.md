# Verification support

The MVP now includes a binary verification helper that can run a local instrumented target and inspect its output for sanitizer signals.

## Current scope

- local binary execution inside workspace bounds
- simple argv injection
- detection of common AddressSanitizer / UBSan markers

## Why this matters

This starts separating:

- heuristic suspicion
- tool-backed verification evidence

That distinction is essential for making the agent useful to an actual security team.
