# Risk hotspots

The MVP now produces both file-level risk hotspots and best-effort function focus.

## Inputs to hotspot scoring

- classified findings and their scores
- detected input surfaces
- verification-aware finding status
- enclosing function matches when a finding or surface can be mapped to one

## Why it matters

A security agent should help reviewers decide where to spend attention first. File-level hotspot ranking gives broad triage,
while function focus narrows that attention to the smallest likely review target without requiring a full parser.
