# Orchestrator interface

The project now includes a minimal orchestration layer.

## What it does

- reads `audit.json`
- builds a compact assessment
- selects top risks
- emits structured next actions for a future model-driven planner/executor loop

## Current action kinds

- `focus_functions`
- `inspect_file`
- `trace_input_surface`
- `run_rebuild_verify`
- `explain_root_cause`

## Why this matters

This is the first explicit bridge between the tool layer and a future base model. The model can consume a compact plan surface instead of raw tool output.
