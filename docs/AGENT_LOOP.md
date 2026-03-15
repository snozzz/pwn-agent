# Agent Loop

`agent-loop` is a bounded local analysis assistant layered on top of the existing binary planner and executor.

## Purpose

The loop lets a model choose among already-planned bounded actions, explain the choice, and optionally execute it through the existing executor.

The model does not generate shell commands.
It only emits structured JSON that references action ids already present in the bounded plan.

## Inputs

- current binary plan json
- current binary artifacts, when available:
  - analysis
  - crash triage
  - patch validation
  - verify
- structured model response json or jsonl stream
- optional loop state json
- optional executor state json

## Model Choice Schema

Each model response must be a JSON object with:

- `chosen_action_id`
- `rationale`
- `confidence`
- `summary_update`

Validation rules:

- `chosen_action_id` must be one of the dependency-resolved bounded candidate actions from the current plan
- `rationale` must be non-empty text
- `confidence` must be numeric in `[0.0, 1.0]`
- `summary_update` must be non-empty text

## Loop Artifact

`agent-loop` emits `pwn-agent.agent-loop.v1`.

It records:

- artifact snapshot before each iteration
- candidate actions presented to the model
- raw and normalized model choice
- execution result
- replanned next actions, when artifact-driven replanning was possible
- final summary text assembled from `summary_update` fields

Persistent resume state uses `pwn-agent.agent-loop-state.v1`.

## Safety Model

- local authorized binaries/projects only
- no remote targeting
- no unrestricted shell autonomy
- no model-generated shell commands
- executor still validates `chosen_action_id` against the bounded plan
- command execution still goes through the existing command-policy and executor layers

## Resume and Budgets

The loop supports:

- `--max-steps`
- `--max-failures`
- `--dry-run`
- resume from loop state
- resume from executor state

Model responses are consumed sequentially from the provided json/jsonl source, and the loop state tracks how many responses were already consumed.
