# Agent Loop

`agent-loop` is a bounded local analysis loop layered on top of the binary planner and
executor. It implements an OODA-style cycle — observe → update state → select action →
execute bounded tool → collect evidence → replan — while the executor remains the sole
authority over what can run.

## Purpose

Each step, a **controller** chooses among already-planned bounded actions, explains the
choice, and the loop executes it through the existing executor. The controller emits
structured intent only; it never generates shell commands and only references action ids
present in the current bounded plan.

## Controller abstraction

Controllers implement `AgentModel.decide(context) -> decision` (`src/agent/controller.py`):

- `DeterministicController` — a real in-process policy over the candidate actions,
  evidence, and attempt history. The loop can run with **no pre-generated response file**.
- `ScriptedController` — replays a local JSON/JSONL list of decisions (the legacy
  behavior), seeded at the already-consumed index so resume is exact.

`build_controller(spec)` is the single registration point. **No network/model transport is
shipped.** A provider backend (Claude-compatible API, local Qwen, OpenAI-compatible
endpoint) is expected to implement `AgentModel` as an out-of-process adapter and register
here; `ModelDecision.usage` exists so such a backend can record token accounting later.

CLI selection (mutually exclusive, exactly one required):

- `--controller deterministic` — run the in-process controller.
- `--model-response-json <file>` / `--model-response-jsonl <file>` — scripted replay.

## Inputs

- current binary plan json
- current binary artifacts when available: analysis, crash triage, patch validation, verify
- a controller selection (in-process or scripted responses)
- optional loop state json / executor state json
- optional `--objective` recorded in the agent state

## Decision schema

A decision is validated against the bounded candidate set (`validate_decision`). The v1
contract is unchanged:

- `chosen_action_id` — must be a dependency-resolved bounded candidate from the current plan
- `rationale` — non-empty text
- `confidence` — numeric in `[0.0, 1.0]`
- `summary_update` — non-empty text

Optional v2 fields are validated only when present:

- `hypothesis` — the belief this action tests
- `expected_information_gain` — what the action is expected to reveal
- `state_update` — structured belief updates (e.g. `open_questions`, `add_hypotheses`)
- `usage` — token/tool-call accounting (nullable; for future provider backends)

## Structured state and evidence

Each step maintains an `AgentState` (`src/agent/state.py`) distinguishing observations,
evidence, verified facts (each backed by evidence ids), hypotheses (open/supported/
rejected + confidence), open questions, action/failure history, progress markers, and
budgets. After each execution the loop derives `EvidenceRecord`s (`src/agent/evidence.py`)
directly from executor output — `tool result → normalized observation → evidence record`.
Controller prose lands in `summary_updates` and can never overwrite verified facts or
evidence.

## Loop protection

Beyond step/failure budgets (`--max-steps`, `--max-failures`) the loop detects stagnation
(`src/agent/progress.py`):

- **no-progress** — a progress signature (completed actions + evidence fingerprints +
  runnable candidate ids) unchanged for `--max-no-progress` consecutive iterations.
- **repeated-action** — the same executed action id chosen `--max-repeats` times in a row.

## Terminal statuses

- `completed` — loop condition exhausted without a break
- `step-budget-exhausted` — `--max-steps` reached
- `no-candidate-actions` — the plan has no runnable bounded action
- `awaiting-model-output` — a scripted controller ran out of responses
- `invalid-model-output` — a decision failed validation (counts against failure budget)
- `controller-error` — a controller backend raised (counts against failure budget)
- `failure-budget-exhausted` — `--max-failures` reached
- `no-progress` / `repeated-action` — loop-protection guards fired

## Loop artifact

`agent-loop` emits `pwn-agent.agent-loop.v1`. Per iteration it records the artifact
snapshot, the candidate actions presented, the raw + normalized decision, the execution
result, per-iteration progress (`signature`, `progressed`, `no_progress_count`), and
replanned next actions when artifact-driven replanning was possible. Top level adds
`controller` (name), `agent_state` (full belief state), and a `final_summary` with verified
fact / hypothesis / evidence counts. Resume state uses `pwn-agent.agent-loop-state.v1` and
carries the serialized `agent_state`.

## Evaluation

`agent-eval` (`src/agent/evaluation.py`) turns one or more trajectories into measured
metrics — terminal-state classification, steps, successful/failed/rejected actions,
repeated actions, no-progress iterations, recovered failures, evidence/fact counts — and
can compare several controllers on the same task. Every field is measured; fields the
pipeline does not yet record (wall-clock time, provider tokens) are reported as `null`.

## Safety model

- local authorized binaries/projects only; no remote targeting
- no unrestricted shell autonomy; no model-generated shell commands
- **no built-in remote inference or model transport**
- the controller may only reference bounded candidate action ids
- the executor still validates `chosen_action_id` against the bounded plan and runs
  everything through the command-policy layer
- `agent-loop` and `agent-eval` are control-plane subcommands and are not executor-eligible
  (no recursive self-invocation through a plan)
