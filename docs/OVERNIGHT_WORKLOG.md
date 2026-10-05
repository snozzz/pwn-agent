# Overnight Worklog

This file is the resume point. Another context window can continue from "Next task".

## Conventions

- Branch: `agent-v2` (off `main`). Push per completed module.
- Canonical test interpreter: `~/.pyenv/versions/3.11.11/bin/python3.11`.
- Product code must stay **3.8-compatible** (executor subprocesses `python3` = 3.8.20).
- Run tests:
  `~/.pyenv/versions/3.11.11/bin/python3.11 <scratch>/run_tests.py .`
  (tests/ is not a package; the runner adds repo root to sys.path and loads each
  `tests/test_*.py`). A committed equivalent lives at `scripts/run_tests.py`.
- Safety invariant that MUST hold: model emits intent (action id + prose) only; executor
  remains the sole authority; no remote transport; no arbitrary shell.

## Assumptions recorded

- A1. "Clean controller abstraction" = an in-process `AgentModel` interface the loop calls
  each step. We ship a deterministic controller and a scripted (replay) controller.
  We do NOT add any live network/provider client (respects "no remote transport",
  "no third-party systems"). Provider backends are documented as adapters implementing
  the interface out of process; the trajectory schema is made able to store token usage
  for when such a backend is added.
- A2. Backward compatibility is required: existing `--model-response-json/jsonl` flow and
  all 67 tests must keep passing. New fields are additive; new terminal statuses are new.
- A3. New control-plane subcommands (e.g. `agent-eval`) are registered as control-plane
  (NOT executor-eligible) so they cannot be invoked recursively through a plan.

## Test status

- Baseline: 67 passed / 0 failed (py3.11).
- Current: see latest "Completed" entry.

## Completed

- Phase 0 baseline established → `docs/OVERNIGHT_BASELINE.md`.
- Phase 1/2 review + prioritized plan → `docs/AGENT_V2_PLAN.md`.

## Current task

(implementation in progress — see AGENT_V2_PLAN.md ordering)

## Next task

Module order (each = commit + push):
1. `src/agent/state.py` + `src/agent/evidence.py` (+ tests) — structured state & evidence.
2. `src/agent/controller.py` (+ tests) — AgentModel / ModelDecision / scripted+deterministic.
3. `src/agent/progress.py` (+ tests) — duplicate + no-progress detection.
4. Integrate into `src/modes/binary/loop.py` + `cli.py` (+ loop tests), keep back-compat.
5. `src/agent/evaluation.py` + `agent-eval` CLI (+ tests).
6. Docs: AGENT_LOOP.md, PROGRESS.md, README, OVERNIGHT_REPORT.md.

## Discovered problems

- W4 (no-progress) is reproducible live: on arm64/Mach-O targets the planner re-suggests
  `collect-binary-evidence` indefinitely. Loop protection (module 3) must catch this.
