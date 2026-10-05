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
- Current: 124 passed / 0 failed (py3.11).

## Completed

- Phase 0 baseline established → `docs/OVERNIGHT_BASELINE.md`.
- Phase 1/2 review + prioritized plan → `docs/AGENT_V2_PLAN.md`.
- Module 1 (commit d8f5092, pushed): `src/agent/state.py` + `evidence.py` + tests.
- Module 2 (commit 7795b0f, pushed): `src/agent/controller.py` + tests.
- Module 3 (commit 2bb4d34, pushed): `src/agent/progress.py` + tests.
- Module 4 (commit 6028aff, pushed): loop/cli integration + v2 tests. Deterministic
  controller verified live via CLI (`--controller deterministic`, no response file).

- Module 5 (commit 3297046, pushed): `src/agent/evaluation.py` + `agent-eval` CLI + tests.
- x86 ELF end-to-end on researcher host: suite 132 passing on py3.12/x86_64; real SIGSEGV
  crash-triage with gdb-batch; deterministic loop clean episode; agent-eval metrics.
- Module 6 (docs): AGENT_LOOP.md rewritten, README + PROGRESS updated, OVERNIGHT_REPORT.md.

## Current task

Session wrap-up complete. All planned modules landed and pushed.

## Next task

See `docs/OVERNIGHT_REPORT.md` "Recommended next steps" (provider adapter first).

## Available resources

- Researcher-provided **x86_64 Linux (WSL2)** host reachable over SSH (key-based auth
  already set up; connection details intentionally NOT committed). Has `gdb`, `readelf`,
  `gcc`, `python3`; `checksec` not present. Use only for an optional realistic ELF +
  gdb crash-triage end-to-end validation near the end. All development stays local with
  fixtures; the suite does not depend on this host.

## Discovered problems

- W4 (no-progress) is reproducible live: on arm64/Mach-O targets the planner re-suggests
  `collect-binary-evidence` indefinitely. Loop protection (module 3) must catch this.
