# Overnight Baseline

Status: established before any code changes in the Agent v2 effort.
Interpreter note: the canonical test interpreter is CPython 3.11 (per `pyproject.toml`
`requires-python = ">=3.11"`). The executor spawns `python3` from `PATH` as a
subprocess for internal leaf commands; on this machine that is CPython 3.8.20, so
**product code must remain runtime-compatible with 3.8** even though tests run on 3.11.
This was verified: `src.executor` imports cleanly under 3.8, and the agent-loop tests
(which subprocess `python3 -m src.main ...`) pass with that 3.8 subprocess.

## 1. Current architecture

The repository is a bounded, local, evidence-driven security-analysis CLI with two
modes layered on a shared execution/policy core.

```
                 ┌──────────────────────────────────────────────┐
                 │                 src/main.py                    │
                 │   argparse dispatch over two mode CLIs         │
                 └───────────────┬───────────────┬────────────────┘
                                 │               │
                   audit mode ───┘               └─── binary mode (primary focus)
          src/modes/audit/cli.py                  src/modes/binary/cli.py
          src/orchestrator.py (planner)           src/modes/binary/workflow.py (planner + tools)
                                                   src/modes/binary/loop.py  (agent loop)
                                                   src/modes/binary/patching.py (bounded patch+validate)
                                 │               │
                                 └──────┬────────┘
                                        ▼
                         src/executor.py  (the execution authority)
                  inspect_plan() / execute_plan() / ExecutionState
                                        ▼
                         src/policy.py  (CommandPolicy)
                 src/command_registry.py (allowlist + per-command validators)
                                        ▼
                              local bounded tools
         (ls/find/rg/grep/file/checksec/readelf/objdump/nm/strings/
          build toolchain/clang-tidy/cppcheck/gdb-batch/ python3 -m src.main <leaf>)
```

### Two planners, one executor

- **Binary planner** (`build_binary_plan` in `workflow.py`): deterministic, *stateless*
  function. Input = one or more evidence artifacts (analysis / crash / patch-validation /
  verify). Output = `pwn-agent.binary-plan.v2` with `next_actions[]`. Stage model:
  `identify → inspect → reproduce → triage → patch → validate → summarize`.
- **Audit planner** (`build_plan` in `orchestrator.py`): phase-oriented
  (`triage/execution/synthesis`) for source audits. Emits `plan_schema_version=2`.
- Both emit the same `next_actions` action shape consumed by the executor.

### The executor is the authority (critical safety property)

`src/executor.py` is the only component that turns a plan action into a running process:

- `_validate_suggested_cli` → `validate_main_cli(..., allowed_subcommands=LEAF_MAIN_SUBCOMMANDS)`:
  only **leaf** internal subcommands may execute; control-plane subcommands
  (`binary-plan`, `binary-run`, `agent-loop`) are rejected, preventing recursive
  self-invocation through a plan.
- `--root` of an action must match the plan/workflow root; all path-bearing options are
  forced to resolve inside `--root`.
- Execution always goes through `CommandPolicy.run_validated`, which enforces the
  allowlist, per-command argv validators, timeouts, and output truncation.
- Per-action state machine (`queued/deferred/running/completed/failed/previewed`) is
  tracked in `ExecutionState` and can be persisted/resumed and reconciled against a
  regenerated plan (signatures carry completed work forward, reset changed actions).

### CommandPolicy / command registry

`command_registry.py` defines a frozen `COMMAND_POLICY_REGISTRY: {executable → CommandRule}`.
Each rule has a `validator` that constrains exact argv shape (e.g. `readelf` only
`-h|-s|-Ws <target>`, `gdb` only a fixed batch of approved `-ex` expressions). Every
path argument is bound inside the workspace root. `CommandPolicy` also pins per-command
timeouts and stdout/stderr truncation. This is the hard safety boundary.

## 2. Current loop lifecycle (`run_agent_loop` in `loop.py`)

Per iteration, while `step_count < max_steps` and `failure_count < max_failures`:

1. **Observe**: load artifact snapshots; `inspect_plan()` → dependency-resolved
   `candidate_actions` + runnable/deferred ids.
2. **Terminate early** if no candidate actions (`no-candidate-actions`).
3. **Decide**: pop the *next pre-generated* model response from a json/jsonl list
   (`consumed_model_responses` index). If the list is exhausted →
   `awaiting-model-output`.
4. **Validate** the choice (`_validate_model_choice`): `chosen_action_id` must be a
   current candidate; `rationale`/`summary_update` non-empty; `confidence ∈ [0,1]`.
   Invalid → `failure_count++`, status `invalid-model-output`.
5. **Execute**: `execute_plan(..., action_id=chosen, max_actions=1)` through the executor.
   A failed command increments `failure_count`.
6. **Update evidence**: `_update_artifact_paths` maps the executed action's `--output`
   onto an artifact slot (analysis/crash/patch-validation/verify).
7. **Replan**: `_replan_from_artifacts` re-runs `build_binary_plan` from the current
   artifacts and overwrites the plan file.
8. **Account**: `step_count++`; append an `iteration` record to the trajectory.

Terminal statuses observed: `completed`, `no-candidate-actions`, `awaiting-model-output`,
`invalid-model-output`, `failure-budget-exhausted`, `step-budget-exhausted`.

Persistence: loop state `pwn-agent.agent-loop-state.v1`, trajectory
`pwn-agent.agent-loop.v1`, executor state (separate file).

## 3. Major schemas / artifacts

| Schema | Producer | Role |
|---|---|---|
| `pwn-agent.binary-analysis.v1` | `scan_binary` | static evidence (metadata, mitigations, imports, strings) |
| `pwn-agent.binary-crash-triage.v1` | `triage_binary_crash` | runtime crash evidence + optional gdb batch |
| `pwn-agent.binary-verify.v1` | `verify_binary_execution` | bounded runtime verification result |
| `pwn-agent.binary-patch-candidate.v1` / `pwn-agent.patch-script.v1` | input | bounded patch intent |
| `pwn-agent.binary-patch-validation.v1` | `patch_validate` | isolated rebuild + launch/regression validation |
| `pwn-agent.binary-plan.v2` | `build_binary_plan` | deterministic next-action plan |
| executor state (inline schema) | `execute_plan` | per-action state machine + history |
| `pwn-agent.agent-loop.v1` | `run_agent_loop` | trajectory |
| `pwn-agent.agent-loop-state.v1` | `run_agent_loop` | resumable loop state |
| `pwn-agent.model-choice.v1` | (input, validated in loop) | the model decision |

## 4. Current safety boundaries (must be preserved)

1. Model emits **intent only** (`chosen_action_id` + prose), never shell commands.
2. Executor rejects any `suggested_cli` that is not a bounded **leaf** subcommand.
3. `CommandPolicy` allowlist + per-command argv validators + workspace-bound paths.
4. All file paths are forced inside `--root` / workspace root.
5. Per-command timeouts and output truncation.
6. No network/remote transport anywhere in the loop; inference transport is out of
   process (the loop reads a local file of decisions).
7. Control-plane subcommands cannot be executed by the executor (no recursion).

## 5. Current model integration

There is **no model/controller abstraction**. The "model" is a static json/jsonl file of
pre-generated `model-choice` objects consumed sequentially. The loop cannot call a live
controller (deterministic policy, Claude API, local Qwen, etc.) without editing
`run_agent_loop` directly. This is the central architectural gap for Agent v2.

## 6. Test baseline

- Command: load every `tests/test_*.py` via a `unittest` loader (tests/ is not a package;
  a 3-line runner adds repo root to `sys.path`). `pytest` is not installed.
- Result (CPython 3.11.11): **67 tests, 0 failures, 0 errors, 0 skipped.**
- Toolchain on this host: `checksec`, `clang`, `gcc`, `rg` present; `gdb`, `cppcheck`,
  `clang-tidy` **absent** — the suite is green regardless, so those paths are either
  mocked or gated at runtime (gdb batch evidence is marked unavailable rather than
  failing).
- End-to-end smoke (verified live): compiled `examples/vuln_demo.c`, ran
  `binary-scan → binary-plan → agent-loop`; loop executed the chosen bounded action,
  replanned from the refreshed analysis artifact, and produced a well-formed trajectory.

## 7. Architectural weaknesses observed (input to Phase 1/2)

W1. **No controller abstraction.** The loop is hard-wired to replay a static decision
    list. No seam for a deterministic policy, a mock, or a future Claude/Qwen backend.
    (`loop.py` `_load_model_responses` + inline consumption.)

W2. **Impoverished state.** Loop state tracks only counters + free-form `summary_updates`
    prose + `last_plan_fingerprint`. There is no structured representation of
    observations, evidence, hypotheses, verified facts, rejected hypotheses, or open
    questions. Research questions ("why was this action chosen, what evidence existed")
    can only be reconstructed by re-reading prose.

W3. **No evidence ledger.** Conclusions are not linked to the tool output that justifies
    them (observation → source → hypothesis → verification → confidence). Replanning
    reads artifacts but discards the provenance chain.

W4. **No loop protection beyond budgets.** There is no duplicate-action detection and no
    no-progress detection. **Confirmed live**: on an arm64/Mach-O target where
    `_analysis_has_mitigations` stays false, executing `collect-binary-evidence` leaves it
    a runnable candidate, so a larger `--max-steps` would re-run the identical action
    every iteration without flagging stagnation.

W5. **Thin decision schema.** `model-choice` has no `hypothesis`, no
    `expected_information_gain`, and no structured `state_update`; the controller cannot
    express *why* an action advances the investigation in machine-readable form.

W6. **Replan can clobber, not merge.** `_replan_from_artifacts` overwrites the plan file
    from artifacts each step; combined with W2/W3 there is no accumulated belief state
    that survives replanning other than the executor's completed-action reconciliation.

W7. **No evaluation harness.** There is no way to score a trajectory (completion, steps,
    repeats, no-progress, recovered failures, terminal state) or to compare controllers.

W8. **Coupling.** `run_agent_loop` couples observation, decision-sourcing, execution,
    artifact-mapping, replanning, and accounting in one function, making controller/state
    experimentation hard to isolate or unit-test.

None of these weaknesses are in the *safety* core (executor/policy/registry), which is
well-factored. The weaknesses are all in the **agent reasoning layer** above it — exactly
where Agent v2 should focus, without touching the enforcement boundary.
