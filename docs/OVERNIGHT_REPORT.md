# Overnight Report

Branch: `agent-v2` (off `main`), pushed to `origin` after each module.
Scope honored: all work is in the agent **reasoning layer**; the executor / command
policy / command registry **enforcement boundary was not weakened**. No remote-target
workflow, no arbitrary shell, no network/model transport were added.

## What I found

The repository is a well-factored, bounded, local binary-analysis CLI. Two planners
(binary stage-based, audit phase-based) feed one executor that is the sole execution
authority: it only runs bounded **leaf** subcommands with workspace-bound paths through a
`CommandPolicy` allowlist with per-command argv validators. That safety core is solid.

The weakness was entirely above it, in the agent loop (documented as W1–W8 in
`OVERNIGHT_BASELINE.md`):

- **W1 — no controller abstraction.** `run_agent_loop` replayed a static JSON/JSONL list
  of decisions; there was no seam to invoke a real decider, a test mock, or a future
  provider. This was the central limitation called out in the task.
- **W2/W3 — impoverished state, no evidence ledger.** Loop state was counters plus
  free-form prose; conclusions were not traceable to the tool output that justified them.
- **W4 — no loop protection.** Only budgets stopped the loop. I reproduced an infinite
  re-suggest of `collect-binary-evidence` live on an arm64/Mach-O target.
- **W5 — thin decision schema.** No hypothesis / expected-information-gain / structured
  state update.
- **W6/W7/W8 — replan clobbers belief, no evaluation, monolithic loop function.**

Baseline test suite: 67 passing on CPython 3.11. (Canonical interpreter is 3.11 per
`pyproject.toml`; the executor subprocesses `python3` — 3.8 here — so product code is kept
3.8-compatible.)

## What I changed

New package `src/agent/` (reasoning layer; nothing in it executes commands):

- `state.py` — `AgentState` belief state: objective, observations, evidence, verified
  facts (evidence-backed), hypotheses (open/supported/rejected + confidence), open
  questions, action/failure history, progress markers, budgets. `to_dict`/`from_dict`.
- `evidence.py` — `EvidenceRecord` + `build_evidence_record`: normalizes a bounded tool
  result into a verified observation with an order-independent artifact fingerprint and
  subcommand→artifact-slot routing. `artifact_slot_for_command` helper.
- `controller.py` — `AgentModel` ABC, `AgentContext`, `ModelDecision`, `validate_decision`
  (v1 rules/errors preserved verbatim; v2 fields optional), `normalize_decision`,
  `ScriptedController`, `DeterministicController`, `build_controller`. No network backend.
- `progress.py` — progress signature, stall-counter assessment, repeated-action detection,
  `no-progress`/`repeated-action` status constants.
- `evaluation.py` — `evaluate_trajectory`, `compare_trajectories`,
  `render_evaluation_markdown`; measured-only metrics.

Integration:

- `src/modes/binary/loop.py` — rewired to decide through a controller; derives evidence
  and maintains a persisted `AgentState` each step; adds loop-protection guards and the
  new terminal statuses; trajectory gains `controller`, `agent_state`, and per-iteration
  `progress` (all additive). Scripted replay + resume semantics (`consumed_model_responses`)
  preserved exactly.
- `src/modes/binary/cli.py` — `--controller deterministic`, `--objective`,
  `--max-no-progress`, `--max-repeats`; new `agent-eval` subcommand.
- `src/command_registry.py` — `agent-eval` registered **control-plane** (not
  executor-eligible); `--trajectory`/`--metrics` added to path-option validation.
- `scripts/run_tests.py` — pytest-free unittest runner (tests/ is not a package).
- Docs: `AGENT_LOOP.md` rewritten; `README.md` and `PROGRESS.md` updated; baseline/plan/
  worklog added.

## Why

The research goal is autonomous reasoning that chooses among safe bounded capabilities,
with the executor as the authority. A controller seam is the minimum change that turns a
decision-replayer into an agent that can be driven by a deterministic policy today and a
Claude/Qwen backend later — without coupling the repository to any provider or adding a
network client. Structured state + an evidence ledger make trajectories analyzable and are
the substrate for the fine-tuning dataset described in `FINETUNE_PLAN.md`. Loop protection
makes episodes terminate honestly (and is a measurable signal). The evaluation harness is
what lets the project compare controllers — the experiment the repo exists to run.

## Tests

Runner: `python3 scripts/run_tests.py .`

- CPython 3.11.11 (macOS/arm64): **132 passed, 0 failed, 0 errors** (67 baseline + 65 new).
- CPython 3.12.3 (Linux/x86_64, researcher host): **132 passed, 0 failed, 0 errors**.
- New tests: `test_agent_state.py` (11), `test_agent_evidence.py` (7),
  `test_agent_controller.py` (23), `test_agent_progress.py` (10),
  `test_agent_evaluation.py` (8), `test_agent_loop_v2.py` (6). All 6 legacy
  `test_agent_loop.py` tests pass unchanged.

Live end-to-end (real binaries, not fabricated):

- macOS/arm64 Mach-O: `binary-scan → binary-plan → agent-loop --controller deterministic`
  drove a real `identify → reproduce → no-candidate-actions` episode with no response file;
  `agent-eval` reported 2 steps, 2 evidence records, clean termination.
- Linux/x86_64 ELF (`examples/vuln_demo.c`, `gcc -fno-stack-protector -no-pie`): a 300-byte
  argument produced a real **SIGSEGV** crash; `crash-triage --gdb-batch` recorded
  `suspicious=true, signal=SIGSEGV, gdb collected=true`; the deterministic controller then
  drove a clean autonomous episode and `agent-eval` scored it. Artifacts are on the host at
  `~/pwn-agent-demo/ws/` (left in place rather than deleted).

## Remaining limitations

1. **No provider backend shipped.** Only the `AgentModel` seam + deterministic and scripted
   controllers exist. Wiring Claude/Qwen is deliberately left as an out-of-process adapter
   (keeps "no network transport" true). The deterministic controller is a sensible policy,
   not a strong reasoner.
2. **Belief state is recomputed, not merged, on replan.** Evidence carries forward, but
   hypotheses are not reconciled against a regenerated plan (W6 partially addressed).
3. **gdb batch parsing is thin.** On the `-no-pie` x86 target, registers/backtrace arrays
   came back empty even though collection succeeded; the parser needs hardening.
4. **No failure-driven alternative selection.** After a failed action the loop counts the
   failure; it does not yet prefer a different bounded action as recovery.
5. **Evaluation is single-episode.** No batch runner to average metrics across seeds/targets
   or to emit a controller-comparison table across many tasks.
6. **checksec absent** on both test hosts, so the mitigations summary is "unknown"; this
   keeps the planner re-suggesting `collect-binary-evidence` until the executor marks it
   complete. Not a bug, but it shapes the demo trajectories.

## Recommended next steps (prioritized)

1. Implement an out-of-process provider adapter for `AgentModel` (Claude-compatible first,
   then local Qwen via an OpenAI-compatible endpoint), reading context and returning a
   decision; keep it behind `build_controller` with no transport in `src/agent`.
2. Add failure-driven recovery: on a failed/invalid action, bias the next decision toward an
   un-attempted bounded candidate; add a terminal `exhausted-alternatives`.
3. Merge belief across replans: reconcile hypotheses/verified facts against the regenerated
   plan instead of recomputing, mirroring the executor's signature reconciliation.
4. Harden gdb batch parsing (registers/backtrace/mappings) and add a fixture-based test on a
   known-crashing ELF.
5. Add a batch evaluation runner (`agent-eval` over a directory of trajectories) that emits a
   controller-comparison table and per-metric aggregates.
6. Capture decision-time context + outcome into a JSONL trajectory export shaped for the
   `FINETUNE_PLAN.md` dataset (input: context/evidence; output: decision + confidence).
7. Record wall-clock time per iteration and plumb provider `usage` into the trajectory so the
   already-present eval fields stop being null.
8. Extend `DeterministicController` with a small evidence-aware policy (e.g. prefer triage
   when a suspicious crash lacks debugger context) and unit-test the preference order.

## Questions for the researcher

(None of these blocked tonight's work; conservative assumptions were made and recorded.)

1. Which provider should be the first real backend — a Claude-compatible API, or local Qwen
   via llama.cpp/an OpenAI-compatible endpoint? That decides the first adapter.
2. Confirm the adapter must stay out-of-process with no network client inside `src/agent`
   (my assumption, to preserve "no remote transport"). If an in-repo HTTP client to a
   **local** endpoint is acceptable, I can add one gated behind explicit config.
3. For `agent-eval`, do you want a fixed task suite (specific local/CTF ELFs) checked into
   the repo as the evaluation benchmark, or should eval stay trajectory-only?
4. Should the belief state persist across *separate* episodes on the same target (a per-target
   memory), or remain per-episode as it is now?
5. Is installing `checksec`/`gdb` on the test host desirable so the planner exercises the
   mitigation-aware branches, or should the agent treat missing tools as first-class
   "evidence unavailable" (current behavior)?
6. Preferred objective phrasing/taxonomy for `--objective`, if you want it to drive planner
   or controller behavior later rather than only being recorded.
