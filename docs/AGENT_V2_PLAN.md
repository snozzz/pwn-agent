# Agent v2 Plan

Phase 1 (architecture review) findings and Phase 2 (prioritized engineering plan).
Scope guardrail: every change is in the **agent reasoning layer** above the executor. The
executor / `CommandPolicy` / command registry enforcement boundary is **not modified**.

## Phase 1 — architecture review (as an autonomous agent)

### Controller
There is no model/controller abstraction (baseline W1). `run_agent_loop` sources decisions
by indexing a static list loaded from a json/jsonl file. Consequences:
- cannot run the loop without pre-generating decisions;
- no seam for a deterministic policy, a test mock, or a future Claude/Qwen backend;
- provider logic, if added naively, would be hard-wired into the loop.
Clean separation that *does* exist and should be kept: planner (intent space) vs executor
(enforcement) vs registry (capabilities). The missing seam is specifically the **decider**.

### Agent state
Current loop state = counters (`step_count`, `failure_count`, `consumed_model_responses`),
a list of free-form `summary_updates`, and `last_plan_fingerprint` (W2). It cannot
distinguish observations, verified facts, hypotheses, uncertainties, failed hypotheses,
attempted actions, action results, remaining objectives, confidence, or terminal
conditions as structured data. Everything reasoning-level is prose.

### Evidence
Conclusions are not traceable to the tool output that justifies them (W3). The executor
records command output, and replanning reads artifacts, but there is no
observation→source→hypothesis→verification→confidence ledger. Prose summaries and verified
tool results are not kept distinct.

### Planning
The deterministic binary planner is sound for stage transitions, dependency handling
(`depends_on`/`blocked_by`), and stale-plan reconciliation (executor signatures). Gaps:
- repeated/duplicate actions are not detected (W4) — confirmed live infinite re-suggest of
  `collect-binary-evidence`;
- no-progress is not detected across iterations (W4);
- evidence-driven replanning overwrites the plan but accumulates no belief state (W6);
- failed-action recovery is only "count a failure and maybe stop", with no alternative-
  action selection.

### Agent loop
The loop consuming pre-generated responses is the central limitation. It also couples
observation, decision-sourcing, execution, artifact-mapping, replanning, and accounting in
one function (W8), which blocks controller/state experimentation.

### Recovery
Present: invalid model output (counted), tool failure (counted), timeout (executor rc=124),
exhausted budgets (terminal). Missing: repeated identical actions, repeated identical
observations, planner dead ends, no-progress detection, and any notion of trying a
different bounded action after a failure.

### Termination
Present: `completed`, `no-candidate-actions`, `awaiting-model-output`,
`invalid-model-output`, `failure-budget-exhausted`, `step-budget-exhausted`. Missing: a
distinct `no-progress` / repeated-loop terminal, and an explicit "objective-complete"
signal separate from "ran out of budget".

## Phase 2 — prioritized plan

Ranking: P0 prevents genuine autonomy · P1 major reliability/research quality ·
P2 important architecture · P3 later.

---

### P0-1 — Controller abstraction (`AgentModel` / `ModelDecision`)
- **Current behavior**: decisions are read from a static json/jsonl list.
- **Problem**: no dynamic controller; the loop cannot invoke a real decider; no test mock.
- **Failure scenario**: to evaluate any policy you must hand-author its exact decision
  sequence in a file; a wrong length silently yields `awaiting-model-output`.
- **Solution**: `src/agent/controller.py` with an `AgentModel` ABC
  (`decide(context) -> ModelDecision`), a `ModelDecision` dataclass, a `ScriptedController`
  (replays the existing file = back-compat), a `DeterministicController` (real in-process
  policy over candidate actions + evidence/state), and `build_controller(spec)`. No network
  client is shipped; provider backends are documented as out-of-process adapters.
- **Affected files**: new `src/agent/controller.py`; later `loop.py`, `cli.py`,
  `command_registry.py`.
- **Tests**: decision validation; scripted replay equivalence; deterministic selection;
  backend-failure surfaced as a recoverable invalid decision.
- **Research value**: enables comparing deterministic vs model controllers on identical
  state — the core experiment this repo is built for.
- **Risk**: low–medium (must preserve the exact loop/executor contract).

### P0-2 — Loop protection (duplicate + no-progress detection)
- **Current behavior**: only budget counters stop the loop.
- **Problem**: identical actions / identical observations loop undetected (W4).
- **Failure scenario**: confirmed — arm64/Mach-O target re-runs `collect-binary-evidence`
  every step until `--max-steps`; a model that fixates never terminates early.
- **Solution**: `src/agent/progress.py` — action-attempt signatures and
  iteration-delta fingerprints; new terminal statuses `repeated-action` and `no-progress`
  with a configurable `--max-no-progress` budget.
- **Affected files**: new `src/agent/progress.py`; `loop.py`, `cli.py`.
- **Tests**: duplicate action triggers `repeated-action`; unchanged evidence+candidate set
  triggers `no-progress`; genuine progress resets the counter.
- **Research value**: trajectories terminate honestly; stagnation is measurable.
- **Risk**: low.

### P1-1 — Structured agent state + evidence ledger
- **Current behavior**: prose + counters (W2/W3).
- **Problem**: no machine-readable observations/evidence/hypotheses/verified-facts.
- **Failure scenario**: "which hypothesis did step 3 test, on what evidence?" is
  unanswerable without re-reading prose.
- **Solution**: `src/agent/state.py` (`AgentState`: objective, observations, evidence refs,
  verified_facts, hypotheses, rejected_hypotheses, open_questions, action_history,
  failure_history, progress markers, stage, confidence, budgets; to_dict/from_dict with
  back-compat) and `src/agent/evidence.py` (normalize execution result + artifact delta
  into an `EvidenceRecord`; keep verified tool facts separate from controller prose).
- **Affected files**: new `src/agent/state.py`, `src/agent/evidence.py`; `loop.py`.
- **Tests**: round-trip persistence; evidence derivation from an execution result; prose
  never overwrites a verified fact.
- **Research value**: the substrate for evaluation, fine-tuning data, and analysis.
- **Risk**: medium (persistence/back-compat).

### P1-2 — Decision schema v2
- **Current**: `chosen_action_id`, `rationale`, `confidence`, `summary_update`.
- **Problem**: cannot express hypothesis under test / expected information gain / a
  structured state update (W5).
- **Solution**: extend `model-choice` to v2 with optional `hypothesis`,
  `expected_information_gain`, `state_update`; keep v1 acceptance unchanged.
- **Affected files**: `controller.py`, `loop.py` validation, docs.
- **Tests**: v1 payloads still accepted; v2 optional fields validated when present.
- **Risk**: low (additive).

### P1-3 — Evaluation harness
- **Current**: none (W7).
- **Problem**: no measured trajectory metrics; no controller comparison.
- **Solution**: `src/agent/evaluation.py` `evaluate_trajectory()` (task_completed, steps,
  successful/failed/repeated actions, no_progress_iterations, recovered_failures,
  terminal_state, trajectory_length, wall_time when present) + an `agent-eval` control-plane
  CLI emitting metrics json + markdown. Only measured fields; nothing fabricated.
- **Affected files**: new `src/agent/evaluation.py`; `cli.py`, `command_registry.py`,
  `main.py` wiring.
- **Tests**: metrics on a known trajectory; success vs no-progress terminal mapping.
- **Risk**: low.

### P2-1 — Observability fields in trajectory
- Add per-iteration `why` (candidate set + chosen rationale + hypothesis), evidence-at-time,
  post-action deltas, and a `usage` block (tokens/tool-calls, nullable) so a future provider
  can populate it. Additive to `pwn-agent.agent-loop.v1` (bump to v2, keep v1 readers happy).
- Risk: low.

### P2-2 — Documentation + overnight report
- Update `AGENT_LOOP.md`, `PROGRESS.md`, `README`, and add `OVERNIGHT_REPORT.md`. Describe
  only what exists. Risk: none.

### P3 (documented, not built tonight)
- Out-of-process provider adapter reference (Claude / local Qwen / OpenAI-compatible).
- Belief-state carried across replans (merge rather than recompute).
- Alternative-action recovery policy after a failed action.
- Multi-target / batch evaluation runner for controller comparison tables.

## Execution order (each = commit + push)
state+evidence → controller → progress → loop integration → evaluation → docs.
