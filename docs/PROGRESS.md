# Progress

## Documentation Consistency Pass

- task completed: aligned README and docs with the current bounded binary-mode implementation and tightened claims that were broader than the code
- files changed: `README.md`, `docs/VERIFICATION.md`, `docs/PIPELINE.md`, `docs/PROGRESS.md`
- docs corrected:
  - replaced overstated `agent-loop` wording with the actual pre-generated structured-response model
  - kept audit rebuild/verify behavior described as conditional rather than default
  - reflected verify artifact participation in replanning as implemented
  - kept scratch workspace patch validation, control-plane vs leaf-action execution, and unified internal-main execution policy documentation aligned
  - confirmed there are no absolute local filesystem links in current README/docs references
- remaining known risks:
  - some older roadmap/design docs still describe intent rather than the exact current CLI surface; they were left untouched because they are not normative implementation docs

## Unified Internal Execution Policy

- task completed: internal `python3 -m src.main ...` leaf actions now execute through the same `CommandPolicy` execution path as other bounded commands
- files changed: `src/policy.py`, `src/executor.py`, `src/command_registry.py`, `tests/test_executor.py`, `docs/EXECUTOR.md`, `README.md`
- tests added/updated:
  - allowed internal-main leaf actions still execute correctly
  - timeout handling now uses the shared policy path
  - truncation handling now uses the shared policy path
  - malformed or disallowed internal-main actions remain rejected
- remaining known risks:
  - internal `python3` actions currently rely on executor/root validation before policy execution, so the unified layer is execution-consistent but still intentionally not a full replacement for executor-side plan validation

## Verify Replanning Consistency

- task completed: made `verify_json` a first-class replanning input all the way through binary loop replanning and binary planner heuristics
- files changed: `src/modes/binary/workflow.py`, `tests/test_binary_mode.py`, `docs/BINARY_PLANNER.md`, `docs/BINARY_MODE.md`
- tests added/updated:
  - timeout verify artifacts now trigger bounded follow-up triage planning
  - signal/crash verify artifacts now trigger bounded follow-up triage planning
  - verify artifact absence preserves the pre-existing no-verify planning shape
  - `binary-verify` artifact normalization now records timeout/signal fields consumed by planner logic
- remaining known risks:
  - verify-driven follow-up remains intentionally narrow and only emits bounded triage, not richer debugging actions without matching evidence
  - older persisted verify artifacts without `timed_out` / `signal_name` still work, but only contribute the fields they carry

## Regression Coverage Strengthening

- task completed: added focused regression tests for binary planner inputs, agent loop bounded execution semantics, scratch-workspace patch validation, and executor control-plane rejection
- files changed: `tests/test_binary_mode.py`, `tests/test_agent_loop.py`, `tests/test_binary_patch_validate.py`
- tests added/updated:
  - planner coverage for analysis-only, crash-only, verify-driven, and patch-validation-driven planning paths
  - loop coverage for valid bounded execution, invalid model-choice failure accounting, replanning behavior, and dry-run non-progress semantics
  - patch validation coverage for scratch isolation, unchanged original root, and repeated-run non-accumulation
  - executor control-plane rejection coverage remained in `tests/test_executor.py`
- remaining known risks:
  - planner heuristics are deterministic but still intentionally shallow; richer artifact combinations may need more explicit precedence tests later
  - loop tests currently exercise local structured response ingestion, not any external model transport layer
  - patch validation isolation is covered for current structured edit operations, but future edit primitives will need the same non-accumulation checks

## Architecture Regression Coverage Audit

- task completed: verified that the current regression suite covers the intended binary planner, bounded loop, patch-validation isolation, and executor-boundary architecture contracts
- files reviewed: `tests/test_binary_mode.py`, `tests/test_agent_loop.py`, `tests/test_binary_patch_validate.py`, `tests/test_executor.py`
- coverage confirmed:
  - planner inputs: analysis-only, crash-only, verify-present, patch-validation-present
  - loop behavior: valid bounded execution, invalid choice failure accounting, replanning after executed actions, dry-run non-progress semantics
  - patch validation: isolated scratch workspaces, unchanged original root, repeated-run non-accumulation
  - executor boundaries: control-plane rejection and leaf-action acceptance
- remaining known risks:
  - there is still more coverage for verify-driven replanning than for crash-triage-driven replanning path variation
  - current loop tests focus on bounded local file-driven model choices, not higher-level controller integration
