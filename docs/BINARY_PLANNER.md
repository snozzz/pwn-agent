# Binary Planner

`binary-plan` converts bounded local binary evidence into a deterministic next-action plan for the binary agent loop.

## Inputs

- `pwn-agent.binary-analysis.v1` from `binary-scan`
- `pwn-agent.binary-crash-triage.v1` from `crash-triage` / `binary-triage`
- `pwn-agent.binary-verify.v1` from `binary-verify`
- optional `pwn-agent.binary-patch-validation.v1` from `patch-validate`

At least one binary artifact is required. If multiple artifacts are provided, they must agree on:

- `root`
- `binary_path`

## Output Schema

`binary-plan` emits `pwn-agent.binary-plan.v2`.

Top-level fields:

- `schema`
- `schema_version`
- `mode`
- `root`
- `binary_path`
- `binary_fingerprint`
- `plan_fingerprint`
- `stage_order`
- `source_artifacts`
- `readiness`
- `next_actions`

Each planned action includes:

- `id`
- `stage`
- `phase`
- `kind`
- `status`
- `priority`
- `depends_on`
- `blocked_by`
- `rationale`
- `expected_artifacts`
- `suggested_cli`

`suggested_cli` is only populated for bounded internal commands that pass the shared command-policy validator.

## Stage Model

The planner uses a binary-specific investigation flow:

1. `identify`
2. `inspect`
3. `reproduce`
4. `triage`
5. `patch`
6. `validate`
7. `summarize`

This differs from the audit planner, which is phase-oriented first. For binary workflows, stage order matters more because evidence gathering and crash reproduction need to happen before patch and validation decisions.

## Deterministic Heuristics

Current deterministic planning rules:

- no mitigations summary yet: suggest `binary-scan`
- no crash artifact and no verify artifact yet: suggest `crash-triage`
- clean verify artifact: treat it as existing runtime-validation evidence, suppress redundant replay/verify work
- failing verify artifact: suggest bounded `crash-triage` using the verify inputs to collect reproducible triage evidence
- suspicious crash without debugger context: suggest `crash-triage --gdb-batch`
- suspicious crash: add `draft-patch-hypothesis` as a patch-stage context action
- patch candidate exists without validation evidence from patch-validation or verify artifacts: suggest `binary-verify`
- summary stays blocked behind earlier ready actions

Verify artifacts are therefore real planner inputs rather than loop-only bookkeeping:

- clean verify evidence can unblock later summarize work by removing redundant runtime-validation steps
- failing verify evidence can introduce or reprioritize bounded triage actions
- when verify input is absent, planner behavior falls back to the analysis/crash/patch-validation evidence already provided

Ordering is deterministic:

- earlier `stage` sorts before later `stage`
- within the same stage, higher `priority` sorts first
- ties break by `id`

## Migration Note

Compared with the older `plan-audit` schema:

- `plan-audit` is source-audit oriented and primarily grouped around `triage`, `execution`, and `synthesis`
- `binary-plan.v2` keeps `phase` for executor compatibility, but adds an explicit binary workflow `stage`
- binary actions now always declare `expected_artifacts` so later local loops can reason about missing evidence
- binary plans carry `source_artifacts` to make the analysis/crash/verify provenance explicit
- executor ordering now prefers earlier binary investigation stages before later summary or synthesis actions
