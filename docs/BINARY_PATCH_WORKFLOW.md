# Binary Patch Workflow

`patch-validate` is the bounded defensive patch workflow for binary mode.

## Scope

The workflow accepts a structured patch artifact or structured patch script, creates an isolated scratch workspace under `.pwn-agent/patch-workspaces/<patch-id-or-run-id>/workspace`, applies bounded local edits only there, optionally rebuilds there, and then runs explicit validation checks against the patched binary in that scratch workspace.

It does not generate patches from free-form model output. It defines the interface that future model-generated patches must satisfy.

## Input Schemas

Accepted patch inputs:

- `pwn-agent.binary-patch-candidate.v1`
- `pwn-agent.patch-script.v1`

Both use the same practical structure:

- `patch_metadata`
- `edits`
- `build`
- `validation`

Supported bounded edit operations:

- `replace_text`
- `write_file`

`build.kind` currently supports:

- `rebuild-target`
- `existing-binary`

`rebuild-target` reuses the existing compile-database rebuild primitive.
`existing-binary` skips rebuild and validates an already materialized binary inside the workspace root.

## Output Schema

`patch-validate` emits `pwn-agent.binary-patch-validation.v1`.

Top-level fields:

- `schema`
- `schema_version`
- `artifact_type`
- `mode`
- `target`
- `workspace`
- `patch_metadata`
- `apply_result`
- `validation_result`
- `regression_notes`
- `remaining_risk_summary`
- `evidence`

## Validation Model

Validation is explicit and bounded:

1. launch check: the patched binary still launches under the configured launch or baseline inputs
2. baseline check: expected baseline inputs still behave acceptably
3. regression check: prior crash/regression input no longer reproduces suspicious behavior, when replay input is available

The workflow reuses existing primitives:

- `rebuild-target` via the compile database rebuild path
- `binary-verify` for launch/baseline execution checks
- `crash-triage` for regression replay checks

## Workspace Lifecycle

Patch validation is isolated from the original workspace tree:

1. copy the current workspace into `.pwn-agent/patch-workspaces/<run-id>/workspace`
2. apply structured edits only inside that scratch copy
3. rebuild and validate against the scratch copy
4. record both the original root and isolated workspace path in the output artifact

Cleanup policy:

- failed validations keep the scratch workspace by default
- successful validations also keep the scratch workspace by default
- `--cleanup-on-success` removes the scratch workspace after a successful run

This keeps the original workspace reproducible across repeated validation attempts.
The output artifact records the original root, isolated workspace path, cleanup outcome, and patched binary path so later replanning or review can reason about what was actually validated.

## Safety Model

- no shell passthrough
- no arbitrary patch code execution
- workspace-bound file edits only
- workspace-bound binaries only
- original workspace tree is not mutated by patch application
- rebuilds go through the existing bounded command policy
- validation runs reuse the existing bounded binary execution primitives

## Future AWDP Path

This is enough to support a future AWDP-style defensive loop:

1. collect evidence with `binary-scan` and `crash-triage`
2. plan next actions with `binary-plan`
3. let a model propose a structured patch artifact or patch script
4. run `patch-validate`
5. feed the resulting validation artifact back into the planner/model

That future loop stays defensive because patch proposals are still constrained by:

- structured edits only
- bounded local rebuilds only
- bounded explicit validation only
