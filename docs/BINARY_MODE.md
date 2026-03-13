# Binary Mode

`binary` mode is a bounded local workflow for authorized binary triage and validation.

## Inputs

- local ELF or executable binary path (`--binary`)
- workspace root (`--root`)
- optional stdin file (`--stdin-file`)
- optional runtime argument hint list (`--args ...`)
- optional timeout override (`--timeout`)
- optional protocol/input sample file (`--protocol-sample`)

## Outputs

Binary mode emits separate artifacts from source-audit outputs:

- `pwn-agent.binary-analysis.v1` from `binary-scan`
- `pwn-agent.binary-plan.v1` from `binary-plan`
- `pwn-agent.binary-verify.v1` from `binary-verify`
- `binary-run` uses the bounded plan executor and writes an execution summary for plan progress

These schemas are intentionally separate from `audit.json` to avoid conflating source-level and binary-level evidence.
See [BINARY_AUDIT_EXAMPLE.json](/home/snoz/pwn-agent/docs/BINARY_AUDIT_EXAMPLE.json) for a concrete artifact example.

## Supported stages

Binary mode tracks this stage sequence:

1. `identify`
2. `inspect`
3. `triage`
4. `validate`
5. `patch`
6. `revalidate`

Current command mapping:

- `binary-scan` covers `identify` + `inspect` + `triage`
- `binary-plan` emits stage-aware next actions
- `binary-run` executes bounded ready actions (for example `binary-verify`)
- `binary-verify` performs bounded local runtime validation and sanitizer-signal capture

`binary-scan` evidence collection is bounded to local tools:

- `file`
- `checksec` (if available)
- `readelf`
- `objdump`
- `nm`
- `strings` (truncated)

## Safety and bounded execution

- workspace-bounded command policy
- explicit command registry with per-command argument validation
- path-like argument binding to workspace/root
- fixed command timeout (with per-command overrides when defined)
- per-command output truncation policy
- local execution only
- no shell passthrough

## Explicit non-goals

- unattended remote exploitation
- unrestricted shell execution
- automatic persistence, privilege escalation, or lateral movement behavior
- autonomous binary rewriting or patch deployment without explicit human action

## Incremental intent

This is a scaffold for dual-mode orchestration. It intentionally starts with bounded local triage and verification,
while leaving deeper debugger/fuzzer/rewrite integrations as future work.
