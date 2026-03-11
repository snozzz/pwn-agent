# pwn-agent

A terminal-using C/C++ security analysis agent MVP.

## Goal

This project explores an AI agent that can:

- inspect a local C/C++ codebase
- use a constrained terminal toolset
- identify likely security-relevant hotspots
- generate evidence-backed audit notes
- prepare for later integration with sanitizers, fuzzers, and debuggers

## MVP scope

The first MVP focuses on:

1. project structure discovery
2. C/C++ source file indexing
3. simple risk-pattern scanning
4. evidence-based markdown reporting
5. a safe command allowlist abstraction

## Planned phases

- Phase 1: repository skeleton and design docs
- Phase 2: local scanner and reporting pipeline
- Phase 3: command policy + execution wrapper
- Phase 4: sanitizer/fuzzer integration
- Phase 5: iterative agent loop

## Quick start

```bash
python3 -m src.main scan --root /path/to/project --report out/report.md
python3 -m src.main scan-sarif --root /path/to/project --output out/report.sarif
python3 -m src.main audit --root /path/to/project --report out/audit.md --trace-json out/trace.json
python3 -m src.main audit --root /path/to/project --report out/audit.md --audit-json out/audit.json
python3 -m src.main plan-audit --audit-json out/audit.json --output out/plan.json --report out/plan.md
python3 -m src.main run-plan --plan out/plan.json --output out/exec.json --report out/exec.md --dry-run
python3 -m src.main run-plan --plan out/plan.json --output out/exec.json --report out/exec.md --phase execution --max-actions 3 --dry-run
python3 -m src.main audit --root /path/to/project --report out/audit.md --config pwn-agent.json
python3 -m src.main sanitize-build --root examples --source examples/vuln_demo.c --output examples/vuln_demo_asan --config pwn-agent.json
python3 -m src.main verify-run --root examples --binary examples/vuln_demo_asan $(python3 - <<'PY'
print('A' * 256)
PY
)
python3 -m src.main audit --root examples --report out/audit.md --config pwn-agent.json
# if examples/verification-plan.json exists, audit will append verification results
# if compile_commands.json exists, audit will also append rebuild+verify pipeline evidence
# audit will also list detected input surfaces, file-level hotspots, and function focus when functions are detected
# --audit-json writes a single structured summary for downstream tooling
python3 -m src.main rebuild-plan --root examples
python3 -m src.main rebuild-target --root examples --index 1 --output-name vuln_demo_rebuilt_asan --config pwn-agent.json
python3 -m src.main rebuild-verify --root examples --index 1 --output-name vuln_demo_pipeline_asan --config pwn-agent.json
```

## Safety model

The command-execution layer is intentionally constrained:

- workspace-bounded cwd
- explicit command allowlist
- fixed timeout for command execution
- no shell passthrough by default

## Current status

This MVP is intended for defensive security review on local codebases with constrained command execution.

It now also supports ingesting `compile_commands.json`, surfacing a compile database summary during audit runs,
best-effort function-level focus so findings and input surfaces can be tied back to enclosing functions,
and an optional `--audit-json` export that aggregates the audit workflow outputs into one machine-readable artifact.
A new `plan-audit` step can then turn that artifact into a compact orchestration plan for a future model-driven loop, with explicit staged guidance about which actions to take next, and `run-plan` now emits a richer execution summary with runnable/deferred inventory plus follow-up action hints.
The audit export now includes concise file/function rollups plus execution-readiness data, and the plan output now marks
which actions are `context`, `ready`, or `blocked`, grouped into explicit `triage`, `execution`, and `synthesis` phases.
Runnable execution steps are preserved even after a sanitizer signal already exists, so downstream loops can still replay
verification, enumerate rebuild targets, rebuild sanitized binaries, and rerun rebuild+verify flows.
A minimal `run-plan` executor can now consume that plan, validate only bounded internal `python3 -m src.main ...` actions,
and the repo now also includes local-model notes in `docs/QWEN_LOCAL.md` plus a first fine-tuning roadmap in `docs/FINETUNE_PLAN.md`.
filter by phase, honor simple action dependencies, reconcile persisted state against regenerated plans, and execute a small
number of ready steps sequentially while emitting a structured execution summary.
