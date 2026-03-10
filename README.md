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
python3 -m src.main audit --root /path/to/project --report out/audit.md
python3 -m src.main audit --root /path/to/project --report out/audit.md --config pwn-agent.json
python3 -m src.main sanitize-build --root examples --source examples/vuln_demo.c --output examples/vuln_demo_asan --config pwn-agent.json
python3 -m src.main verify-run --root examples --binary examples/vuln_demo_asan $(python3 - <<'PY'
print('A' * 256)
PY
)
python3 -m src.main audit --root examples --report out/audit.md --config pwn-agent.json
# if examples/verification-plan.json exists, audit will append verification results
# if compile_commands.json exists, audit will also append rebuild+verify pipeline evidence
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

It now also supports ingesting `compile_commands.json` and surfacing a compile database summary during audit runs.
