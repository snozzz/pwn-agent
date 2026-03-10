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
```

## Safety model

This MVP is intended for defensive security review on local codebases with constrained command execution.
