# MVP Design

## Objective

Build a defensive C/C++ security analysis agent that can inspect a repository, use a constrained terminal workflow, and produce auditable findings.

## Core components

### 1. Project mapper
- discovers files and build metadata
- classifies source/header/test/build files
- surfaces likely entry points and parsing-heavy code

### 2. Risk scanner
- searches for risky APIs and coding patterns
- records evidence with file paths and line numbers
- assigns rough severity and confidence

### 3. Command policy layer
- wraps terminal execution in a strict allowlist
- enforces cwd constraints, timeout limits, and logging
- provides a future hook for human approval on risky actions

### 4. Reporter
- emits markdown findings with evidence
- distinguishes between heuristic suspicion and verified issues

## Initial architecture

```text
CLI -> Project Mapper -> Risk Scanner -> Reporter
                  \-> Command Policy
```

## First supported heuristics

- unsafe string and memory APIs
- dangerous shell/process invocation usage
- integer/length handling hotspots
- parser/input-facing code concentration

## Near-term roadmap

1. repo skeleton
2. scanner implementation
3. command policy execution wrapper
4. config file support
5. sanitizer integration
6. fuzz harness suggestions

## Non-goals for MVP

- autonomous exploitation
- unconstrained shell execution
- network-enabled actions
- binary-only deep reversing
