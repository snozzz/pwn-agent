# Local Qwen runner

A minimal local test entrypoint is included at:

- `scripts/local_qwen_plan.sh`

## Purpose

It feeds `audit.json` into a local GGUF model through `llama.cpp` and asks for a short structured planning response.

## Example

```bash
./scripts/local_qwen_plan.sh \
  /path/to/Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf \
  out/audit.json
```

## Intended use

This is a first smoke-test for local-model suitability.
It is not the final orchestrator integration layer.

## What to evaluate

- does the model stay on schema?
- does it prioritize verified evidence?
- does it choose bounded next actions?
- does it stay stable over repeated runs?
