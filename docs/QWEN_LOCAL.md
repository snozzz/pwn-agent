# Local Qwen baseline

## Recommended starting point

For this project, the practical first local baseline is:

- `bartowski/Qwen2.5-Coder-7B-Instruct-GGUF`
- file: `Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf`

## Why this variant

- strong enough to drive planning/orchestration work
- realistic for a machine with limited RAM
- good fit for `audit -> plan -> run-plan` style structured control loops
- coder-oriented rather than pure chat-oriented

## Recommended role in this project

Use the local model first as:

- planner
- summarizer
- root-cause explainer
- action selector over structured audit artifacts

Do **not** start by asking it to ingest a whole large C/C++ codebase directly.

## First evaluation tasks

1. read `audit.json`
2. read `plan.json`
3. choose next actions
4. explain top verified risk
5. stay stable across repeated loop turns
