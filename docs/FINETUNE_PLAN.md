# Qwen fine-tuning plan for pwn-agent

## Goal

Fine-tune a local Qwen-family model so it becomes better at:

- consuming `audit.json`
- consuming `plan.json`
- selecting safe next actions
- explaining evidence-backed root cause
- writing concise security-oriented summaries

## Best first tuning target

Do **not** start by fine-tuning raw exploit knowledge.
Start by tuning these higher-value behaviors instead:

1. structured audit interpretation
2. action selection for the orchestrator loop
3. report synthesis from verified evidence
4. rejection of unsafe / unsupported execution paths

## Training format

Use instruction data shaped like:

### Input
- project context summary
- `audit.json` excerpt
- `plan.json` excerpt
- optional file/function snippet

### Output
- assessment
- top risks
- chosen next actions
- confidence
- short rationale

## Data sources to collect

- traces from real `audit -> plan -> run-plan` sessions
- human corrections to bad action choices
- verified vs heuristic finding labels
- rebuild/verification success and failure paths
- preferred report wording for your team

## Recommended tuning method

Start with:

- LoRA / QLoRA
- small high-quality dataset
- short action-oriented outputs

## Suggested tooling

- Unsloth
- Axolotl
- Hugging Face TRL

## Important note

The most valuable dataset for this project is not generic public C/C++ code.
It is the project-specific trajectory data produced by this tool stack.
