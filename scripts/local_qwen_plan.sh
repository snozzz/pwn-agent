#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <model.gguf> <audit.json> [ctx-size]" >&2
  exit 1
fi

MODEL_PATH="$1"
AUDIT_JSON="$2"
CTX_SIZE="${3:-8192}"
LLAMA_CLI="/home/snoozy/.openclaw/workspace/llama.cpp/build/bin/llama-cli"

if [ ! -x "$LLAMA_CLI" ]; then
  echo "llama-cli not found at $LLAMA_CLI" >&2
  exit 1
fi

if [ ! -f "$MODEL_PATH" ]; then
  echo "model not found: $MODEL_PATH" >&2
  exit 1
fi

if [ ! -f "$AUDIT_JSON" ]; then
  echo "audit json not found: $AUDIT_JSON" >&2
  exit 1
fi

PROMPT=$(cat <<'EOF'
You are the planning brain for a defensive C/C++ security audit agent.
Read the audit summary and respond with ONLY valid JSON.
Do not use markdown. Do not explain first. Do not add prose before or after the JSON.
Return exactly this schema:
{
  "assessment": "string",
  "top_risks": ["string"],
  "next_actions": ["string"],
  "confidence": "low|medium|high"
}
Keep it short and concrete. Prefer actions that fit the existing bounded tool workflow.
Prioritize verified evidence over heuristic findings.

AUDIT_JSON:
EOF
)

{
  printf "%s\n" "$PROMPT"
  cat "$AUDIT_JSON"
} | "$LLAMA_CLI" -m "$MODEL_PATH" -c "$CTX_SIZE" -n 512 --temp 0.2 --top-p 0.9 --no-display-prompt
