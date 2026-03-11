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

SCHEMA_FILE="$(cd "$(dirname "$0")/.." && pwd)/tmp_local_plan_schema.json"
PROMPT_FILE="$(mktemp)"
trap 'rm -f "$PROMPT_FILE"' EXIT

cat > "$PROMPT_FILE" <<'EOF'
You are the planning brain for a defensive C/C++ security audit agent.
Read the audit summary and produce a short structured planning result.
Prefer actions that fit the existing bounded tool workflow.
Prioritize verified evidence over heuristic findings.
EOF
printf '\nAUDIT_JSON:\n' >> "$PROMPT_FILE"
cat "$AUDIT_JSON" >> "$PROMPT_FILE"

"$LLAMA_CLI" \
  --no-conversation \
  --simple-io \
  --no-display-prompt \
  --json-schema-file "$SCHEMA_FILE" \
  -m "$MODEL_PATH" \
  -f "$PROMPT_FILE" \
  -c "$CTX_SIZE" \
  -n 256 \
  --temp 0.2 \
  --top-p 0.9
