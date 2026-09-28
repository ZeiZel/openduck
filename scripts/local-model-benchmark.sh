#!/bin/sh
set -eu

# Synthetic-only smoke benchmark. Never pass real chat or credential-bearing text here.
base_url="${OLLAMA_HOST:-http://127.0.0.1:11434}"
model="${OLLAMA_MODEL:-qwen3:8b}"

curl -fsS "$base_url/api/version" >/dev/null
curl -fsS "$base_url/api/generate" \
  -H 'Content-Type: application/json' \
  -d "{\"model\":\"$model\",\"prompt\":\"Return exactly SAFE for synthetic text: project status green.\",\"stream\":false,\"think\":false,\"options\":{\"temperature\":0,\"num_predict\":16}}"
printf '\n'
