#!/usr/bin/env bash
set -u

if [[ -z "${ASV_CANARY:-}" ]]; then
  echo "ASV_CANARY is required" >&2
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required" >&2
  exit 2
fi

if [[ "$#" -gt 0 ]]; then
  scan_paths=("$@")
else
  scan_paths=(
    "build"
    "test-artifacts"
    "mcp-server/test-artifacts"
    "mcp-server/captures"
    "mcp-server/fixtures/transcripts"
    "$HOME/Library/Application Support/AgentSecretVault"
    "$HOME/Library/Logs/AgentSecretVault"
    "$HOME/Library/Logs/DiagnosticReports"
  )
fi

existing_paths=()
for path in "${scan_paths[@]}"; do
  if [[ -e "$path" ]]; then
    existing_paths+=("$path")
  fi
done

if [[ "${#existing_paths[@]}" -eq 0 ]]; then
  exit 0
fi

matches="$(
  rg \
    -l \
    --fixed-strings \
    --hidden \
    --glob '!**/.git/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/DerivedData/**' \
    --glob '!**/*.xcresult/**' \
    -- \
    "$ASV_CANARY" \
    "${existing_paths[@]}" 2>/dev/null || true
)"

if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches"
  exit 1
fi

exit 0
