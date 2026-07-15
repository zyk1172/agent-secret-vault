#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_HOME="${CODEX_HOME:-"$HOME/.codex"}"
SOURCE_SKILL="$ROOT_DIR/plugins/svlt/skills/svlt"
TARGET_DIR="$CODEX_HOME/skills/svlt"

if [[ ! -d "$SOURCE_SKILL" ]]; then
  echo "Missing source skill: $SOURCE_SKILL" >&2
  exit 1
fi

mkdir -p "$(dirname "$TARGET_DIR")"
rm -rf "$TARGET_DIR"
cp -R "$SOURCE_SKILL" "$TARGET_DIR"

echo "Installed SVLT skill to: $TARGET_DIR"
echo "Restart Codex or reload skills before using it."
