#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SOURCE="$RELEASE_DIR/AgentSecretVault.app"
MCP_SOURCE="$RELEASE_DIR/MCP"

APP_DIR="/Applications"
if [[ ! -w "$APP_DIR" ]]; then
  APP_DIR="$HOME/Applications"
fi
APP_TARGET="$APP_DIR/AgentSecretVault.app"

APP_SUPPORT="$HOME/Library/Application Support/AgentSecretVault"
MCP_TARGET="$APP_SUPPORT/MCP"
CONFIG_PATH="$APP_SUPPORT/agent-secret-vault.mcp.json"

if [[ ! -d "$APP_SOURCE" ]]; then
  echo "找不到 AgentSecretVault.app。请从完整 release 包中运行本脚本。" >&2
  exit 1
fi

if [[ ! -d "$MCP_SOURCE" ]]; then
  echo "找不到 MCP 目录。请从完整 release 包中运行本脚本。" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "需要先安装 Node.js 24 或更新版本。安装后重新运行本脚本。" >&2
  echo "推荐：从 https://nodejs.org 下载 LTS/current 版本。" >&2
  exit 1
fi

mkdir -p "$APP_DIR" "$APP_SUPPORT"

rm -rf "$APP_TARGET"
cp -R "$APP_SOURCE" "$APP_TARGET"

rm -rf "$MCP_TARGET"
mkdir -p "$MCP_TARGET"
cp -R "$MCP_SOURCE"/. "$MCP_TARGET"/

(cd "$MCP_TARGET" && npm ci --omit=dev --ignore-scripts)

cat > "$CONFIG_PATH" <<JSON
{
  "mcpServers": {
    "agent-secret-vault": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"\$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
JSON

echo "安装完成。"
echo "App: $APP_TARGET"
echo "MCP 配置: $CONFIG_PATH"
echo
echo "下一步："
echo "1. 打开 Agent Secret Vault：open \"$APP_TARGET\""
echo "2. 在 Codex / Claude / Hermes 的 MCP 配置中粘贴 $CONFIG_PATH 的内容。"

open "$APP_TARGET"
