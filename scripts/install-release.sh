#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SOURCE="$RELEASE_DIR/AgentSecretVault.app"
MCP_SOURCE="$RELEASE_DIR/MCP"
OBSIDIAN_PLUGIN_SOURCE="$RELEASE_DIR/ObsidianPlugin/agent-secret-vault"

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

install_obsidian_plugin() {
  local vault_path="$1"
  local plugin_target="$vault_path/.obsidian/plugins/agent-secret-vault"

  if [[ ! -d "$vault_path/.obsidian" ]]; then
    echo "跳过 Obsidian 插件安装：$vault_path 不是有效 Obsidian Vault（缺少 .obsidian）。" >&2
    return 1
  fi

  if [[ ! -d "$OBSIDIAN_PLUGIN_SOURCE" ]]; then
    echo "跳过 Obsidian 插件安装：release 包中缺少 ObsidianPlugin/agent-secret-vault。" >&2
    return 1
  fi

  mkdir -p "$plugin_target"
  cp "$OBSIDIAN_PLUGIN_SOURCE/main.js" "$plugin_target/main.js"
  cp "$OBSIDIAN_PLUGIN_SOURCE/manifest.json" "$plugin_target/manifest.json"
  if [[ -f "$OBSIDIAN_PLUGIN_SOURCE/styles.css" ]]; then
    cp "$OBSIDIAN_PLUGIN_SOURCE/styles.css" "$plugin_target/styles.css"
  fi
  echo "Obsidian 插件已安装: $plugin_target"
}

detect_obsidian_vaults() {
  local search_root="$HOME/Documents/obsidian"
  if [[ ! -d "$search_root" ]]; then
    return 0
  fi

  find "$search_root" -maxdepth 4 -type d -name ".obsidian" -print 2>/dev/null | while IFS= read -r obsidian_dir; do
    dirname "$obsidian_dir"
  done
}

OBSIDIAN_INSTALL_STATUS="未安装"
if [[ -n "${1:-}" ]]; then
  if install_obsidian_plugin "$1"; then
    OBSIDIAN_INSTALL_STATUS="已安装到: $1"
  fi
elif [[ -n "${OBSIDIAN_VAULT_PATH:-}" ]]; then
  if install_obsidian_plugin "$OBSIDIAN_VAULT_PATH"; then
    OBSIDIAN_INSTALL_STATUS="已安装到: $OBSIDIAN_VAULT_PATH"
  fi
else
  detected_vaults=()
  while IFS= read -r detected_vault; do
    detected_vaults+=("$detected_vault")
  done < <(detect_obsidian_vaults)

  if [[ "${#detected_vaults[@]}" -eq 1 ]]; then
    if install_obsidian_plugin "${detected_vaults[0]}"; then
      OBSIDIAN_INSTALL_STATUS="已自动安装到: ${detected_vaults[0]}"
    fi
  elif [[ "${#detected_vaults[@]}" -gt 1 ]]; then
    echo "检测到多个 Obsidian Vault，未自动安装插件。请指定 Vault 路径重新运行："
    echo "./install.sh \"/你的/Obsidian/Vault/路径\""
  else
    echo "未检测到 Obsidian Vault。需要时手动复制 ObsidianPlugin/agent-secret-vault 到 Vault/.obsidian/plugins/。"
  fi
fi

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
echo "Obsidian 插件: $OBSIDIAN_INSTALL_STATUS"
echo
echo "下一步："
echo "1. 打开 Agent Secret Vault：open \"$APP_TARGET\""
echo "2. 在 Codex / Claude / Hermes 的 MCP 配置中粘贴 $CONFIG_PATH 的内容。"
echo "3. 如果安装了 Obsidian 插件，请在 Obsidian 设置 → 第三方插件中启用 Agent Secret Vault。"

open "$APP_TARGET"
