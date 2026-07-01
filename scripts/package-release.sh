#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build/release"
STAGING_DIR="$DIST_DIR/AgentSecretVault-release"
MCP_STAGING="$STAGING_DIR/MCP"

cd "$ROOT_DIR"

rm -rf "$BUILD_DIR" "$STAGING_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR" "$MCP_STAGING"

echo "==> Building MCP server"
(cd "$ROOT_DIR/mcp-server" && npm ci && npm run build)

echo "==> Building macOS app"
if command -v xcodegen >/dev/null 2>&1; then
  xcodegen generate
fi

if [[ -z "${DEVELOPER_DIR:-}" && -d "/Applications/Xcode-beta.app/Contents/Developer" ]]; then
  export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
fi

xcodebuild \
  -project "$ROOT_DIR/AgentSecretVault.xcodeproj" \
  -scheme AgentSecretVault \
  -configuration Release \
  -derivedDataPath "$BUILD_DIR/DerivedData" \
  build

APP_SOURCE="$BUILD_DIR/DerivedData/Build/Products/Release/AgentSecretVault.app"
if [[ ! -d "$APP_SOURCE" ]]; then
  echo "Build succeeded but app was not found at $APP_SOURCE" >&2
  exit 1
fi

echo "==> Staging app and MCP bundle"
cp -R "$APP_SOURCE" "$STAGING_DIR/AgentSecretVault.app"
cp "$ROOT_DIR/mcp-server/package.json" "$MCP_STAGING/package.json"
cp "$ROOT_DIR/mcp-server/package-lock.json" "$MCP_STAGING/package-lock.json"
cp -R "$ROOT_DIR/mcp-server/dist" "$MCP_STAGING/dist"
cp "$ROOT_DIR/scripts/install-release.sh" "$STAGING_DIR/install.sh"
cp "$ROOT_DIR/scripts/install-release.sh" "$STAGING_DIR/install.command"
chmod +x "$STAGING_DIR/install.sh"
chmod +x "$STAGING_DIR/install.command"

cat > "$STAGING_DIR/README_INSTALL.txt" <<'TEXT'
Agent Secret Vault 安装方式

1. 双击 install.command；如果系统拦截，右键点它再选“打开”。
   也可以在终端运行 install.sh。
2. 安装脚本会把 App 复制到 /Applications 或 ~/Applications。
3. 安装脚本会把 MCP server 安装到：
   ~/Library/Application Support/AgentSecretVault/MCP
4. 安装脚本会生成可复制的 MCP 配置：
   ~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json
5. 打开 Agent Secret Vault，再把 MCP 配置粘贴到 Codex / Claude / Hermes。

注意：本版本需要本机已安装 Node.js 24 或更新版本，用于运行 MCP server。
TEXT

ZIP_PATH="$DIST_DIR/AgentSecretVault-release.zip"
rm -f "$ZIP_PATH"
(cd "$DIST_DIR" && ditto -c -k --sequesterRsrc --keepParent "AgentSecretVault-release" "$ZIP_PATH")

echo "Release package:"
echo "$ZIP_PATH"
