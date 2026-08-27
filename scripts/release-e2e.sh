#!/usr/bin/env bash
set -euo pipefail

# This is an intentionally manual, release-installed E2E harness. It prepares
# an isolated v3 Catalog and verifies the installed code signature, but it
# never fabricates or prints a credential and it cannot automate Touch ID.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="${SVLT_RELEASE_APP:-/Applications/SVLT.app}"
E2E_ROOT="$ROOT_DIR/test-artifacts/release-e2e"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_DIR="$E2E_ROOT/$RUN_ID"
CATALOG_PATH="$RUN_DIR/敏感信息.md"
TEAM_ID="9KXSB4HR69"

umask 077

if [[ ! -d "$APP_PATH" ]]; then
  echo "找不到 release App：$APP_PATH" >&2
  echo "可用 SVLT_RELEASE_APP 指向本次安装的 SVLT.app。" >&2
  exit 1
fi
if [[ ! -x "$APP_PATH/Contents/MacOS/SVLTAgent" ]]; then
  echo "release App 缺少 SVLTAgent，停止 E2E。" >&2
  exit 1
fi

codesign --verify --deep --strict "$APP_PATH"
for signed_path in "$APP_PATH" "$APP_PATH/Contents/MacOS/SVLTAgent"; do
  actual_team="$(codesign --display --verbose=4 "$signed_path" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  if [[ "$actual_team" != "$TEAM_ID" ]]; then
    echo "release 签名 TeamIdentifier 不匹配，停止 E2E。" >&2
    exit 1
  fi
done

mkdir -p "$RUN_DIR"
chmod 700 "$E2E_ROOT" "$RUN_DIR"
cp "$ROOT_DIR/Resources/Templates/敏感信息.md" "$CATALOG_PATH"
chmod 600 "$CATALOG_PATH"

echo "已创建隔离 Release E2E Catalog：$CATALOG_PATH"
echo "这次回归不会使用生产 Catalog，也不会在终端记录秘密明文。"
echo
echo "手工步骤："
echo "1. 打开 $APP_PATH，并在 SVLT 中选择 $CATALOG_PATH。"
echo "2. 通过 App 创建一个测试 Entry 和至少一个空 secret placeholder。"
echo "3. 让已安装的 MCP 调用 secret_catalog_request_secure_inputs；记录返回的 PENDING/requestID。"
echo "4. 在 SVLT SecureField 中完成测试输入并确认一次 Touch ID 或 macOS 密码认证。"
echo "5. 只用 secret_catalog_secure_input_status 轮询同一 requestID，确认 COMPLETED 与 revision。"
echo "6. 关闭/切后台、锁屏或让 Mac 睡眠，确认 SecureField 取消且旧 requestID 不能再次提交。"
echo "7. 仅记录状态、revision、semantic diff 类型和时间；不要复制或截图测试明文。"
echo
echo "完成后可对隔离目录执行："
echo "ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' $ROOT_DIR/scripts/scan-plaintext.sh $RUN_DIR"

if [[ "${SVLT_E2E_LAUNCH:-0}" == "1" ]]; then
  open "$APP_PATH"
fi
