# Agent Integration

SVLT 面向 Codex、Claude、Hermes 和其他 MCP-capable agents。

核心规则：聊天里只保留 `secret://...` 引用。明文只允许停留在本地 macOS app，或停留在会内部解析引用并只返回脱敏结果的窄范围 MCP 工具里。

日常使用应自动触发。agent 看到消息、笔记片段、工具输出里有 `secret://...`，或任务需要本地登录、SSH、HTTP、本地文件导出时，应主动使用本流程；不要要求用户把明文贴到聊天。

## MCP server

普通用户安装 release 包后，MCP server 固定安装在：

```text
~/Library/Application Support/AgentSecretVault/MCP/dist/server.js
```

安装脚本会生成完整 MCP 配置：

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

在任何 MCP-capable agent 中使用类似配置：

```json
{
  "mcpServers": {
    "svlt": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
```

Codex、Claude、Hermes 的 MCP 配置位置可能不同；稳定部分是都启动同一个本机 MCP server。

## Agent 必须遵守

看到 `secret://...` 或需要使用密码、token、cookie、私钥等敏感值时：

1. 把引用当作不透明句柄，不从密文推断隐藏值。
2. 不要求用户把明文贴到聊天。
3. 不把解密明文、Authorization header、cookie、session key、填充后的敏感文件内容返回聊天。
4. 文本/段落/工具输出中含引用时，默认先调用 `secret_auto_handle_text`；若任务已经明确是本地动作，则直接用 `secret_action_router` 或更具体的安全工具。
5. 用户需要亲自查看明文时，用 `secret_reveal_request` 或 `paragraph_reveal_request` 让本地 app 展示；聊天里只报告 `DISPLAYED_TO_USER`。
6. 只用 `secret_inspect_reference` 查看非敏感元数据。
7. 任务提到服务、设备、主机、账号或用途但没有引用时，先用 `secret_search` 发现 opaque 引用；不要要求用户复制 `secret://` ID。
8. 没有安全工具时停止并请求新增 allowlisted 工具，不降级为通用命令、浏览器填表或索要明文。

## 工具选择规则

优先使用 `secret_action_router` 或能完成整个动作的具体安全工具：

| 场景 | 首选工具 | 规则 |
| --- | --- | --- |
| 普通文本/笔记片段含 `secret://` | `secret_auto_handle_text` | 检测、脱敏或打开本地 reveal；不返回明文。 |
| 本地网页登录 | `secret_action_router` 的 `browser_web_login`，或 `browser_web_login_with_secret` | 只允许本地/内网 URL；selector 必须明确；不能安全定位就返回状态。 |
| 本地 App 表单 | `secret_action_router` 的 `local_app_form_fill`，或 `local_app_form_fill_with_secret` | 字段必须明确；不用剪贴板；不返回填充值。 |
| SSH 到本机/内网设备 | `secret_action_router` 的 `ssh_command`，或 `ssh_command_with_secret` | 只允许本地/内网主机和只读命令；密码用 `passwordRef`。 |
| 本地/内网 HTTP(S) | `secret_action_router` 的 `local_http_request`，或 `local_http_request_with_secret` | 只允许 localhost、`.local`、私有 IP；默认 GET/HEAD；输出脱敏。 |
| API token 请求 | `secret_action_router` 的 `api_request`，或 `api_request_with_token` | token 只走 `tokenRef`；拒绝 URL token 参数；redirect manual；输出脱敏。 |
| 数据库只读查询 | `secret_action_router` 的 `database_query`，或 `database_query_with_secret` | 只允许本地/内网 host 和单条 read-only SQL；先校验再解密。 |
| SFTP/SCP | `secret_action_router` 的 `sftp_transfer`，或 `sftp_transfer_with_secret` | 只允许本地/内网 host；先校验 operation 和路径；输出脱敏。 |
| 本地文件导出 | `secret_action_router` 的 `export_resolved_text`，或 `export_resolved_text_to_local_file` | 用户明确要求导出时使用；只返回状态和路径。 |
| 用户本地查看明文 | `secret_reveal_request` / `paragraph_reveal_request` | 明文显示在本地 app，不进入聊天。 |
| 元数据检查 | `secret_inspect_reference` | 只返回 reference、policy、label、时间等非敏感字段。 |
| 服务/设备/主机发现 | `secret_search` | 按服务名、设备名、NAS、地址、用途或字段查询；只返回 opaque 引用和非敏感 catalog metadata。 |
| 创建引用 | `secret_create_request` | 从本地 app 选择/输入生成 `secret://`。 |

`secret_action_router` 支持的 intent：

- `ssh_command`
- `local_http_request`
- `api_request`
- `database_query`
- `sftp_transfer`
- `browser_web_login`
- `local_app_form_fill`
- `export_resolved_text`

## Tools

| Tool | Use |
| --- | --- |
| `agent_secret_usage_policy` | Returns the non-sensitive operating rules for Codex, Claude, Hermes, or another MCP-capable agent. |
| `secret_action_router` | Routes `secret://` references to allowlisted SSH, HTTP/API, database, SFTP/SCP, browser/app fill, or local file export. Plaintext is never returned. |
| `secret_auto_handle_text` | First-choice automatic handler for paragraphs or note excerpts containing `secret://`; detects references, redacts text, or opens a local app reveal. |
| `vault_status` | Checks whether the local channel and operation policy engine are ready; `locked` is compatibility-only. |
| `secret_inspect_reference` | Returns metadata only: reference, policy, label, timestamps. |
| `secret_search` | Finds opaque references by service, device, host, purpose, label, or field without exposing catalog paths or plaintext. |
| `secret_create_request` | Asks the app to encrypt selected local text and return a `secret://` reference. |
| `secret_reveal_request` | Asks the app to display one secret locally to the user. |
| `paragraph_reveal_request` | Asks the app to display a paragraph locally with all referenced secrets filled in. |
| `export_resolved_text_to_local_file` | Resolves references inside the app and writes the filled text to an allowed local file; returns only status/path. |
| `ssh_command_with_secret` | Resolves a password reference internally for restricted local/private-network SSH; returns sanitized stdout/stderr. |
| `local_http_request_with_secret` | Resolves `secret://` credentials internally for restricted local HTTP GET/HEAD requests and returns redacted output. |
| `api_request_with_token` | Resolves a token reference internally for a restricted allowlisted API request; returns status and redacted metadata/preview. |
| `database_query_with_secret` | Resolves database credentials internally for a restricted read-only query through a purpose-built runner. |
| `sftp_transfer_with_secret` | Resolves transfer credentials internally for restricted SFTP/SCP list/download/upload through a purpose-built runner. |
| `browser_web_login_with_secret` | Resolves login credentials internally for a specific local/private browser form fill. |
| `local_app_form_fill_with_secret` | Resolves field values internally for a specific macOS app form fill. |

## 失败处理

- `vault_status` 显示本机通道不可达：让用户打开 SVLT 一次以完成 SMAppService 注册/批准；普通后台 Agent 不要求 App 一直运行。
- `vault_status` 的 `locked` 字段为兼容信息：不要要求用户预先打开 GUI 解锁；直接提交具体操作，由本地策略判断静默、审批或拒绝。
- 返回 `URL_NOT_ALLOWED`、`HOST_NOT_ALLOWED`、`COMMAND_NOT_ALLOWED`：说明目标或动作超出 allowlist；请用户确认目标，或新增更窄的安全工具。
- 返回 `QUERY_NOT_ALLOWED`、`PATH_NOT_ALLOWED`、`URL_TOKEN_NOT_ALLOWED`：说明 SQL、路径或 URL 形态不安全；修正非敏感参数后重试，不要索要明文。
- 返回 `SAFE_AUTOFILL_UNAVAILABLE`、`DATABASE_RUNNER_UNAVAILABLE`、`FILE_TRANSFER_RUNNER_UNAVAILABLE`：说明本地 runner 尚不可用；不要改用明文或剪贴板绕过。
- 返回 `BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD`：要求补充缺失的用户名引用或非敏感用户名；不要要求密码明文。
- 返回 `REQUEST_FAILED`、`SSH_REQUEST_FAILED`：报告失败状态和非敏感上下文，可建议检查网络/服务状态。
- 返回 `SELECTION_ENCRYPT_UNAVAILABLE`：说明当前本地选择加密桥接能力不可用；不要改用明文替代。
- 返回 `QUARANTINED`：只报告隔离原因，不展示被隔离输出。
- 没有匹配工具：停止，请求新增 allowlisted MCP 工具；不要用 shell、curl、浏览器自动填表或让用户复制明文绕过边界。

## 可选兜底提示

仅在客户端无法自动加载 skill 时使用：

```text
看到 secret://、本地登录、SSH、HTTP 或本地文件导出需要秘密时，自动使用 svlt 的 secret_action_router 或具体安全工具；不要让我粘贴明文，不要把明文返回聊天。
```

## 本地预期

- SVLT.app 已安装；首次启动完成 SMAppService Agent 注册并在系统设置中批准（如 macOS 要求）。
- SVLTAgent 可在 SVLT.app 退出后继续运行；只有需要本机窗口的 reveal 才会按需激活 App。
- MCP server 已安装到 `~/Library/Application Support/AgentSecretVault/MCP`。
- agent 的 MCP entry 指向安装后的 `MCP/dist/server.js`。
- 现有笔记和任务中的敏感值以 `secret://...` 保存，不保存明文。
