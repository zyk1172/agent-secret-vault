---
name: svlt
description: Use when Codex, Claude, Hermes, or another MCP agent sees secret:// references, credentials, tokens, API keys, local login, SSH, local HTTP/API, SFTP/SCP, database access, browser form fill, local app form fill, or local file export that needs secrets without exposing plaintext.
---

# SVLT

中文优先。遇到敏感值、凭据、token、API key、知识库密文、`secret://...`，或需要本地登录、SSH、HTTP、本地文件导出时，先用 SVLT 的 MCP 安全工具。明文只允许留在本地 macOS app 或安全工具内部。

用户不需要贴长提示。只要出现 `secret://...` 或需要使用密码/令牌，就自动执行本规则。

## 硬规则

- 用户在 App 中选定的 `敏感信息.md` 是唯一权威目录，每个 `secret://` 引用对应本地保险箱中的独立加密记录。只能经 MCP 使用引用或非敏感元数据；不得直接读取、搜索、解析、修改或重写该文件及本地加密记录。必须遵守文件顶部“必读：格式与使用”：每组信息独立成段，引用前保留一个英文空格且不使用反引号、链接或方括号包裹。
- 不得将普通笔记、历史对话、终端输出、日志、缓存、环境变量、模型记忆或外部来源作为敏感值的替代来源；它们只能用于理解业务上下文。
- 不要求用户把明文密码、token、cookie、私钥贴到聊天里。
- 不把解密后的明文、Authorization header、cookie、会话 key、填充后的敏感文件内容返回聊天。
- 把 `secret://` 当作不透明句柄；不要猜测、分类、摘要或改写背后的真实值。
- 可以讨论引用周围可见文本；若周围文字暴露“密码/token/API key”等用途，要提醒可能泄露语义。
- 需要执行操作时，把普通参数放普通字段，把敏感值只以 `secret://` 传给安全工具。
- 工具返回失败、锁定、不可用或隔离时，只报告非敏感状态码和下一步，不降级为索要明文。
- 没有对应引用、MCP 找不到记录或没有合适安全工具时停止，请用户在 App 中创建或确认引用；不要使用通用 shell、curl、浏览器填表或其他方式绕过。

## 工具选择

优先选择能完成整个动作且不返回明文的工具：

- `agent_secret_usage_policy`：读取 Codex/Claude/Hermes 的非敏感使用规则。
- `vault_status`：操作依赖 app 时先检查可用性和锁定状态。
- `secret_auto_handle_text`：文本、笔记片段、工具输出里含 `secret://` 时的默认入口；除非已经明确要执行下面某个具体动作。
- `secret_action_router`：本地动作的首选路由器；用于 `ssh_command`、`local_http_request`、`api_request`、`database_query`、`sftp_transfer`、`browser_web_login`、`local_app_form_fill`、`export_resolved_text`，明文不出工具边界。
- `ssh_command_with_secret`：已明确是本地/内网 SSH 且只读命令时可直接用。
- `local_http_request_with_secret`：已明确是 localhost、`.local` 或内网 HTTP(S) 的 GET/HEAD，含 Basic Auth 或账号密码引用时可直接用。
- `api_request_with_token`：已明确是本地/内网或显式 allowlist API 请求，且 token 用 `tokenRef` 提供时使用；不接受 token URL 参数。
- `database_query_with_secret`：已明确是本地/内网数据库只读查询时使用；SQL 必须是单条 read-only 语句。
- `sftp_transfer_with_secret`：已明确是本地/内网 SFTP/SCP list/download/upload 时使用；路径必须是确定路径，不使用 glob、`..` 或 shell 字符。
- `browser_web_login_with_secret`：已明确是本地/内网页面登录，且 selector 明确时使用；不能安全定位就返回状态，不索要明文。
- `local_app_form_fill_with_secret`：已明确是本地 macOS app 表单填充，且字段明确时使用；明文只进入本地 runner。
- `export_resolved_text_to_local_file`：用户明确要把填充后的敏感文本写入本地允许路径时可直接用；只回传路径/状态。
- `secret_reveal_request` / `paragraph_reveal_request`：用户本人需要本地查看明文时使用；结果应是 `DISPLAYED_TO_USER`，不是明文。
- `secret_inspect_reference`：只看引用元数据。
- `secret_create_request`：把本地选中文本加密成新的 `secret://`。
- `secure_execute`：仅用于已有 allowlist 模板；可能返回 `EXECUTE_UNAVAILABLE`。

## 场景规则

- 本地登录：本地/内网页面登录用 `secret_action_router` 的 `browser_web_login` 或 `browser_web_login_with_secret`；本地 macOS app 表单用 `local_app_form_fill` 或 `local_app_form_fill_with_secret`。不能安全定位时停止，不要用剪贴板或让用户贴密码。若只是本地 HTTP Basic Auth，使用 `local_http_request` 或 `local_http_request_with_secret`。
- SSH：使用 `secret_action_router` 的 `ssh_command` 或 `ssh_command_with_secret`。只接受本机、`.local`、内网地址和只读命令；被拒绝时报告 `HOST_NOT_ALLOWED`、`COMMAND_NOT_ALLOWED` 等状态。
- HTTP：使用 `secret_action_router` 的 `local_http_request` 或 `local_http_request_with_secret`。只做本地/内网 GET/HEAD；需要 POST、删除、重启、写入、公开网络发送时，必须改用专门 allowlisted 工具。
- API token：使用 `secret_action_router` 的 `api_request` 或 `api_request_with_token`。token 只能走 `tokenRef`，不要放 URL、header 文本或聊天。
- 数据库：使用 `secret_action_router` 的 `database_query` 或 `database_query_with_secret`。先校验 host 和 SQL，只允许单条只读查询。
- SFTP/SCP：使用 `secret_action_router` 的 `sftp_transfer` 或 `sftp_transfer_with_secret`。先校验 host、operation、path，再解密。
- 本地文件导出：使用 `secret_action_router` 的 `export_resolved_text` 或 `export_resolved_text_to_local_file`。聊天里只说导出状态和路径，不展示文件内容。

## 失败处理

- app 未运行或 vault 锁定：报告状态，请用户打开/解锁后再试。
- 工具返回 `*_UNAVAILABLE`、`*_NOT_ALLOWED`、`REQUEST_FAILED`、`SSH_REQUEST_FAILED`、`QUARANTINED`：复述状态码和非敏感原因，说明需要用户授权、调整目标，或新增更窄的 allowlisted 工具。
- 没有合适安全工具：停止。不要用通用 shell、curl、浏览器填表或让用户贴明文绕过边界。
