---
name: svlt
description: Use when Codex, Claude, Hermes, or another MCP agent sees secret:// references or the user explicitly chooses SVLT to manage or use a credential. SVLT is opt-in and does not claim ownership of credentials selected through another provider or explicitly supplied as plaintext for the current operation.
---

# SVLT

SVLT is opt-in. It protects secrets that the user chooses to manage with SVLT; it does not claim ownership of all credentials available to an Agent.

触发范围：

- 出现 `secret://...`，或用户明确要求“使用 SVLT / 使用 SVLT 中的登录 / 保存到 SVLT”时，进入 SVLT 管理路径。
- 仅仅出现 password、token、API key、凭据等词，或任务需要登录、SSH、HTTP、数据库、SFTP、浏览器/本地 App 填充，并不会自动激活 SVLT。
- 用户当前亲自提供明文并明确要求本次使用，或明确选择“这次不用 SVLT”时，建立 `USER_EXPLICIT_PLAINTEXT`；不得搜索、比较、替换成 `secret://`、导入 SVLT、要求 Touch ID，或仅因 Catalog 可能已有对应 Secret 而阻断。
- 用户明确指定 QNAP MCP、GitHub connector、已登录 CLI、环境变量、第三方密码管理器或其他 provider 时，使用该 provider；SVLT 不得抢占。

英文原则：SVLT is opt-in. The user may explicitly choose to provide or use plaintext credentials. When the user explicitly chooses plaintext for the current operation, do not force conversion to `secret://` and do not block the operation solely because an equivalent credential may already exist in SVLT. Do not treat user-supplied plaintext as SVLT-managed unless the user explicitly asks to store it in or use it through SVLT.

中文原则：用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。即使 SVLT 中可能已有对应 Secret，本次仍按用户明确选择执行。SVLT 只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

## scope 与来源优先级

- `SVLT_MANAGED_OPERATION`：用户明确选择 SVLT、Entry 或 `secret://`；只经 SVLT 的专用工具使用。
- `USER_EXPLICIT_PLAINTEXT`：用户在当前请求中提供明文并明确要求使用，或明确选择本次不用 SVLT。
- `EXTERNAL_PROVIDER_OPERATION`：用户明确选择其他 MCP、connector、CLI、环境变量或密码管理器。
- `UNMANAGED_CREDENTIAL`：用户没有指定来源；可以按任务需要发现可用 provider，但 SVLT 不是唯一选择。
- 来源优先级：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 没有指定时才自动发现。
- 以上选择只对当前 operation 有效；不得把上一轮对话、旧 provider 选择或 Agent 状态当成当前授权。每次 operation 只能有一个最终 source decision。
- 不比较用户明文与 `secret://` 背后的值，不因可能相同而改变 provenance。

## 硬规则

- 用户在 App 中选定的 v2 `敏感信息.md` 是 SVLT managed catalog。只能经 MCP 使用 `secret://` 或允许返回的非敏感元数据；不得直接读取、搜索、解析、修改或重写 managed 文件及本地加密记录。
- Catalog 写入只能使用 SVLT Catalog MCP 和 App 当前有效的编辑授权。不得使用 shell、Python、sed、echo、编辑器或文件 API 直接修改 Markdown/JSON。
- `secret://` 是不透明句柄；不要猜测、分类、摘要、解码、比较或改写背后的值。
- SVLT MCP/search/response/log/audit 不返回秘密明文。秘密字段只能是 opaque `secret://` 引用；Catalog JSON 不得写入秘密明文。
- 用户明确选择的当前明文可以由用户指定的外部工具/工作区按其安全规则使用；SVLT 不自动创建 Secret、替换输入或阻止操作。其他仓库、日志、持久化、网络和工具规则仍然有效。
- 不得把通过 SVLT 解密得到的明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。禁止的是 Agent 自己把 `secret://` 洗成明文绕过 SVLT 专用操作。
- 不要把用户主动提供的明文识别为 security bypass attempt，也不要把它与已有 Secret 做等值关联。

## 工具选择

先判断用户是否选择了来源，再选择工具：

- `agent_secret_usage_policy`：读取 SVLT 范围、用户覆盖规则和 SVLT 派生明文边界。
- `vault_status`：只有即将执行 SVLT 管理操作时才检查 SVLT 可用性。
- `secret_auto_handle_text`：文本中出现 `secret://` 且用户没有明确选择其他来源时使用。
- `secret_search` / `secret_catalog_search`：没有明确来源且需要发现 SVLT 记录时使用；明确 plaintext 或外部 provider 时不要调用来替换来源。
- `secret_catalog_get`：用户明确选择 SVLT Entry 后获取非敏感上下文和 opaque 引用。
- `secret_action_router`：用户明确选择 SVLT 且需要在本机/内网执行受控动作时使用；明文只在 SVLT 专用边界内处理。
- `ssh_command_with_secret`、`local_http_request_with_secret`、`api_request_with_token`、`database_query_with_secret`、`sftp_transfer_with_secret`、`browser_web_login_with_secret`、`local_app_form_fill_with_secret`：仅用于 `secret://` 管理路径。
- `secret_reveal_request` / `paragraph_reveal_request`：用户明确要在本机 App 查看 SVLT 明文时使用；结果是本地显示状态，不是返回给 Agent 的明文。

如果用户明确选择了其他 MCP/CLI/App 或当前明文，保持 SVLT 沉默，调用该工具并遵守其自身的权限、日志和持久化规则。不要因为 SVLT Catalog 有候选记录而抢占。

## 失败处理

- SVLT managed 操作遇到 `APP_UNAVAILABLE`、`CATALOG_INVALID`、`EXTERNAL_CATALOG_MODIFICATION`、策略拒绝或审批取消时，只报告非敏感状态；不得把 SVLT 派生明文交给普通工具。
- 旧版 Catalog 的 `LEGACY_CATALOG_UNSUPPORTED` 只表示需要用户手工转换为 v2；Agent 不得自行转换或直接修改旧文件。
- 如果用户明确选择当前明文或外部 provider，SVLT 的不可用、未安装或 Catalog 命中都不是阻断本次操作的理由；是否能执行由用户选定的工具和工作区规则决定。
- 如果用户明确要求把当前明文存入 SVLT，先走 App/MCP 的安全导入流程；成功后再使用生成的 `secret://`。不得默认保存。
