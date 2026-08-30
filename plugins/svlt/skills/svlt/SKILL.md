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

- 用户在 App 中选定的 v3 `敏感信息.md` 是 SVLT managed catalog。Agent 只能经 MCP 使用 `secret://` 或允许返回的非敏感元数据；不得读取 managed Markdown 或本地 sidecar 来发现、验证或猜测 opaque ID。
- Catalog 的合法 writer 可以是 App、MCP、Obsidian、编辑器或脚本；无论渠道都必须产生符合 v3 marker/schema 的 Markdown，不得伪造 marker/`secret://`、写入 plaintext，Agent 的 mutation 仍必须走 SVLT operation-bound authorization。
- `secret://` 是不透明句柄；不要猜测、分类、摘要、解码、比较或改写背后的值。
- 同一 operation 中不得重复提交同一个 `secret://`；不要为了“去重”静默改变调用语义，重复引用应修正后重新提交。
- SVLT MCP/search/response/log/audit 不返回秘密明文。秘密字段只能是 opaque `secret://` 引用；Catalog JSON 不得写入秘密明文。
- 用户明确选择的当前明文可以由用户指定的外部工具/工作区按其安全规则使用；SVLT 不自动创建 Secret、替换输入或阻止操作。其他仓库、日志、持久化、网络和工具规则仍然有效。
- 不得把通过 SVLT 解密得到的明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。禁止的是 Agent 自己把 `secret://` 洗成明文绕过 SVLT 专用操作。
- 不要把用户主动提供的明文识别为 security bypass attempt，也不要把它与已有 Secret 做等值关联。
- 每笔 Agent Catalog mutation 都必须使用精确绑定、一次消费的 operation-bound write request；需要批准时直接触发 macOS device-owner authentication，认证本身就是本次授权，不存在额外 App“验证并授权”按钮。

### SSH session 与授权窗口

- 连续 SSH 任务优先使用 `ssh_command_with_secret` 返回的 opaque `sessionID`，或一次调用 `ssh_batch_with_secret`。`sessionID` 只代表 SVLT 内部可复用的 SSH transport，不代表命令已获授权，也不是密码、ControlPath 或其他 capability。
- 每一次命令（包括带 `sessionID` 的后续命令）仍由 SVLT 重新做 principal、目标、secretRef 和本地 Policy 校验；不要把 session 的存在当成执行许可。
- `ssh_command_with_secret` 的 `command` 是真正的 remote shell 命令，会 byte-for-byte 交给远端登录 shell 执行：单行、多行、`;`、`&&`、`|`、`>`、`$()`、glob、引号、heredoc、`bash -c`、`python -c`、`find -exec`、`sudo` 都按你真实的意图提交，SVLT 不解析也不改写 shell 语法。需要真实 shell 语义时优先用它。
- 结构化 `ssh_batch_with_secret`（每项 `executable` + `arguments`）适合天然参数化的任务；不要为了绕过任何限制把脚本强行拆成 batch。两种形式都是一等公民。
- 准确填写 `intendedEffect` 和风险提示。不得拆小、改写、伪装或谎报 destructive/不可逆操作；SVLT 会把完整原始命令展示给设备所有者，由用户通过 Touch ID/密码做最终决定。
- 授权分层（§22 新模型）：所有使用 Secret 的 SSH 命令——包括 hostname、df、cat、未知 NAS CLI——默认都是普通操作：第一次 Touch ID/密码，之后同 scope 300 秒免审批。只有固定 5 类高危操作每次 fresh approval：电源控制（reboot/shutdown/poweroff/halt/systemctl kexec·isolate）、文件删除（rm/shred）、块设备与文件系统（mkfs*/wipefs/fdisk/parted/dd）、存储/RAID 破坏（zpool destroy、破坏性 mdadm）、容器删除（docker rm/volume rm/system prune）。fresh approval 不会刷新或延长普通 lease。
- MCP 连接建立后应声明客户端名称与版本；Audit/UI 只显示 `Codex（自报）`、`Pi（自报）` 等 display metadata。该 identity 不是可信 security principal，也不能改变 lease 隔离。
- 以上是行为指导。SVLT 的职责是判断授权级别、展示事实、执行用户决定；它不替设备所有者拒绝任何技术上可执行的请求，最终允许/拒绝由用户通过 Touch ID/密码决定。

### 非 SSH 执行器与能力清单

- 在任何非 SSH 执行前先调用 `vault_capabilities`。daemon 返回的 capability manifest 才是实际能力来源；`unavailable` 不是“稍后重试即可”的支持状态，也不能因此请求明文或换成普通 shell/CLI。
- 能力清单中的 `version` 与 `features` 是实际 adapter 的非敏感能力说明；不要只因为 MCP tool 存在就假设某个 auth、body、response projection、session 或 capture 能力存在。
- HTTP/API 只能使用 typed payload：Basic、Bearer、API-key header、Cookie 等由 SVLT 分别校验。HTTPS 是默认传输；未加密 `http://` 不再被直接拒绝，但会触发 fresh approval 并明确提示"凭据可能以明文传输"，由设备所有者决定。凭据类 URL query 参数同样触发 fresh 警告。不要自行添加任意 header；重定向会停止并要求重新审查。
- 带认证的 HTTP 响应默认只返回状态/Content-Type。只有 capability manifest 声明 `projectedJSON` 且 App-owned profile ID 与 allowlisted JSON fields 同时匹配时，才能返回投影字段；不要请求 token、access_token、refresh_token、password、secret、cookie、session、authorization 等字段。`captureCredential`/派生 Cookie session 在本版本仍不可用。
- `Authorization` header 默认使用 `Bearer`；`X-API-Key`、`X-Auth-Token` 等 custom API-key header 默认只发送原始 token，只有明确安全的 scheme 才会加前缀。不要用自定义 header 绕过 profile/Policy。
- 通用 `localExecution`（把 Secret 交给任意本地进程）是极高危操作：会触发 fresh approval，审批中明确提示"批准后 SVLT 无法保证 Agent 不获得该凭据"，审计标记 `userApprovedSecretRelease`；是否释放由设备所有者决定。`trustedProcess` 是独立的未来 adapter 边界，只有能力清单声明已配置的 signed profile 时才可用，禁止退回 shell、AppleScript、剪贴板或通用脚本。
- `database_query_with_secret`、`sftp_transfer_with_secret`、`browser_web_login_with_secret`、`local_app_form_fill_with_secret` 和 trusted-process 能力必须以 manifest 的 `supported` 为前提。当前没有真实安全 adapter 时应接受 `ACTION_EXECUTOR_UNAVAILABLE` 并停止，不得伪造成功；数据库不得退回 shell client，浏览器不得退回 AppleScript、剪贴板或页面 JavaScript，本地 App 不得退回通用脚本。
- 导出工具只返回本地路径/状态；plaintext resolution 和安全文件写入留在 App/daemon 边界内。不要读取导出文件再把内容放入聊天或普通工具。
- HTTP transport `sessionID` 只是 SVLT 内部连接复用句柄，不代表请求已授权。每次请求仍须通过 principal、secretRef、目标、策略和授权要求检查；transport session 不会让 DELETE 或其他 destructive action 免于 fresh approval。
- 非 SSH 请求仍需准确填写 `intendedEffect` 和风险。授权级别是 `none`（明确只读）、`reusableApproval`（普通操作，5 分钟窗口）、`freshApprovalRequired`（危险/高影响，每次重新认证）；Agent 自报的高风险提示只会把操作升级为 fresh approval 并在审批中展示原因，SVLT 不会替设备所有者拒绝任何技术上可执行的请求。fresh approval 不会延长原 lease。
- MCP 连接建立时声明 client name/version。Audit 中的 `Codex（自报）`、`Pi（自报）`、`Hermes（自报）` 只是显示 metadata；不得把它当成 security principal，也不能用它绕过 scope 隔离。

## Catalog Markdown 布局

- SVLT 自己生成或受控插入的 `敏感信息.md` 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局。Note、说明、callout、用户段落和 WikiLink 是 unmanaged，不属于 Index/Entry/Field semantic model，也不计入搜索、计数或 App UI；已有未知用户 Markdown 即使位于两个 Index 之间也保持原位。
- policy block 与前言位于业务 Catalog 之前；存在 Index 时，新 Index 插入最后一个合法 `SVLT-INDEX` 之后、尾部非托管 Markdown 之前。没有 Index 时，首个 Index 插入前言之后。不得把新内容简单 append 到文件绝对末尾，也不要为了追求连续主体搬迁既有用户 Markdown。
- Index marker/Entry marker/Field marker 是 authoritative structure。新生成的 Index 之间由 renderer 生成标准 `\n\n---\n\n`；已有 `---` 没有 provenance 时按用户内容保留，不要全局重写用户自己的分隔线。
- 同一 Index 内 Entry 之间统一使用双空行视觉间距；canonical render、create、batch、migration、format repair 和 minimal patch 必须遵守同一布局。
- 普通写入优先 source-range minimal patch，只修改目标块和新写入时 renderer 明确生成的边界空白，保留用户 Markdown、注释、WikiLink、Note、备注和尾部内容。format repair 不为追求连续主体而移动无法确认来源的用户 Note/Markdown/WikiLink，也不删除用户 HR；只有 migration 能确定来自旧版官方结构化“目录说明”的 Note 时，才可将它放入前言。

## 工具选择

先判断用户是否选择了来源，再选择工具：

- `agent_secret_usage_policy`：读取 SVLT 范围、用户覆盖规则和 SVLT 派生明文边界。
- `vault_status`：只有即将执行 SVLT 管理操作时才检查 SVLT 可用性。
- `secret_auto_handle_text`：文本中出现 `secret://` 且用户没有明确选择其他来源时使用。
- `secret_search` / `secret_catalog_search`：没有明确来源且需要发现 SVLT 记录时使用；明确 plaintext 或外部 provider 时不要调用来替换来源。
- `secret_catalog_get`：用户明确选择 SVLT Entry 后获取非敏感上下文和 opaque 引用。
- `secret_catalog_list_indices`：列出全部 Index（包括空 Index），从 MCP 响应获取 opaque `indexID`。
- `secret_catalog_list_entries`：使用 MCP 返回的 `indexID` 列出目标 Index 的 Entry。
- `secret_catalog_create_structure`：一次创建一个 Index 和多个安全 Entry，由 SVLT 生成 opaque ID 并返回映射、revision 与 validation。
- `secret_catalog_add_secret_placeholder`：向已存在 Entry 添加空 `secret` placeholder；不要提交 plaintext 或自造 `secretRef`。
- `secret_catalog_request_secure_inputs`：请求本机 SecureField 填写秘密；只发送 field metadata 和 revision，Agent 永远不接收 plaintext。当前同步 transport 返回完成状态/revision；若兼容 transport 返回 `PENDING` + `requestID`，只能用 `secret_catalog_secure_input_status` 轮询同一请求。
- `secret_action_router`：用户明确选择 SVLT 且需要在本机/内网执行受控动作时使用；明文只在 SVLT 专用边界内处理。
- `ssh_command_with_secret`：适合单条结构受限 SSH 命令；连续任务优先复用返回的 opaque `sessionID`。
- `ssh_batch_with_secret`：适合巡检和批量任务；传入结构化 `commands`，让 SVLT 在执行前完整评估整批风险，并返回独立、已脱敏的结果。
- `local_http_request_with_secret`、`api_request_with_token`、`database_query_with_secret`、`sftp_transfer_with_secret`、`browser_web_login_with_secret`、`local_app_form_fill_with_secret`：仅用于 `secret://` 管理路径。
- `secret_reveal_request` / `paragraph_reveal_request`：用户明确要在本机 App 查看 SVLT 明文时使用；结果是本地显示状态，不是返回给 Agent 的明文。

## Secure Input 异步事务

- `secret_catalog_request_secure_inputs` 只接受 `entryID`、field key、模式、required 和 accepted revision；不要传入 label。SVLT 会从 accepted Catalog 重建 UI label。
- 该调用立即返回 `PENDING` 与 opaque `requestID`，因为用户可能需要较长时间完成 Touch ID 或 macOS 密码认证。使用 `secret_catalog_secure_input_status` 按 requestID 轮询，直到 `COMPLETED`、`CANCELLED`、`EXPIRED` 或 `FAILED`。
- status 只包含状态、revision 和稳定 errorCode，不包含 plaintext、Catalog 内容或 secretRef。不要因 MCP 请求返回 `PENDING` 而重复创建请求。
- daemon 将本机 device-owner authentication、字段加密、最终 semantic diff、策略检查和 Catalog commit 绑定在同一笔 requestID 事务中；过期、取消、App 失焦/睡眠/锁定后不得重试旧 Sheet 或调用 generic Catalog commit。

如果用户明确选择了其他 MCP/CLI/App 或当前明文，保持 SVLT 沉默，调用该工具并遵守其自身的权限、日志和持久化规则。不要因为 SVLT Catalog 有候选记录而抢占。

## 失败处理

- SVLT managed 操作遇到 `APP_UNAVAILABLE`、`CATALOG_INVALID`、`EXTERNAL_CATALOG_MODIFICATION`、策略拒绝或审批取消时，只报告非敏感状态；不得把 SVLT 派生明文交给普通工具。
- 旧版 Catalog 的 `LEGACY_CATALOG_UNSUPPORTED` 表示需要用户在 App 中走明确的备份、验证并升级流程；Agent 不得自行转换或直接修改旧文件。
- 如果用户明确选择当前明文或外部 provider，SVLT 的不可用、未安装或 Catalog 命中都不是阻断本次操作的理由；是否能执行由用户选定的工具和工作区规则决定。
- 如果用户明确要求把当前明文存入 SVLT，先走 App/MCP 的安全导入流程；成功后再使用生成的 `secret://`。不得默认保存。
