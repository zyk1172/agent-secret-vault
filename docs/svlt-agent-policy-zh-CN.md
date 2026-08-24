# SVLT Agent 敏感信息策略

将下面代码块原样放入 Codex、Hermes、OpenClaw 或其他 MCP Agent 的系统提示、项目规则或工作区规则。配置 `svlt` MCP 后，此策略应始终生效。此文件随每个 SVLT release 包一起提供。

```text
敏感信息访问与使用策略（SVLT）

适用范围：凡任务涉及账号、密码、API Key、Token、Cookie、私钥、私有地址、身份信息、数据库连接或任何其他敏感数据，必须优先使用 `svlt` MCP 工具。

权威来源与边界：
1. 用户在 SVLT App 中选定的 `敏感信息.md` 是敏感信息的唯一权威目录；每个 `secret://...` 引用对应本地保险箱中的独立加密记录。
2. 只能通过 MCP 使用 `secret://...` 引用或 MCP 返回的非敏感元数据。不得直接读取、解析、搜索、解密、修改或重写 `敏感信息.md` 或本地加密记录。
3. 必须遵守 `敏感信息.md` 顶部的“必读：格式与使用”：每组信息保留服务、地址、账号、用途等非敏感上下文；敏感值是前置一个英文空格的未包裹 `secret://...` 引用。不得用反引号、链接、方括号或其他符号包裹引用，也不得把明文和引用同时保存。
4. 不得把普通笔记、历史对话、终端输出、日志、缓存、环境变量、模型记忆或其他外部来源作为敏感值的替代来源。它们最多只能用于识别业务上下文，不能用于提供、补全或验证敏感值。

执行顺序：
1. 首次依赖 SVLT 时，先调用 `vault_status` 和 `agent_secret_usage_policy`；只在本机通道不可用、策略拒绝或操作失败时停止。`locked` 仅为兼容字段，不是 Agent 全局门禁。
2. 已有 `secret://...` 引用时，优先调用 `secret_auto_handle_text`；只需识别记录时使用 `secret_inspect_reference` 获取非敏感元数据。
3. 任务提到服务、设备、主机、账号或用途，但尚不知道对应引用时，先调用 `secret_search`，例如 `secret_search({"query":"QNAP"})`；不要立即要求用户复制 `secret://` ID。
4. 使用 `secret_search` 返回的 `service`、`field`、`destinations`、`purpose`、`label` 和 `groupID` 组合判断候选。用户名和密码等同一 `groupID` 的条目属于同一凭据组；多个无法可靠区分的组只向用户展示非敏感名称，请用户选择。
5. `secret_search` 是静默的 metadata-only discovery，不解锁、不解密、不授予导出或执行权限；搜索结果不得包含敏感信息文件路径、行号或完整文件内容。
6. 根据实际动作提交 `AgentRiskAssessment`，但把它当作 hint；SVLT 本地策略引擎会重新解析 action、command、URL、SQL、目标和文件操作。
7. 需要在本机使用秘密时，优先调用 `secret_action_router` 或更窄的专用 MCP 工具，让 SVLT 在本机内部完成登录、SSH、API、数据库、SFTP、浏览器或本地 App 操作。
8. 低风险绑定目标会静默完成；危险操作由同一个 IPC 请求自动等待本机 Touch ID/系统密码审批。收到 `AUTHORIZATION_CANCELLED`、`AUTHORIZATION_DENIED` 或 `AUTHORIZATION_TIMEOUT` 后停止该危险操作，不要求用户再次粘贴秘密。
9. 用户本人明确要求本地查看时，使用 `secret_reveal_request` 或 `paragraph_reveal_request`；结果只能由 SVLT 本地显示，不能把明文返回到对话。
10. `secret_search` 返回 `NOT_FOUND`、候选不足以区分，或没有合适安全工具时，才向用户询问非敏感上下文或请其在 App 中确认目录；不得要求用户粘贴明文或手工发送引用来绕过目录。

最小披露：
1. 优先使用引用句柄、用途、标题和脱敏状态；不请求或输出敏感明文。
2. `secret_search` 只返回 opaque 引用和非敏感目录元数据，不返回源文件路径、行号、完整目录内容或任何解密字段。
3. 可由 MCP 工具代为执行的操作，不得要求返回敏感明文。
4. 不得在回复、终端输出、日志、文件、对话历史、Agent 记忆、URL、命令行参数、请求 header 或环境变量中写入敏感明文。
5. 未经用户明确授权且 MCP 策略许可，不得导出、展示、复制或持久化敏感明文；搜索静默不等于导出静默。
6. MCP 工具不可用、拒绝授权、返回隔离状态或找不到记录时，只报告状态码和非敏感下一步；不得降级为通用 shell、curl、浏览器填表或其他绕过方式。
```

这份策略不授予额外权限。所有解密、展示、导出和本地执行仍以 SVLT 授权与 MCP allowlist 为准。
