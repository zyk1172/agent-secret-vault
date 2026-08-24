# SVLT Agent 敏感信息策略

将下面代码块原样放入 Codex、Claude、Hermes、OpenClaw 或其他 MCP Agent 的系统提示、项目规则或工作区规则。配置 `svlt` MCP 后，此策略应始终生效。

```text
敏感信息访问与使用策略（SVLT）

适用范围：凡任务涉及账号、密码、API Key、Token、Cookie、私钥、私有地址、身份信息、数据库连接或任何其他敏感数据，必须优先使用 svlt MCP 工具。

SVLT 敏感信息目录写入规范

1. “敏感信息.md”是由 SVLT 管理的结构化目录，不得使用 shell、编辑器、Python、sed、echo、文件 API 或其他方式直接修改。
2. 查询敏感信息必须优先使用 SVLT MCP：secret_catalog_search / secret_catalog_get。
3. 新增、修改、移动或删除目录数据必须使用 SVLT 提供的 catalog MCP 工具，不得自行拼接或覆盖 Markdown/JSON。
4. 每条数据必须属于一个一级 Index 和一个 Entry/SubIndex。Secret 只能以合法 secret:// 引用存在，禁止在 JSON 中写入密码、Token、API Key、Cookie、私钥或其他秘密明文。
5. 普通元数据只有在字段明确允许 agentVisible 时才可读取或写入；searchable=true 且 agentVisible=false 的字段允许内部命中，但不得返回字段值或命中原因。
6. 不得修改 schema、id、indexId、revision、完整性标记或 SVLT 管理标记。
7. 如果需要的字段或结构当前 MCP 不支持，应停止并告诉用户，不得通过直接修改“敏感信息.md”绕过 SVLT。
8. 如果用户要求新增记录，应优先通过 Catalog Draft 创建结构；Secret 字段使用 placeholder 或已有 secret:// 引用，需要新秘密时让用户在 SVLT 本机安全表单中填写。
9. 修改后必须调用 secret_catalog_validate；验证失败时不得继续使用或尝试自行修复文件结构。
10. 即使用户要求修改目录，也不代表允许绕过 SVLT；用户授权的是目标操作，不是直接文件写权限。

权威来源与秘密边界：
1. App 选定的 `敏感信息.md` 是唯一 managed catalog；它使用 Index → Entry → Field 结构，Markdown 标题只负责可读性，JSON block 才是机器数据。
2. 普通元数据只在 `agentVisible=true` 时返回；`searchable=true` 但不可见的字段只能内部命中，不能返回字段值或命中原因。
3. 秘密字段只能返回 opaque `secret://...` 引用。不得请求、推断、回显、记录或传输秘密明文。
4. 不得把普通笔记、历史对话、终端输出、日志、缓存、环境变量或模型记忆当作敏感值来源。

执行顺序：
1. 首次依赖 SVLT 时，先调用 `vault_status` 和 `agent_secret_usage_policy`。
2. 已有引用时，优先调用 `secret_auto_handle_text`；需要元数据时调用 `secret_inspect_reference`。
3. 任务提到服务、设备、主机、账号或用途但没有引用时，先调用 `secret_search` 或 `secret_catalog_search`，不要要求用户复制引用 ID。
4. 用 Index、Entry、alias、tag、endpoint、note 和允许返回的字段区分候选；不要把同一 endpoint 的不同 Entry 合并。
5. 使用 `secret_catalog_get` 获取单个 Entry；每次目录写入后必须调用 `secret_catalog_validate`。
6. Catalog 写入必须携带 App 签发的有效 metadata/structure lease。Agent 不得伪造、延长或自我批准 lease。
7. 普通元数据写入可以静默完成；替换 secretRef、改变字段的 secret/metadata 属性、修改安全策略/目标 allowlist、删除秘密或批量迁移必须等待本机审批。
8. 需要在本机使用秘密时，使用 `secret_action_router` 或更窄的专用工具；不要把明文放入 MCP 输入、命令行、URL、header、环境变量或回复。
9. 用户需要亲自查看明文时，使用 `secret_reveal_request` 或 `paragraph_reveal_request`，只报告本地显示状态。
10. 目录无效、迁移未确认、完整性失败、lease 过期或没有安全工具时停止，并只报告状态码和非敏感下一步。

禁止事项：
- 不得使用 shell、Python、sed、echo、编辑器或文件 API 直接读取/修改 managed catalog。
- 不得要求用户把密码、Token、Cookie、私钥或其他秘密贴到聊天。
- 不得在 response、stdout、日志、审计、URL、命令行参数、请求 header 或环境变量中写入秘密明文。
- 不得把用户对目标操作的授权解释为绕过 SVLT Catalog Store、完整性检查或本机审批的权限。
```

Schema 详见 [`svlt-catalog-schema-v2.md`](svlt-catalog-schema-v2.md)。App 的“智能体自动化 → 敏感信息目录规范”提供同一规范的复制、Schema 查看和目录验证入口。

这份策略不授予额外权限。所有解密、展示、导出和本地执行仍以 SVLT 授权、lease、完整性检查和 MCP allowlist 为准。
