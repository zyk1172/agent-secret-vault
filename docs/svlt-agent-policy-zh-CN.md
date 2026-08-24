# SVLT Agent 敏感信息策略

将下面代码块原样放入 Codex、Claude、Hermes、OpenClaw 或其他 MCP Agent 的系统提示、项目规则或工作区规则。SVLT 是 opt-in；这份策略只约束 SVLT 管理路径，不接管用户明确选择的其他凭据来源。

```text
敏感信息访问与使用策略（SVLT）

产品原则：SVLT protects secrets that the user chooses to manage with SVLT. It does not claim ownership of all credentials available to an Agent. The user may explicitly choose plaintext for an operation at any time.

中文原则：SVLT 只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

触发与来源：
1. 出现 secret://，或用户明确说使用 SVLT、使用 SVLT Entry、保存到 SVLT 时，进入 SVLT_MANAGED_OPERATION。
2. 仅出现 password、token、API key、凭据等词，或任务需要登录、SSH、HTTP、数据库、SFTP、浏览器/本地 App 填充，不会自动激活 SVLT。
3. 用户在当前请求中亲自提供明文并明确要求本次使用，或明确选择“这次不用 SVLT”时，进入 USER_EXPLICIT_PLAINTEXT。
4. 用户明确指定 QNAP MCP、GitHub connector、已登录 CLI、环境变量、第三方密码管理器或其他 provider 时，进入 EXTERNAL_PROVIDER_OPERATION。
5. 没有明确来源时才进入 UNMANAGED_CREDENTIAL，并允许按任务需要自动发现；SVLT 不是唯一选择。
6. 来源优先级：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 无明确选择时才自动发现。
7. 以上选择只对当前 operation 有效；不得从上一轮对话、旧 provider 选择或 Agent 状态继承来源。每个 operation 只能产生一个最终 source decision。

SVLT 敏感信息目录写入规范：
1. “敏感信息.md”是由 SVLT 管理的结构化目录，不得使用 shell、编辑器、Python、sed、echo、文件 API 或其他方式直接修改。
2. 只有用户选择使用 SVLT、提供 secret://，或没有指定来源且需要发现 SVLT 记录时，才查询 secret_catalog_search / secret_catalog_get。
3. 新增、修改、移动或删除目录数据必须使用 SVLT 提供的 catalog MCP 工具，不得自行拼接或覆盖 Markdown/JSON。
4. 每条数据必须属于一个一级 Index 和一个 Entry/SubIndex。Secret 只能以合法 secret:// 引用存在，禁止在 JSON 中写入密码、Token、API Key、Cookie、私钥或其他秘密明文。
5. 普通元数据只有在字段明确允许 agentVisible 时才可读取或写入；searchable=true 且 agentVisible=false 的字段允许内部命中，但不得返回字段值或命中原因。
6. 不得修改 schema、id、indexId、revision、完整性标记或 SVLT 管理标记。
7. 如果需要的字段或结构当前 MCP 不支持，应停止并告诉用户，不得通过直接修改“敏感信息.md”绕过 SVLT。该规则不阻止用户选择其他明确允许的凭据工具或直接提供明文。
8. 如果用户要求新增记录，应优先通过 secret_catalog_create_entry 或 Catalog Draft 创建结构；普通元数据和空 Secret placeholder 可以安全写入，需要新秘密时让用户在 SVLT 本机安全表单中填写。绑定已有 secret:// 是独立的高风险操作，不得默认导入用户明文。
9. 修改后必须调用 secret_catalog_validate；验证失败时不得继续使用或尝试自行修复文件结构。
10. 新建 Index/Entry、普通元数据、空 Secret placeholder 和 validate 属于安全目录编辑，默认静默完成，由 App-control 的安全编辑开关控制（默认开启）。绑定、替换或删除已有 secretRef，改变秘密类型、目标或策略，删除含 Secret 的记录，以及批量导入导出必须经过本机审批。MCP 不携带、生成、延长或伪造 lease/nonce；关闭安全编辑时安全写入返回 CATALOG_AGENT_WRITE_NOT_ALLOWED。
11. 遇到 LEGACY_CATALOG_UNSUPPORTED 时必须停止；SVLT 不提供旧版目录自动升级，Agent 不得自行转换或修改旧文件。合法 v2 文件只能由 App 的“验证并接管 v2 文件”流程接管，MCP 不得调用接管操作。

用户明文覆盖规则：
1. 用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。即使上一轮使用 SVLT 或 Catalog 中可能已有对应 Secret，本次仍按用户明确选择执行。
2. 不要搜索、比较、替换、导入 secret://、要求用户删除明文、打开 SVLT、触发 Touch ID，或仅因 Catalog 命中而拒绝本次操作。
3. 不要把用户主动提供的明文识别为 security bypass attempt，也不要判断它与已有 SVLT Secret 相同；SVLT 不做值比对。
4. 如果用户同时明确要求“把这个 Token 存到 SVLT，然后调用”，先走 App/MCP 安全导入流程，之后使用生成的 secret://。

safeWorkflow：
1. 在调用 SVLT 前，先判断用户是否明确选择 SVLT，或是否已经亲自提供并明确要求使用当前明文。
2. 如果用户明确提供明文并要求使用，继续使用该值并遵守当前工具/工作区规则；除非用户要求，不要搜索或替换成 SVLT 引用。
3. 如果用户选择 SVLT，使用 secret_auto_handle_text、secret_search、secret_catalog_search、secret_catalog_get 或专用 secret action。
4. 搜索只返回非敏感上下文和 opaque 引用，不授予明文展示、导出或外发权限。
5. 目录写入后调用 secret_catalog_validate；无授权、完整性失败或旧版目录状态时停止，不要自行修复文件。
6. 需要本机使用 SVLT 秘密时，使用 secret_action_router 或更窄的工具；不要把 SVLT 解密明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。

禁止事项：
- Do not expose plaintext obtained by decrypting an SVLT-managed secret outside the approved SVLT operation.
- 不得把 SVLT 派生明文放入普通 shell、curl、URL、header、环境变量、日志、审计或聊天。
- 不得直接读取、修改或覆盖 managed catalog；不得让用户授权被解释为文件写权限。
- 不得因用户明确选择明文而强制导入 SVLT；也不得因其他 MCP/provider 有凭据而自动抢占。
- 其他仓库、工具和工作区的安全规则仍然有效：用户允许本次使用，不等于允许写入 Git、日志、issue、公开网络或不安全持久化位置。
```

Schema 详见 [`svlt-catalog-schema-v2.md`](svlt-catalog-schema-v2.md)。App 的“智能体自动化 → 敏感信息目录规范”提供同一规范的复制、Schema 查看和目录验证入口。合法 v2 文件只能通过 App 的“验证并接管 v2 文件”流程接管，MCP 不得调用该流程。
