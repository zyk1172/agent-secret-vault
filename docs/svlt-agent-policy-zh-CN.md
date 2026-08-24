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
1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
2. `##` 表示分组，`###` 表示条目。
3. 条目和字段必须符合 SVLT v3 marker 与 schema。
4. 已存在的 id 必须保持稳定，禁止随意重新生成。
5. 同一条目不得出现重复 field key。
6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
7. 字段不够时再增加。
8. 可以使用 App、MCP、Obsidian、编辑器、脚本或其他工具修改，不限制写入渠道。
9. 无论使用什么方式，都必须产生符合 SVLT v3 的结构。
10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
12. `[[双链]]` 属于合法 Markdown 内容，禁止删除或展开成普通文本。
13. 密码字段不得保存明文。
14. 密码字段只能为空 placeholder 或合法 `secret://`。
15. Token 应写作“令牌”。
16. API Key 应写作“API 密钥”。
17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
19. 禁止伪造 `secret://`。
20. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
21. 删除包含密码引用的条目或分组需要用户批准。
22. 普通标题、别名、备注、标签、非密码字段等修改可以静默完成。
23. 普通新增分组、条目、字段、空密码 placeholder 可以静默完成。
24. 合法的普通批量操作不因“批量”本身升级为高风险。
25. 修改完成后必须通过 Catalog validation（`secret_catalog_validate`）。
26. 校验失败时不得继续自行猜测修复结构。
27. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
28. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
29. 不得把 SVLT 解密得到的明文写回 `敏感信息.md`。
30. 凭据来源标签包括 `SVLT_MANAGED_OPERATION`、`USER_EXPLICIT_PLAINTEXT`、`EXTERNAL_PROVIDER_OPERATION`、`UNMANAGED_CREDENTIAL`；不得因为用户使用其他凭据 provider 而强制接管。

目录状态规则：
- v3 的外部合法编辑由 SVLT coordinator 重新解析；格式/普通语义变化可以接纳，高风险语义变化进入本机审批，不按编辑器或传输渠道一律拒绝。
- `SVLT-POLICY` 是 document-level 折叠 callout，不属于分组、条目、字段、搜索结果或计数。
- v2 仅作为迁移输入。遇到 `LEGACY_CATALOG_UNSUPPORTED` 必须停止；合法 v2 文件只能由 App 的“备份、验证并升级”流程接管，MCP 不得调用接管操作。

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
- 不得写入不符合 v3 marker/schema 的 Markdown；不得把用户批准高风险语义变化解释为输出 SVLT 解密明文的权限。
- 不得因用户明确选择明文而强制导入 SVLT；也不得因其他 MCP/provider 有凭据而自动抢占。
- 其他仓库、工具和工作区的安全规则仍然有效：用户允许本次使用，不等于允许写入 Git、日志、issue、公开网络或不安全持久化位置。
```

Schema 详见 [`svlt-catalog-schema-v3.md`](svlt-catalog-schema-v3.md)；v2 仅见于 [`svlt-catalog-schema-v2.md`](svlt-catalog-schema-v2.md) 的迁移说明。App 不展示 policy 正文；`SVLTAgentCatalogPolicy` 同时生成文档 policy block 和 MCP `agent_secret_usage_policy` 响应。
