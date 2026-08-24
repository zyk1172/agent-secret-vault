# SVLT Catalog v2 Schema

`敏感信息.md` 的机器数据必须是 SVLT 管理的 JSON fenced block。Markdown 标题只负责可读层级，真实关联由 opaque ID 决定。

```text
Index
├── id       stable opaque ID
├── title
├── aliases[]
└── tags[]

Entry
├── id       stable opaque ID
├── indexId  parent Index ID
├── title
├── type
├── aliases[]
├── endpoints[] { type, host, port? }
├── fields[]
├── notes?
└── tags[]

Field
├── key
├── label
├── type       text | multiline | url | host | port | number | boolean |
│             date | list | secret
├── agentVisible
├── searchable
├── value?     ordinary metadata only
└── secretRef? opaque secret:// reference only
```

约束：

- 文件顶部必须有 `<!-- SVLT-MANAGED-CATALOG schema="2" -->`。
- 每个 Index 与 Entry 都有独立、稳定、不可预测的 ID；重命名不得改变 ID。
- 一个字段不能同时有 `value` 和 `secretRef`。
- `secret` 字段不能有普通 `value`；秘密明文永远不进入 Markdown、JSON、MCP response、日志或审计。
- `indexId` 必须指向现有 Index；Entry ID、Index ID、字段 key 不得重复。
- App 的 Catalog Store 负责 canonical formatting、校验、完整性、revision 和原子写入。
- Agent/Obsidian 必须使用 Catalog MCP/IPC；不得直接修改文件。
- 旧版 `敏感信息.md` 不支持自动升级，运行状态为 `LEGACY_CATALOG_UNSUPPORTED`；Agent 不得自行转换或修改旧文件。
- 人工准备的合法 v2 文件在没有完整性 sidecar 时，只能由 App 的“验证并接管 v2 文件”流程严格校验、备份并建立 `catalog-integrity.json`；MCP 不得调用接管流程。
- Catalog 写入服从 App 当前的 Agent 编辑授权，最长 10 分钟；秘密替换、类型转换、删除秘密、allowlist 和策略变化仍需本机审批。
