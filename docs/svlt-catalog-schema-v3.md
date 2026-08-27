# SVLT Catalog v3：Obsidian 原生格式

`敏感信息.md` 是正常的 Obsidian Markdown，不是 JSON 数据库。机器边界由
SVLT marker 定义，标题、字段正文、备注、空行和双链仍保留为普通 Markdown。

```markdown
<!-- SVLT-CATALOG schema="3" -->
# 敏感信息

<!-- SVLT-POLICY-BEGIN version="3" digest="4b15014d7b07d401e8a4a24a53cafafc24b17533ca4fd0e5827297901580aeae" -->
> [!info]- SVLT 智能体写入规范
> ...
<!-- SVLT-POLICY-END -->

<!-- SVLT-INDEX {"id":"01...","aliases":[],"tags":[]} -->
## QNAP

<!-- SVLT-ENTRY {"id":"01...","type":"credential"} -->
### 管理后台

<!-- SVLT-FIELD {"key":"username","label":"用户名","type":"text","agentVisible":true,"searchable":true} -->
- 用户名：admin

<!-- SVLT-FIELD {"key":"password","label":"密码","type":"secret","agentVisible":true,"searchable":false} -->
- 密码：`secret://01...`

<!-- /SVLT-ENTRY -->
<!-- /SVLT-INDEX -->
```

## 字段值与 secret placeholder

下面是 MCP 创建输入中 `secret` 字段的合法空 placeholder。创建时省略
`value`，由用户稍后在 SVLT App 的安全输入流程中填写：

```json
{
  "key": "password",
  "label": "密码",
  "type": "secret"
}
```

下面的写法不合法；`"value": ""` 仍然是一个 plaintext value，不代表空
placeholder：

```json
{
  "key": "password",
  "label": "密码",
  "type": "secret",
  "value": ""
}
```

安全创建也不能直接携带已有 `secretRef`；绑定或替换 `secret://` 必须走
单独的 App 批准流程。字段 `label` 只需满足 schema 的非空要求；例如推荐把
API Key 显示为“API 密钥”，但该显示标签不是 schema 合法性约束。

## Endpoint 与 executor 边界

`endpoint.type` 是任意非空类型字符串，不是固定的 `http`/`https` 枚举。
例如下面这些 endpoint 在 Catalog 结构层面都可以表达：

```json
[
  {"type":"ssh","host":"192.168.1.10","port":22},
  {"type":"postgresql","host":"db.home","port":5432},
  {"type":"mysql","host":"db.home","port":3306},
  {"type":"redis","host":"nas.home","port":6379}
]
```

结构层合法只表示字段形状满足要求（`type`、`host` 非空，`port` 如提供则
为 `0...65535` 的整数）；它不表示某个 executor 支持该类型，也不授予绕过
executor allowlist、网络限制或操作授权的权限。

约束：

- `##` 是真实分组标题，`###` 是真实条目标题；每个受管分组/条目有稳定 opaque ID。
- 普通字段正文、备注、callout、空行和 `[[WikiLink]]` 都是合法 Markdown；SVLT 修改时只 patch 目标 source range。
- `secret` 字段只能为空 placeholder 或合法 `secret://`，禁止明文、伪造引用、同时设置普通值和引用。
- Agent 不得从 selection JSON、Catalog Markdown 或 `Application Support` sidecar 查找或验证 Index/Entry ID；应使用 MCP 的 list/get/create 响应。目标调用流是 `secret_catalog_list_indices` 浏览分组（包括空分组）、`secret_catalog_list_entries(indexID)` 浏览条目，以及 `secret_catalog_create_structure` 一次创建 Index 和多个 Entry；工具是否可用以当前 MCP `tools/list` 为准。
- 每一笔 Agent Catalog mutation（包括 batch）都必须使用精确绑定、一次消费的 operation-bound write authorization；Agent 不能自行开启、扩大或复用授权。
- 受控 MCP write 的结果必须带 post-commit validation 摘要；`secret_catalog_validate` 仍用于外部编辑检查、显式 health check 和详细 diagnostics。
- `SVLT-POLICY` 是 document-level 折叠 callout，不是分组、条目、字段，不计入搜索和数量。
- 任何合法 writer 都可以修改 v3；安全策略比较 semantic diff：普通 metadata 可不触发额外的高风险 secretRef 批准，绑定/替换/删除已有引用及删除带引用对象需要本机审批。由 Agent 提交的 mutation 仍须走 operation-bound write authorization。
- 原始 Markdown hash 只用于 CAS；空行、用户注释或非受管排版变化不会被当成篡改。Coordinator 使用锁、重读和冲突检测尽量避免丢写，但面对不参与协作的第三方 writer，最终替换仍存在 TOCTOU 窗口；v3 不宣称绝对的 multi-writer atomicity，冲突时应重新读取、rebase 后重试。
- v2 仅作为迁移输入。迁移前必须生成 timestamp backup，严格 decode、v3 再 parse、比较 ID 和完整 secretRef 集合后才替换原文件；legacy v1 不自动升级。

完整写入规则来自 `SVLTAgentCatalogPolicy`，并同步生成文档 policy block 与
MCP `agent_secret_usage_policy` 响应。
