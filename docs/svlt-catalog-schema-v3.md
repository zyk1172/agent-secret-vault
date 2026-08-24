# SVLT Catalog v3：Obsidian 原生格式

`敏感信息.md` 是正常的 Obsidian Markdown，不是 JSON 数据库。机器边界由
SVLT marker 定义，标题、字段正文、备注、空行和双链仍保留为普通 Markdown。

```markdown
<!-- SVLT-CATALOG schema="3" -->
# 敏感信息

<!-- SVLT-POLICY-BEGIN version="3" digest="4bd8b04f91ba9980d48ef263bb691885807c533b6d6c67660a39d9417d257a24" -->
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

约束：

- `##` 是真实分组标题，`###` 是真实条目标题；每个受管分组/条目有稳定 opaque ID。
- 普通字段正文、备注、callout、空行和 `[[WikiLink]]` 都是合法 Markdown；SVLT 修改时只 patch 目标 source range。
- `secret` 字段只能为空 placeholder 或合法 `secret://`，禁止明文、伪造引用、同时设置普通值和引用。
- `SVLT-POLICY` 是 document-level 折叠 callout，不是分组、条目、字段，不计入搜索和数量。
- 任何合法 writer 都可以修改 v3；安全策略比较 semantic diff：普通 metadata 静默接纳，绑定/替换/删除已有引用及删除带引用对象需要本机审批。
- 原始 Markdown hash 只用于 CAS；空行、用户注释或非受管排版变化不会被当成篡改。Coordinator 使用锁、重读和冲突检测尽量避免丢写，但面对不参与协作的第三方 writer，最终替换仍存在 TOCTOU 窗口；v3 不宣称绝对的 multi-writer atomicity，冲突时应重新读取、rebase 后重试。
- v2 仅作为迁移输入。迁移前必须生成 timestamp backup，严格 decode、v3 再 parse、比较 ID 和完整 secretRef 集合后才替换原文件；legacy v1 不自动升级。

完整写入规则来自 `SVLTAgentCatalogPolicy`，并同步生成文档 policy block 与
MCP `agent_secret_usage_policy` 响应。
