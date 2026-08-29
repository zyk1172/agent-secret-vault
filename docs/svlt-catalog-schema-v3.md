# SVLT Catalog v3：Obsidian 原生格式

`敏感信息.md` 是正常的 Obsidian Markdown，不是 JSON 数据库。机器边界由
SVLT marker 定义，标题、字段正文、备注、空行和双链仍保留为普通 Markdown。

## 文档区域与写入布局

v3 文档按三个逻辑区域理解（这是 SVLT 自己生成或受控插入时的布局约束）：

1. 前言区：policy block、Note、使用说明、用户段落、callout、评论和 WikiLink 等 unmanaged Markdown。
2. Catalog 主体区：连续排列的 `SVLT-INDEX`、`SVLT-ENTRY`、`SVLT-FIELD` 及其绑定标题、字段正文和 notes。
3. 尾部非托管区：最后一个 Index 后用户保留的普通 Markdown。

前言和尾部内容不属于 semantic Catalog，不计入分组/条目搜索、计数或 App UI。已有未知
用户 Markdown、Note、WikiLink 或评论即使位于两个 Index 之间也保持原位，不会为了追求
连续主体而自动搬迁。新 Index 必须插入最后一个合法 Index 之后、尾部非托管 Markdown
之前；没有 Index 时插入前言之后。新生成 Index 之间由 renderer 生成标准 `\n\n---\n\n`；
已有 `---` 没有 provenance 时按用户内容保留，不能全局重写。同一 Index 内 Entry 之间
使用统一的双空行视觉间距。所有合法 writer 都必须遵守这套写入规则；受控写入优先
source-range minimal patch，只调整目标块和新写入时由 SVLT renderer 明确生成的边界空白，保留
其他用户字节。format repair 不移动无法确认来源的用户 Note/Markdown/WikiLink，也不删除
用户 HR。

## 可直接校验的最小文件模板

下面是完整的、可以直接保存为 `敏感信息.md` 并交给
`secret_catalog_validate` 校验的最小模板。策略块必须原样保留；示例中的
Index/Entry ID 只是这个文档 fixture 的合法 opaque ID，实际新增结构应让
App/MCP 生成 ID。密码字段先使用空 placeholder，不要手造 `secret://` 引用。

App 默认安装的起步模板见 [`Resources/Templates/敏感信息.md`](../Resources/Templates/敏感信息.md)。
它与下面模板保持同一份 policy block 和无秘密示例结构。

```markdown
<!-- SVLT-CATALOG schema="3" -->
# 敏感信息

<!-- SVLT-POLICY-BEGIN version="3" digest="a0d5bc9c4270a7198163323526d2575b9df8d1b834164563626d18bbf70c9605" -->
> [!info]- SVLT 智能体写入规范
>
> 1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
> 2. ## 表示分组，### 表示条目。
> 3. 条目和字段必须符合 SVLT v3 marker 与 schema。
> 4. 已存在的 id 必须保持稳定，禁止随意重新生成。
> 5. 同一条目不得出现重复 field key。
> 6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
> 7. 字段不够时再增加。
> 8. SVLT 正式支持三种写入路径：App 受控写入、Agent 经 MCP 写入、Obsidian/编辑器/脚本直接修改文件。
> 9. 无论哪条路径，都必须产生符合 SVLT v3 的结构；直接写文件不会获得更高权限。
> 10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
> 11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
> 12. [[双链]] 属于合法 Markdown 内容，禁止删除或展开成普通文本。
> 13. 密码字段不得保存明文。
> 14. 密码字段只能为空 placeholder 或合法 secret://。
> 15. Token 应写作“令牌”。
> 16. API Key 推荐显示为“API 密钥”，但这只是推荐显示标签，不是 schema 合法性约束。
> 17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
> 18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
> 19. endpoint.type 可以是任意非空类型字符串，例如 ssh、postgresql、mysql、redis；结构层合法不等于 executor 支持该类型。
> 20. 禁止伪造 secret://。
> 21. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
> 22. 删除包含密码引用的条目或分组需要用户批准。
> 23. 普通标题、别名、备注、标签、非密码字段等修改不触发额外的高风险 secretRef 批准；由 Agent 提交的 mutation 仍必须走 operation-bound write request。
> 24. 普通新增分组、条目、字段、空密码 placeholder 不触发额外的高风险 secretRef 批准；不等于无边界或无授权写入。
> 25. 合法的普通批量操作不因“批量”本身升级为高风险；一次提交的 batch 仍对应一个精确的 operation-bound write request。
> 26. 每一笔 Agent semantic Catalog mutation 都必须由 Agent 主动发起一次精确绑定、一次消费的 operation-bound write request；Agent 不能自行开启权限、扩大或复用授权。
> 27. 每笔需要授权的 Agent semantic Catalog mutation 都会直接触发一次精确绑定的 macOS device-owner authentication；该身份认证本身就是本次用户授权，不存在额外的 App 前置确认，认证票据只消费一次。
> 28. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
> 29. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
> 30. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
> 31. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
> 32. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。
> 33. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
> 34. 受控 MCP Catalog write 的结果必须带 post-commit validation 摘要；secret_catalog_validate 仍用于外部编辑检查、显式 health check 和详细 diagnostics。
> 35. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
> 36. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
> 37. 不得把 SVLT 解密得到的明文写回敏感信息.md。
> 38. 凭据来源标签包括 SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL；不得因为用户使用其他凭据 provider 而强制接管。
> 39. SVLT 自己生成或受控插入的 managed Catalog 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局；已有未知 Note、说明、用户 Markdown、callout 与 WikiLink 不属于 Catalog semantic model，必须保持原位。
> 40. 新建 Index 必须插入最后一个合法 SVLT-INDEX 之后、尾部非托管 Markdown 之前；如果已有用户 Markdown 位于 Index 之间，不为追求连续主体而搬迁它；当前没有 Index 时，插入 policy 和前言之后，不得追加到用户尾注之后。
> 41. 新生成 Index 之间使用 renderer 的标准 Markdown 分隔 \n\n---\n\n；已有 --- 没有 provenance 时按用户内容保留，不猜测或全局重写用户自己的分隔线。
> 42. 同一 Index 内的 Entry 之间使用统一的双空行视觉间距；新增、batch、migration、format repair 和 minimal patch 不得混用一行、两行或三行布局。
> 43. Catalog 写入遵守最小修改原则；只改目标 source range 和新写入时由 SVLT renderer 明确生成的边界空白，保留用户普通 Markdown、注释、WikiLink、Note 和尾部内容；format repair 不搬迁无法确认来源的 Note/Markdown/WikiLink，也不删除用户 HR。
> 44. Agent 浏览必须使用 secret_catalog_list_indices、secret_catalog_list_entries、secret_catalog_get、secret_catalog_create_structure 等 MCP 响应发现 opaque ID；不得读取 selection sidecar、敏感信息.md 或 Application Support 文件解析 ID。
> 45. 需要用户输入秘密时使用 secret_catalog_request_secure_inputs；若 transport 返回 PENDING 与 requestID，只能用 secret_catalog_secure_input_status 轮询同一请求，Agent 永远只能收到状态/非敏感结果，不能收到 plaintext。
<!-- SVLT-POLICY-END -->

<!-- SVLT-INDEX {"aliases":[],"id":"0123456789ABCDEFGHJKMNPQRS","tags":[]} -->
## 示例服务

<!-- SVLT-ENTRY {"aliases":[],"endpoints":[],"id":"0123456789ABCDEFGHJKMNPQRT","tags":[],"type":"credential"} -->
### 示例登录

<!-- SVLT-FIELD {"agentVisible":true,"key":"username","label":"用户名","searchable":true,"type":"text"} -->
- 用户名：示例账号
<!-- /SVLT-FIELD -->

<!-- SVLT-FIELD {"agentVisible":true,"key":"password","label":"密码","searchable":false,"type":"secret"} -->
- 密码：
<!-- /SVLT-FIELD -->

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
- 受控 MCP write 的结果必须带 post-commit validation 摘要。只有 `validation.status == FOUND` 且 `validation.diagnostics` 为空才表示提交后的健康确认成功；`CREATED` 搭配 `CATALOG_UNAVAILABLE` 等状态表示写入可能已提交但确认未完成，不要盲目重试写入，服务恢复后再用 `secret_catalog_validate` 显式确认。
- `SVLT-POLICY` 是 document-level 折叠 callout，不是分组、条目、字段，不计入搜索和数量。
- 任何合法 writer 都可以修改 v3；安全策略比较 semantic diff：普通 metadata 可不触发额外的高风险 secretRef 批准，绑定/替换/删除已有引用及删除带引用对象需要本机审批。由 Agent 提交的 mutation 仍须走 operation-bound write authorization。
- 原始 Markdown hash 只用于 CAS；空行、用户注释或非受管排版变化不会被当成篡改。Coordinator 使用锁、重读和冲突检测尽量避免丢写，但面对不参与协作的第三方 writer，最终替换仍存在 TOCTOU 窗口；v3 不宣称绝对的 multi-writer atomicity，冲突时应重新读取、rebase 后重试。
- v2 仅作为迁移输入。迁移前必须生成 timestamp backup，严格 decode、v3 再 parse、比较 ID 和完整 secretRef 集合后才替换原文件；legacy v1 不自动升级。

完整写入规则来自 `SVLTAgentCatalogPolicy`，并同步生成文档 policy block 与
MCP `agent_secret_usage_policy` 响应。
