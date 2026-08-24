import Foundation

/// The shared human-readable contract shown by the App and returned by the
/// MCP policy tool.  It deliberately describes authority and data shape only;
/// it never contains a secret value or a catalog document path.
public enum SVLTAgentCatalogPolicy {
    public static let text = """
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
    11. 遇到 LEGACY_CATALOG_UNSUPPORTED 时必须停止；SVLT 不提供旧版目录自动升级，Agent 不得自行转换或修改旧文件。合法的 v2 文件只能由 App 的“验证并接管 v2 文件”流程接管，MCP 不得调用接管操作。
    12. Catalog 写入必须使用 App 当前有效的 Agent 编辑授权；授权最长 10 分钟并自动过期。MCP 不携带、生成、延长或伪造 lease/nonce；无授权或授权过期时只能读取和报告状态。
    """

    public static let schema = """
    SVLT Catalog v2

    Index
    - id: opaque stable ID
    - title, aliases, tags

    Entry
    - id: opaque stable ID
    - indexId, title, type, aliases, endpoints, fields, notes, tags

    Field
    - key, label, type, agentVisible, searchable
    - ordinary metadata: value
    - secret: secretRef only

    Field types: text, multiline, url, host, port, number, boolean, date, list, secret.
    A field must never contain both value and secretRef. Secret plaintext is never stored in the catalog or returned by MCP.
    """

    public static let managedMarker = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->"
}
