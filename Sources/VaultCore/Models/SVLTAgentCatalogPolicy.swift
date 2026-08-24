import Foundation

/// Describes which credential owner/source the user selected for the current
/// operation. This value never carries a credential or a decrypted value.
public enum SVLTCredentialScope: String, Codable, CaseIterable, Sendable {
    case svltManagedOperation = "SVLT_MANAGED_OPERATION"
    case userExplicitPlaintext = "USER_EXPLICIT_PLAINTEXT"
    case externalProviderOperation = "EXTERNAL_PROVIDER_OPERATION"
    case unmanagedCredential = "UNMANAGED_CREDENTIAL"
}

/// The source ordering used when an Agent has more than one possible
/// credential provider. It is a policy ordering, not an instruction to search
/// for or compare credential values.
public enum SVLTCredentialSource: String, Codable, CaseIterable, Sendable {
    case userCurrentRequest = "USER_CURRENT_REQUEST"
    case explicitExternalProvider = "EXPLICIT_EXTERNAL_PROVIDER"
    case explicitSVLTReference = "EXPLICIT_SVLT_REFERENCE"
    case automaticDiscovery = "AUTOMATIC_DISCOVERY"
}

/// A user-selected plaintext decision contains only provenance and intent.
/// The plaintext itself is deliberately not representable by this type.
public enum ExplicitPlaintextOverride: String, Codable, CaseIterable, Sendable, Equatable {
    case userSuppliedForCurrentOperation = "USER_SUPPLIED_FOR_CURRENT_OPERATION"
    case explicitlySelectedNoSVLT = "EXPLICITLY_SELECTED_NO_SVLT"

    public var scope: SVLTCredentialScope { .userExplicitPlaintext }
    public var source: SVLTCredentialSource { .userCurrentRequest }
}

/// A single, per-operation credential decision. Previous turns or provider
/// selections are intentionally not represented here and cannot become sticky
/// state. Construct exactly one case for each operation.
public enum SVLTCredentialSelection: Equatable, Sendable {
    case userPlaintext(ExplicitPlaintextOverride)
    case externalProvider
    case svlt
    case automatic

    public static let sourcePriority: [SVLTCredentialSource] = [
        .userCurrentRequest,
        .explicitExternalProvider,
        .explicitSVLTReference,
        .automaticDiscovery
    ]

    public var scope: SVLTCredentialScope {
        switch self {
        case .userPlaintext:
            return .userExplicitPlaintext
        case .externalProvider:
            return .externalProviderOperation
        case .svlt:
            return .svltManagedOperation
        case .automatic:
            return .unmanagedCredential
        }
    }

    public var source: SVLTCredentialSource {
        switch self {
        case .userPlaintext:
            return .userCurrentRequest
        case .externalProvider:
            return .explicitExternalProvider
        case .svlt:
            return .explicitSVLTReference
        case .automatic:
            return .automaticDiscovery
        }
    }

    public var shouldInvokeSVLT: Bool { self == .svlt }

    public var shouldSearchSVLT: Bool {
        switch self {
        case .automatic, .svlt:
            return true
        case .userPlaintext, .externalProvider:
            return false
        }
    }
}

/// Provenance for a value that is already in a caller's process. SVLT does
/// not compare values across these cases: independently supplied user text is
/// not treated as SVLT-derived even if the bytes happen to match.
public enum SVLTPlaintextProvenance: String, Codable, CaseIterable, Sendable {
    case userExplicitPlaintext = "USER_EXPLICIT_PLAINTEXT"
    case svltDerivedPlaintext = "SVLT_DERIVED_PLAINTEXT"
    case externalProviderCredential = "EXTERNAL_PROVIDER_CREDENTIAL"
}

public enum SVLTPlaintextBoundary {
    /// User-provided and external-provider values are outside SVLT's scope.
    /// Values decrypted from an SVLT reference remain confined to an approved
    /// SVLT operation.
    public static func mayLeaveSVLTOperation(
        provenance: SVLTPlaintextProvenance,
        approvedSVLTOperation: Bool
    ) -> Bool {
        switch provenance {
        case .svltDerivedPlaintext:
            return approvedSVLTOperation
        case .userExplicitPlaintext, .externalProviderCredential:
            return true
        }
    }
}

/// The shared human-readable contract shown by the App and returned by the
/// MCP policy tool. It describes authority, scope, and data shape only; it
/// never contains a secret value or a catalog document path.
public enum SVLTAgentCatalogPolicy {
    public static let text = """
    SVLT 敏感信息目录写入规范

    SVLT 是 opt-in 的秘密保护工具，只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

    1. “敏感信息.md”是由 SVLT 管理的结构化目录，不得使用 shell、编辑器、Python、sed、echo、文件 API 或其他方式直接修改。
    2. 只有用户选择使用 SVLT、提供 secret://，或没有指定来源且需要发现 SVLT 记录时，才查询敏感信息：secret_catalog_search / secret_catalog_get。
    3. 新增、修改、移动或删除目录数据必须使用 SVLT 提供的 catalog MCP 工具，不得自行拼接或覆盖 Markdown/JSON。
    4. 每条数据必须属于一个一级 Index 和一个 Entry/SubIndex。Secret 只能以合法 secret:// 引用存在，禁止在 JSON 中写入密码、Token、API Key、Cookie、私钥或其他秘密明文。
    5. 普通元数据只有在字段明确允许 agentVisible 时才可读取或写入；searchable=true 且 agentVisible=false 的字段允许内部命中，但不得返回字段值或命中原因。
    6. 不得修改 schema、id、indexId、revision、完整性标记或 SVLT 管理标记。
    7. 如果需要的字段或结构当前 MCP 不支持，应停止并告诉用户，不得通过直接修改“敏感信息.md”绕过 SVLT。该规则不阻止用户在本次操作中选择其他明确允许的凭据工具或直接提供明文。
    8. 如果用户要求新增记录，应优先通过 Catalog Draft 创建结构；Secret 字段使用 placeholder 或已有 secret:// 引用，需要新秘密时让用户在 SVLT 本机安全表单中填写。
    9. 修改后必须调用 secret_catalog_validate；验证失败时不得继续使用或尝试自行修复文件结构。
    10. 即使用户要求修改目录，也不代表允许绕过 SVLT；用户授权的是目标操作，不是直接文件写权限。另一方面，用户明确选择本次直接使用明文时，不需要导入、转换、检索、SVLT 授权或 Touch ID。
    11. 遇到 LEGACY_CATALOG_UNSUPPORTED 时必须停止；SVLT 不提供旧版目录自动升级，Agent 不得自行转换或修改旧文件。合法的 v2 文件只能由 App 的“验证并接管 v2 文件”流程接管，MCP 不得调用接管操作。
    12. Catalog 写入必须使用 App 当前有效的 Agent 编辑授权；授权最长 10 分钟并自动过期。MCP 不携带、生成、延长或伪造 lease/nonce；无授权或授权过期时只能读取和报告状态。

    范围与来源优先级：
    - SVLT_MANAGED_OPERATION：用户明确要求使用 SVLT、Entry 或 secret://；秘密仍只能在 SVLT 批准的专用操作内解析。
    - USER_EXPLICIT_PLAINTEXT：用户在当前请求中亲自提供明文并明确要求本次使用，或明确选择“不使用 SVLT”。即使 SVLT 可能存在相同凭据，本次也不得搜索、比较、替换、阻断或要求审批。
    - EXTERNAL_PROVIDER_OPERATION：用户明确选择设备 MCP、GitHub connector、已登录 CLI、环境变量或其他凭据提供方；SVLT 不得抢占。
    - UNMANAGED_CREDENTIAL：用户没有选择 SVLT，且没有可用的明确外部来源；不得把它自动升级为 SVLT 管理。
    - 来源优先级为：用户当前明确凭据/来源 → 用户明确选择的外部 provider → 用户明确选择的 SVLT → 无明确选择时才自动发现。
    - 以上判断只对当前 operation 有效；不得从上一轮对话、旧 provider 选择或 Agent 状态继承来源。每个 operation 只能产生一个最终 credential source decision。
    - 不比较用户明文与 SVLT secret 的值，也不因值可能相同而改变 provenance。

    用户明文覆盖规则：用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。不要自动创建 Secret、替换为 secret://、要求用户删除明文、打开 SVLT、触发 Touch ID，或仅因 Catalog 中可能已有对应 Secret 而拒绝本次操作。其他工作区、仓库、工具的日志、持久化和外发规则仍然有效。

    SVLT 派生明文边界：不得把 secret:// 经 SVLT 解密得到的明文转交普通 shell、curl、URL、header、环境变量、日志或聊天。禁止的是 Agent 自己洗出 SVLT 明文绕过专用操作，不是用户独立重新提供明文。

    SVLT 范围之外：设备 MCP 自持凭据、GitHub connector 自有授权、已登录 CLI、环境变量、第三方密码管理器和用户明确提供的当前明文由其各自工具/项目安全规则负责，SVLT 不得自动劫持。
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
    A field must never contain both value and secretRef. Secret plaintext is never stored in the catalog or returned by MCP. This catalog rule does not prohibit a user from choosing plaintext for a separate, current operation outside SVLT.

    Credential scopes: SVLT_MANAGED_OPERATION, USER_EXPLICIT_PLAINTEXT, EXTERNAL_PROVIDER_OPERATION, UNMANAGED_CREDENTIAL.
    Credential selection is per-operation; a later user choice replaces an earlier provider choice.
    User plaintext is not compared with secretRef values. SVLT-derived plaintext remains inside the approved SVLT operation.
    """

    public static let managedMarker = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->"
}
