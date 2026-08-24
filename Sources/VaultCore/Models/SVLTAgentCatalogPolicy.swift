import CryptoKit
import Foundation

public enum SVLTCredentialScope: String, Codable, CaseIterable, Sendable {
    case svltManagedOperation = "SVLT_MANAGED_OPERATION"
    case userExplicitPlaintext = "USER_EXPLICIT_PLAINTEXT"
    case externalProviderOperation = "EXTERNAL_PROVIDER_OPERATION"
    case unmanagedCredential = "UNMANAGED_CREDENTIAL"
}

public enum SVLTCredentialSource: String, Codable, CaseIterable, Sendable {
    case userCurrentRequest = "USER_CURRENT_REQUEST"
    case explicitExternalProvider = "EXPLICIT_EXTERNAL_PROVIDER"
    case explicitSVLTReference = "EXPLICIT_SVLT_REFERENCE"
    case automaticDiscovery = "AUTOMATIC_DISCOVERY"
}

public enum ExplicitPlaintextOverride: String, Codable, CaseIterable, Sendable, Equatable {
    case userSuppliedForCurrentOperation = "USER_SUPPLIED_FOR_CURRENT_OPERATION"
    case explicitlySelectedNoSVLT = "EXPLICITLY_SELECTED_NO_SVLT"

    public var scope: SVLTCredentialScope { .userExplicitPlaintext }
    public var source: SVLTCredentialSource { .userCurrentRequest }
}

public enum SVLTCredentialSelection: Equatable, Sendable {
    case userPlaintext(ExplicitPlaintextOverride)
    case externalProvider
    case svlt
    case automatic

    public static let sourcePriority: [SVLTCredentialSource] = [
        .userCurrentRequest, .explicitExternalProvider, .explicitSVLTReference, .automaticDiscovery
    ]

    public var scope: SVLTCredentialScope {
        switch self {
        case .userPlaintext: return .userExplicitPlaintext
        case .externalProvider: return .externalProviderOperation
        case .svlt: return .svltManagedOperation
        case .automatic: return .unmanagedCredential
        }
    }

    public var source: SVLTCredentialSource {
        switch self {
        case .userPlaintext: return .userCurrentRequest
        case .externalProvider: return .explicitExternalProvider
        case .svlt: return .explicitSVLTReference
        case .automatic: return .automaticDiscovery
        }
    }

    public var shouldInvokeSVLT: Bool { self == .svlt }
    public var shouldSearchSVLT: Bool {
        switch self {
        case .automatic, .svlt: return true
        case .userPlaintext, .externalProvider: return false
        }
    }
}

public enum SVLTPlaintextProvenance: String, Codable, CaseIterable, Sendable {
    case userExplicitPlaintext = "USER_EXPLICIT_PLAINTEXT"
    case svltDerivedPlaintext = "SVLT_DERIVED_PLAINTEXT"
    case externalProviderCredential = "EXTERNAL_PROVIDER_CREDENTIAL"
}

public enum SVLTPlaintextBoundary {
    public static func mayLeaveSVLTOperation(provenance: SVLTPlaintextProvenance, approvedSVLTOperation: Bool) -> Bool {
        switch provenance {
        case .svltDerivedPlaintext: return approvedSVLTOperation
        case .userExplicitPlaintext, .externalProviderCredential: return true
        }
    }
}

/// The only policy source. It feeds the document callout and the MCP policy
/// response; the App UI intentionally does not display this body.
public enum SVLTAgentCatalogPolicy {
    public static let text = """
    SVLT 敏感信息目录写入规范

    1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
    2. ## 表示分组，### 表示条目。
    3. 条目和字段必须符合 SVLT v3 marker 与 schema。
    4. 已存在的 id 必须保持稳定，禁止随意重新生成。
    5. 同一条目不得出现重复 field key。
    6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
    7. 字段不够时再增加。
    8. 可以使用 App、MCP、Obsidian、编辑器、脚本或其他工具修改，不限制写入渠道。
    9. 无论使用什么方式，都必须产生符合 SVLT v3 的结构。
    10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
    11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
    12. [[双链]] 属于合法 Markdown 内容，禁止删除或展开成普通文本。
    13. 密码字段不得保存明文。
    14. 密码字段只能为空 placeholder 或合法 secret://。
    15. Token 应写作“令牌”。
    16. API Key 应写作“API 密钥”。
    17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
    18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
    19. 禁止伪造 secret://。
    20. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
    21. 删除包含密码引用的条目或分组需要用户批准。
    22. 普通标题、别名、备注、标签、非密码字段等修改可以静默完成。
    23. 普通新增分组、条目、字段、空密码 placeholder 可以静默完成。
    24. 合法的普通批量操作不因“批量”本身升级为高风险。
    25. 修改完成后必须通过 Catalog validation（secret_catalog_validate）。
    26. 校验失败时不得继续自行猜测修复结构。
    27. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
    28. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
    29. 不得把 SVLT 解密得到的明文写回敏感信息.md。
    30. 凭据来源标签包括 SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL；不得因为用户使用其他凭据 provider 而强制接管。
    """

    public static let documentPolicyDigest: String = SHA256.hash(data: Data(text.utf8))
        .map { String(format: "%02x", $0) }
        .joined()

    public static let documentPolicyBeginMarker = "<!-- SVLT-POLICY-BEGIN version=\"3\" digest=\"\(documentPolicyDigest)\" -->"
    public static let documentPolicyEndMarker = "<!-- SVLT-POLICY-END -->"

    public static let documentPolicyBlock: String = {
        let lines = text.components(separatedBy: "\n")
        var result = [documentPolicyBeginMarker, "> [!info]- SVLT 智能体写入规范"]
        for line in lines.dropFirst() {
            result.append(line.isEmpty ? ">" : "> " + line)
        }
        result.append(documentPolicyEndMarker)
        return result.joined(separator: "\n")
    }()

    public static let schema = """
    SVLT Catalog v3

    ## is a real Markdown heading for a group and ### is a real Markdown heading for an entry.
    SVLT-INDEX, SVLT-ENTRY and SVLT-FIELD markers carry stable opaque IDs and structural metadata.
    Ordinary field values remain Markdown; a secret field contains only an empty placeholder or opaque secretRef.
    The document-level SVLT-POLICY block is not part of SecretCatalogDocument, search, counts, or UI.
    Field types: text, multiline, url, host, port, number, boolean, date, list, secret.
    Credential scopes: SVLT_MANAGED_OPERATION, USER_EXPLICIT_PLAINTEXT, EXTERNAL_PROVIDER_OPERATION, UNMANAGED_CREDENTIAL.
    """

    public static let managedMarker = "<!-- SVLT-CATALOG schema=\"3\" -->"
}
