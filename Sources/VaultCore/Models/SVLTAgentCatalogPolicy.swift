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
    8. SVLT 正式支持三种写入路径：App 受控写入、Agent 经 MCP 写入、Obsidian/编辑器/脚本直接修改文件。
    9. 无论哪条路径，都必须产生符合 SVLT v3 的结构；直接写文件不会获得更高权限。
    10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
    11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
    12. [[双链]] 属于合法 Markdown 内容，禁止删除或展开成普通文本。
    13. 密码字段不得保存明文。
    14. 密码字段只能为空 placeholder 或合法 secret://。
    15. Token 应写作“令牌”。
    16. API Key 推荐显示为“API 密钥”，但这只是推荐显示标签，不是 schema 合法性约束。
    17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
    18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
    19. endpoint.type 可以是任意非空类型字符串，例如 ssh、postgresql、mysql、redis；结构层合法不等于 executor 支持该类型。
    20. 禁止伪造 secret://。
    21. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
    22. 删除包含密码引用的条目或分组需要用户批准。
    23. 普通标题、别名、备注、标签、非密码字段等修改不触发额外的高风险 secretRef 批准；由 Agent 提交的 mutation 仍必须走 operation-bound write request。
    24. 普通新增分组、条目、字段、空密码 placeholder 不触发额外的高风险 secretRef 批准；不等于无边界或无授权写入。
    25. 合法的普通批量操作不因“批量”本身升级为高风险；一次提交的 batch 仍对应一个精确的 operation-bound write request。
    26. 每一笔 Agent semantic Catalog mutation 都必须由 Agent 主动发起一次精确绑定、一次消费的 operation-bound write request；Agent 不能自行开启权限、扩大或复用授权。
    27. 用户批准需要批准的 Agent Catalog mutation 前必须完成 macOS device-owner authentication；授权只消费一次，不能被另一笔 mutation 复用。
    28. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
    29. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
    30. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
    31. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
    32. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。
    33. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
    34. 受控 MCP Catalog write 的结果必须带 post-commit validation 摘要；secret_catalog_validate 仍用于外部编辑检查、显式 health check 和详细 diagnostics。
    35. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
    36. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
    37. 不得把 SVLT 解密得到的明文写回敏感信息.md。
    38. 凭据来源标签包括 SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL；不得因为用户使用其他凭据 provider 而强制接管。
    """

    public static let documentPolicyDigest: String = SHA256.hash(data: Data(text.utf8))
        .map { String(format: "%02x", $0) }
        .joined()

    public static let documentPolicyBeginMarker = "<!-- SVLT-POLICY-BEGIN version=\"3\" digest=\"\(documentPolicyDigest)\" -->"
    public static let documentPolicyEndMarker = "<!-- SVLT-POLICY-END -->"

    public static let documentPolicyBlock: String = makePolicyBlock(
        text: text,
        beginMarker: documentPolicyBeginMarker
    )

    /// The policy text used by the previous Catalog v3 releases. It is kept
    /// separately from the current policy so fixed legacy digests continue to
    /// identify the exact historical blocks they were intended to migrate.
    private static let legacyPolicyText = """
    SVLT 敏感信息目录写入规范

    1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
    2. ## 表示分组，### 表示条目。
    3. 条目和字段必须符合 SVLT v3 marker 与 schema。
    4. 已存在的 id 必须保持稳定，禁止随意重新生成。
    5. 同一条目不得出现重复 field key。
    6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
    7. 字段不够时再增加。
    8. SVLT 正式支持三种写入路径：App 受控写入、Agent 经 MCP 写入、Obsidian/编辑器/脚本直接修改文件。
    9. 无论哪条路径，都必须产生符合 SVLT v3 的结构；直接写文件不会获得更高权限。
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
    31. 每一笔 Agent semantic Catalog mutation 都必须由 Agent 主动发起一次 operation-bound write request；Agent 不能自行开启权限。
    32. 用户批准 Agent Catalog mutation 前必须完成 macOS device-owner authentication；授权只消费一次，不能被另一笔 mutation 复用。
    33. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
    34. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
    35. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
    36. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
    37. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。
    38. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
    """

    private static let legacyDocumentPolicyBlockTemplate: String = makePolicyBlock(
        text: legacyPolicyText,
        beginMarker: documentPolicyBeginMarker
    )

    private static func makePolicyBlock(text: String, beginMarker: String) -> String {
        let lines = text.components(separatedBy: "\n")
        var result = [documentPolicyBeginMarker, "> [!info]- SVLT 智能体写入规范"]
        for line in lines.dropFirst() {
            result.append(line.isEmpty ? ">" : "> " + line)
        }
        result.append(documentPolicyEndMarker)
        result[0] = beginMarker
        return result.joined(separator: "\n")
    }

    /// Catalog v3 policy blocks from earlier SVLT builds. Keep this exact,
    /// bounded migration allowlist so templates generated by those builds can
    /// be repaired without accepting an arbitrary policy block. The migration
    /// is only applied by the explicit App format-repair flow and still
    /// requires the accepted Catalog semantic state before any bytes are
    /// written.
    public static let legacyDocumentPolicyDigest = "d1c316c832325a8e3b8914bab1cb74b00a53286df5319be184cf043fe682f458"
    public static let legacyDocumentPolicyBeginMarker = "<!-- SVLT-POLICY-BEGIN version=\"3\" digest=\"\(legacyDocumentPolicyDigest)\" -->"

    public static let legacyDocumentPolicyBlock: String = {
        let currentRule = "> 33. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。"
        let legacyRule = "> 33. 恢复功能只能恢复结构和 opaque 引用，不能生成或展开明文。"
        return legacyDocumentPolicyBlockTemplate
            .replacingOccurrences(of: documentPolicyBeginMarker, with: legacyDocumentPolicyBeginMarker)
            .replacingOccurrences(of: currentRule, with: legacyRule)
    }()

    /// The two earlier v3 policy shapes were emitted before the current
    /// operation-bound authorization wording was introduced. They are built
    /// from the current policy lines, with their historical rule changes
    /// applied exactly, and their historical digests are fixed allowlist
    /// identifiers. This avoids accepting a caller-provided policy merely
    /// because it has a plausible marker or self-reported digest.
    public static let legacyDocumentPolicyBlocks: [String] = [
        legacyDocumentPolicyBlock,
        makeLegacyDocumentPolicyBlock(
            digest: "007b4dc3adc7cd0921ce048cde9b1bc148bba478868c5dcebab71b0b55471535",
            replacements: [
                31: "Agent 的安全目录修改需要用户批准的有限授权；Agent 只能申请，不能自行开启。",
                32: "有限 Agent 授权不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。",
                33: "普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。",
                34: "恢复功能只能恢复结构和 opaque 引用，不能生成或展开明文。"
            ],
            removedRuleNumbers: Set(35...38)
        ),
        makeLegacyDocumentPolicyBlock(
            digest: "4bd8b04f91ba9980d48ef263bb691885807c533b6d6c67660a39d9417d257a24",
            replacements: [
                8: "可以使用 App、MCP、Obsidian、编辑器、脚本或其他工具修改，不限制写入渠道。"
            ],
            removedRuleNumbers: Set(31...38)
        )
    ]

    private static func makeLegacyDocumentPolicyBlock(
        digest: String,
        replacements: [Int: String],
        removedRuleNumbers: Set<Int>
    ) -> String {
        let transformed = legacyDocumentPolicyBlockTemplate
            .components(separatedBy: "\n")
            .compactMap { line -> String? in
                guard let number = policyRuleNumber(in: line) else { return line }
                if removedRuleNumbers.contains(number) { return nil }
                if let replacement = replacements[number] { return "> \(number). \(replacement)" }
                return line
            }
        var lines = transformed
        lines[0] = "<!-- SVLT-POLICY-BEGIN version=\"3\" digest=\"\(digest)\" -->"
        return lines.joined(separator: "\n")
    }

    private static func policyRuleNumber(in line: String) -> Int? {
        guard line.hasPrefix("> ") else { return nil }
        let body = line.dropFirst(2)
        guard let separator = body.firstIndex(of: ".") else { return nil }
        return Int(body[..<separator])
    }

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
