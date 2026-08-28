import Foundation
import Testing
@testable import VaultCore

private let v2IndexID = "0123456789ABCDEFGHJKMNPQRS"
private let v2EntryID = "0123456789ABCDEFGHJKMNPQRT"
private let v2KomgaEntryID = "0123456789ABCDEFGHJKMNPQRV"
private let v2PasswordReference = "secret://0123456789ABCDEFGHJKMNPQRW"
private let v2TokenReference = "secret://0123456789ABCDEFGHJKMNPQRY"
private let layoutIndexAID = "0123456789ABCDEFGHJKMNPQRS"
private let layoutIndexBID = "0123456789ABCDEFGHJKMNPQRT"
private let layoutIndexCID = "0123456789ABCDEFGHJKMNPQRV"
private let layoutEntryAID = "0123456789ABCDEFGHJKMNPQRW"
private let layoutEntryBID = "0123456789ABCDEFGHJKMNPQRY"
private let layoutEntryCID = "0123456789ABCDEFGHJKMNPQRZ"
private let layoutIndexDID = "0123456789ABCDEFGHJKMNPQSA"

private func layoutEntry(id: String, indexID: String, title: String) -> SecretCatalogEntry {
    SecretCatalogEntry(
        id: id,
        indexId: indexID,
        title: title,
        fields: [SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("user"))]
    )
}

private func layoutEntry(_ entry: SecretCatalogEntry, in indexID: String) -> SecretCatalogEntry {
    SecretCatalogEntry(
        id: entry.id,
        indexId: indexID,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: entry.fields,
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )
}

private let pr21ReleasedPolicyBlockFixture = """
<!-- SVLT-POLICY-BEGIN version="3" digest="e67fb9b5e9b62b3f72df86b6a3ec89ec1d40328c9d67fd7ad3e43f05c466e6f4" -->
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
<!-- SVLT-POLICY-END -->
"""

private func qnapDocument() -> SecretCatalogDocument {
    let index = SecretCatalogIndex(
        id: v2IndexID,
        title: "QNAP",
        aliases: ["NAS 管理"],
        tags: ["NAS"]
    )
    let username = SecretCatalogFieldValue(
        key: "username",
        label: "用户名",
        type: .text,
        value: .string("admin")
    )
    let password = SecretCatalogFieldValue(
        key: "password",
        label: "密码",
        type: .secret,
        agentVisible: true,
        searchable: false,
        secretRef: v2PasswordReference
    )
    let admin = SecretCatalogEntry(
        id: v2EntryID,
        indexId: v2IndexID,
        title: "QNAP 管理后台登录",
        endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
        fields: [username, password],
        tags: ["管理"]
    )
    let komga = SecretCatalogEntry(
        id: v2KomgaEntryID,
        indexId: v2IndexID,
        title: "Komga 漫画服务器登录",
        aliases: ["漫画服务器", "Komga"],
        endpoints: [CatalogEndpoint(type: "http", host: "192.168.2.240", port: 25600)],
        fields: [
            SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("zyk")),
            SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: v2TokenReference)
        ],
        tags: ["漫画", "Komga"]
    )
    return SecretCatalogDocument(indexes: [index], entries: [admin, komga])
}

@Test func catalogV3RoundTripsWithCanonicalPolicyBlockWithoutPlaintext() throws {
    let document = qnapDocument()
    let rendered = try SensitiveCatalogDocumentCodec.encode(document)
    let decoded = try SensitiveCatalogDocumentCodec.decode(rendered)

    #expect(decoded == document)
    #expect(rendered.hasPrefix(SensitiveCatalogDocumentCodec.v3Marker + "\n"))
    #expect(rendered.contains("SVLT-POLICY-BEGIN"))
    #expect(rendered.contains("SVLT-INDEX"))
    #expect(rendered.contains("SVLT-ENTRY"))
    #expect(rendered.contains("SVLT-FIELD"))
    #expect(!rendered.contains("indexId"))
    #expect(rendered.contains(v2IndexID))
    #expect(!rendered.contains("\r"))
    #expect(!rendered.contains("password-plaintext-canary"))
    #expect(try SensitiveCatalogDocumentCodec.canonicalData(document) == Data(rendered.utf8))
}

@Test func catalogV3EmptyTemplateIsARealMarkdownDocumentWithoutFakeCatalogData() throws {
    let rendered = try SensitiveCatalogDocumentCodec.encode(SecretCatalogDocument())

    #expect(try SensitiveCatalogDocumentCodec.decode(rendered).indexes.isEmpty)
    #expect(try SensitiveCatalogDocumentCodec.decode(rendered).entries.isEmpty)
    #expect(rendered.contains("# 敏感信息"))
    #expect(rendered.contains("SVLT-POLICY-BEGIN"))
    #expect(!rendered.contains("<!-- SVLT-INDEX "))
    #expect(!rendered.contains("<!-- SVLT-ENTRY "))
    #expect(!rendered.contains("QNAP"))
}

@Test func catalogV3RequiresExactlyOneUntamperedPolicyBlock() throws {
    let rendered = try SensitiveCatalogDocumentCodec.encode(SecretCatalogDocument())

    let missing = rendered.replacingOccurrences(
        of: SVLTAgentCatalogPolicy.documentPolicyBlock + "\n",
        with: ""
    )
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(missing)
    }

    let duplicate = rendered.replacingOccurrences(
        of: "\n\n\(SVLTAgentCatalogPolicy.documentPolicyBlock)",
        with: "\n\n\(SVLTAgentCatalogPolicy.documentPolicyBlock)\n\n\(SVLTAgentCatalogPolicy.documentPolicyBlock)"
    )
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(duplicate)
    }

    let tampered = rendered.replacingOccurrences(
        of: "> 13. 密码字段不得保存明文。",
        with: "> 13. 密码字段可以保存明文。"
    )
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(tampered)
    }
}

@Test func catalogV3FormatRepairMigratesOnlyTheKnownPreviousPolicyBlock() throws {
    let rendered = try SensitiveCatalogDocumentCodec.encode(SecretCatalogDocument())
    for legacyPolicyBlock in SVLTAgentCatalogPolicy.legacyDocumentPolicyBlocks {
        let legacy = rendered.replacingOccurrences(
            of: SVLTAgentCatalogPolicy.documentPolicyBlock,
            with: legacyPolicyBlock
        )

        #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
            try SensitiveCatalogDocumentCodec.decode(legacy)
        }

        let plan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(legacy.utf8)))
        #expect(plan.canRepair)
        #expect(plan.repairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
        #expect(plan.unrepairableDiagnostics.isEmpty)

        let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(legacy.utf8))
        #expect(repaired == Data(rendered.utf8))

        let unrelated = legacy.replacingOccurrences(of: "> 13. 密码字段不得保存明文。", with: "> 13. 不可信内容。")
        let unrelatedPlan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(unrelated.utf8)))
        #expect(!unrelatedPlan.canRepair)
        #expect(unrelatedPlan.unrepairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
    }
}

@Test func catalogV3FormatRepairMigratesThePR19BaseTemplateWithoutChangingSemantics() throws {
    // This is the canonical empty template shipped by PR #19's base commit.
    // Keep it fixed in the test so a future policy edit cannot silently lose
    // compatibility with the immediately previous release.
    let previousTemplate = """
    <!-- SVLT-CATALOG schema="3" -->
    # 敏感信息

    <!-- SVLT-POLICY-BEGIN version="3" digest="5259128b1df47f9e24b46892186654f02c9793fb0e0318b016b4b8a135b3e595" -->
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
    > 16. API Key 应写作“API 密钥”。
    > 17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
    > 18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
    > 19. 禁止伪造 secret://。
    > 20. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
    > 21. 删除包含密码引用的条目或分组需要用户批准。
    > 22. 普通标题、别名、备注、标签、非密码字段等修改可以静默完成。
    > 23. 普通新增分组、条目、字段、空密码 placeholder 可以静默完成。
    > 24. 合法的普通批量操作不因“批量”本身升级为高风险。
    > 25. 修改完成后必须通过 Catalog validation（secret_catalog_validate）。
    > 26. 校验失败时不得继续自行猜测修复结构。
    > 27. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
    > 28. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
    > 29. 不得把 SVLT 解密得到的明文写回敏感信息.md。
    > 30. 凭据来源标签包括 SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL；不得因为用户使用其他凭据 provider 而强制接管。
    > 31. 每一笔 Agent semantic Catalog mutation 都必须由 Agent 主动发起一次 operation-bound write request；Agent 不能自行开启权限。
    > 32. 用户批准 Agent Catalog mutation 前必须完成 macOS device-owner authentication；授权只消费一次，不能被另一笔 mutation 复用。
    > 33. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
    > 34. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
    > 35. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
    > 36. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
    > 37. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。
    > 38. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
    <!-- SVLT-POLICY-END -->
    """
    let policyStart = try #require(previousTemplate.range(of: "<!-- SVLT-POLICY-BEGIN"))
    let policyEnd = try #require(previousTemplate.range(of: "<!-- SVLT-POLICY-END -->"))
    let previousPolicyBlock = String(previousTemplate[policyStart.lowerBound..<policyEnd.upperBound])
    #expect(previousPolicyBlock == SVLTAgentCatalogPolicy.previousDocumentPolicyBlock)

    let canonical = try SensitiveCatalogDocumentCodec.encode(qnapDocument())
    let legacy = canonical.replacingOccurrences(
        of: SVLTAgentCatalogPolicy.documentPolicyBlock,
        with: previousPolicyBlock
    )
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(legacy)
    }

    let plan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(legacy.utf8)))
    #expect(plan.canRepair)
    #expect(plan.repairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
    #expect(plan.unrepairableDiagnostics.isEmpty)

    let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(legacy.utf8))
    #expect(repaired == Data(canonical.utf8))
    let canonicalDocument = try SensitiveCatalogDocumentCodec.decode(canonical)
    let repairedDocument = try SensitiveCatalogDocumentCodec.decode(String(data: repaired, encoding: .utf8)!)
    #expect(repairedDocument == canonicalDocument)
    #expect(
        Set(repairedDocument.entries.flatMap { $0.fields.compactMap(\.secretRef) })
            == Set(canonicalDocument.entries.flatMap { $0.fields.compactMap(\.secretRef) })
    )
}

@Test func catalogV3FormatRepairMigratesThePreAutoAuthorizationPolicyWithoutChangingSemantics() throws {
    let previousPolicy = SVLTAgentCatalogPolicy.preAutoAuthorizationDocumentPolicyBlock
    #expect(SVLTAgentCatalogPolicy.legacyDocumentPolicyBlocks.contains(previousPolicy))

    let canonical = try SensitiveCatalogDocumentCodec.encode(qnapDocument())
    let legacy = canonical.replacingOccurrences(
        of: SVLTAgentCatalogPolicy.documentPolicyBlock,
        with: previousPolicy
    )
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(legacy)
    }

    let plan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(legacy.utf8)))
    #expect(plan.canRepair)
    #expect(plan.repairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
    #expect(plan.unrepairableDiagnostics.isEmpty)

    let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(legacy.utf8))
    #expect(repaired == Data(canonical.utf8))

    let canonicalDocument = try SensitiveCatalogDocumentCodec.decode(canonical)
    let repairedDocument = try SensitiveCatalogDocumentCodec.decode(String(data: repaired, encoding: .utf8)!)
    #expect(repairedDocument == canonicalDocument)
    #expect(
        Set(repairedDocument.entries.flatMap { $0.fields.compactMap(\.secretRef) })
            == Set(canonicalDocument.entries.flatMap { $0.fields.compactMap(\.secretRef) })
    )
}

@Test func catalogV3FormatRepairMigratesTheExactPR21ReleasedPolicyFixture() throws {
    // Frozen from Resources/Templates/敏感信息.md at merge 890fff8. This
    // must remain an exact released block rather than an approximation built
    // from today's policy rules.
    #expect(pr21ReleasedPolicyBlockFixture == SVLTAgentCatalogPolicy.pr21ReleasedDocumentPolicyBlock)
    #expect(SVLTAgentCatalogPolicy.pr21ReleasedPolicyDigest == "e67fb9b5e9b62b3f72df86b6a3ec89ec1d40328c9d67fd7ad3e43f05c466e6f4")

    let preamble = "> [!note]- 用户前言\n> 保留说明 [[保留链接]]\n\n用户尾注"
    let document = qnapDocument()
    let canonical = try SensitiveCatalogDocumentCodec.encode(document, unmanagedMarkdown: preamble)
    let legacy = canonical.replacingOccurrences(
        of: SVLTAgentCatalogPolicy.documentPolicyBlock,
        with: pr21ReleasedPolicyBlockFixture
    )

    let strict = SensitiveCatalogDocumentCodec.validateDetailed(Data(legacy.utf8))
    #expect(strict.diagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
    #expect(throws: SecretCatalogValidationError.invalidPolicyBlock) {
        try SensitiveCatalogDocumentCodec.decode(legacy)
    }

    let plan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(legacy.utf8)))
    #expect(plan.canRepair)
    #expect(plan.repairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })
    #expect(!plan.unrepairableDiagnostics.contains { $0.code == "POLICY_BLOCK_INVALID" })

    let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(legacy.utf8))
    #expect(repaired == Data(canonical.utf8))
    #expect(CatalogSemanticDigest.rawSHA256(repaired) != CatalogSemanticDigest.rawSHA256(Data(legacy.utf8)))
    #expect(plan.semanticSHA256 == CatalogSemanticDigest.sha256(document))

    let repairedDocument = try SensitiveCatalogDocumentCodec.decode(repaired)
    #expect(repairedDocument == document)
    #expect(
        Set(repairedDocument.entries.flatMap { $0.fields.compactMap(\.secretRef) })
            == Set(document.entries.flatMap { $0.fields.compactMap(\.secretRef) })
    )
    let repairedText = String(decoding: repaired, as: UTF8.self)
    #expect(repairedText.contains(preamble))
    #expect(repairedText.contains("[[保留链接]]"))
    #expect(repairedText.contains("用户尾注"))
    #expect(repairedText.contains(SVLTAgentCatalogPolicy.documentPolicyBeginMarker))
}

@Test func detailedValidationReportsTheSecondDuplicateFieldMarkerLine() throws {
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: v2IndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: v2EntryID,
            indexId: v2IndexID,
            title: "QNAP 登录",
            fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
        )]
    )
    var text = try SensitiveCatalogDocumentCodec.encode(document)
    let duplicateField = """
    <!-- SVLT-FIELD {"key":"password","label":"密码","type":"secret","agentVisible":true,"searchable":true} -->
    - 密码：
    <!-- /SVLT-FIELD -->
    """
    text = text.replacingOccurrences(
        of: "<!-- /SVLT-ENTRY -->",
        with: duplicateField + "\n<!-- /SVLT-ENTRY -->"
    )

    let report = SensitiveCatalogDocumentCodec.validateDetailed(Data(text.utf8))
    let diagnostic = try #require(report.diagnostics.first)
    let lines = text.components(separatedBy: "\n")
    let fieldMarkerLines = lines.enumerated().filter {
        $0.element.trimmingCharacters(in: .whitespaces).hasPrefix("<!-- SVLT-FIELD ")
    }
    let secondDuplicateMarker = try #require(fieldMarkerLines.dropFirst().first)
    #expect(diagnostic.code == "FIELD_KEY_DUPLICATE")
    #expect(diagnostic.line == secondDuplicateMarker.offset + 1)
}

@Test func detailedValidationUsesTheExactFourthFieldBodySpan() throws {
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: v2IndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: v2EntryID,
            indexId: v2IndexID,
            title: "登录",
            fields: [
                SecretCatalogFieldValue(key: "one", label: "一", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "two", label: "二", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "three", label: "三", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "port", label: "端口", type: .number, value: .number(443))
            ]
        )]
    )
    var lines = try SensitiveCatalogDocumentCodec.encode(document).components(separatedBy: "\n")
    let markerLine = try #require(lines.firstIndex { $0.contains("\"key\":\"port\"") })
    let bodyLine = markerLine + 1
    lines[bodyLine] = "- 端口：not-a-number"

    let report = SensitiveCatalogDocumentCodec.validateDetailed(Data(lines.joined(separator: "\n").utf8))
    let diagnostic = try #require(report.diagnostics.first)
    #expect(diagnostic.code == "FIELD_VALUE_INVALID")
    #expect(diagnostic.line == bodyLine + 1)
    #expect(diagnostic.endLine == bodyLine + 1)
    #expect(diagnostic.column == 1)
}

@Test func detailedValidationUsesTheExactFourthSecretFieldBodySpan() throws {
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: v2IndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: v2EntryID,
            indexId: v2IndexID,
            title: "登录",
            fields: [
                SecretCatalogFieldValue(key: "one", label: "一", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "two", label: "二", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "three", label: "三", type: .text, value: .string("ok")),
                SecretCatalogFieldValue(key: "apiKey", label: "API 密钥", type: .secret)
            ]
        )]
    )
    var lines = try SensitiveCatalogDocumentCodec.encode(document).components(separatedBy: "\n")
    let markerLine = try #require(lines.firstIndex { $0.contains("\"key\":\"apiKey\"") })
    let bodyLine = markerLine + 1
    lines[bodyLine] = "- API 密钥：not-opaque-reference"

    let report = SensitiveCatalogDocumentCodec.validateDetailed(Data(lines.joined(separator: "\n").utf8))
    let diagnostic = try #require(report.diagnostics.first)
    #expect(diagnostic.code == "SECRET_FIELD_PLAINTEXT")
    #expect(diagnostic.line == bodyLine + 1)
    #expect(diagnostic.endLine == bodyLine + 1)
}

@Test func detailedValidationUsesTheExactThirdEntryHeadingSpan() throws {
    let entries = (0..<4).map { offset in
        SecretCatalogEntry(
            id: [v2EntryID, v2KomgaEntryID, v2PasswordReference.replacingOccurrences(of: "secret://", with: ""), v2TokenReference.replacingOccurrences(of: "secret://", with: "")][offset],
            indexId: v2IndexID,
            title: "条目 \(offset + 1)"
        )
    }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: v2IndexID, title: "QNAP")],
        entries: entries
    )
    var lines = try SensitiveCatalogDocumentCodec.encode(document).components(separatedBy: "\n")
    let entryMarkers = lines.enumerated().filter { $0.element.contains("<!-- SVLT-ENTRY ") }
    let thirdMarker = try #require(entryMarkers.dropFirst(2).first)
    let badHeadingLine = thirdMarker.offset + 1
    lines[badHeadingLine] = "## 错误层级"

    let report = SensitiveCatalogDocumentCodec.validateDetailed(Data(lines.joined(separator: "\n").utf8))
    let diagnostic = try #require(report.diagnostics.first)
    #expect(diagnostic.code == "HEADING_INVALID")
    #expect(diagnostic.line == badHeadingLine + 1)
    #expect(diagnostic.endLine == badHeadingLine + 1)
}

@Test func catalogV2IsInputOnlyAndDecodesToTheSameSemanticDocument() throws {
    let document = qnapDocument()
    let rendered = try SensitiveCatalogDocumentCodec.encodeV2(document)

    #expect(SensitiveCatalogDocumentCodec.format(rendered) == .managedV2)
    #expect(try SensitiveCatalogDocumentCodec.decode(rendered) == document)
    #expect(!rendered.contains("password-plaintext-canary"))
}

@Test func catalogV3KeepsHeadingsAndWikiLinksInsideEntryNotes() throws {
    let index = SecretCatalogIndex(id: v2IndexID, title: "QNAP")
    let entry = SecretCatalogEntry(
        id: v2EntryID,
        indexId: v2IndexID,
        title: "登录",
        notes: "部署说明\n\n## 外部标题\n[[QNAP]]\n\n### 子标题\n[[服务器配置]]"
    )
    let document = SecretCatalogDocument(indexes: [index], entries: [entry])
    let rendered = try SensitiveCatalogDocumentCodec.encode(document)

    #expect(try SensitiveCatalogDocumentCodec.decode(rendered) == document)
    #expect(rendered.contains("[[QNAP]]"))
    #expect(rendered.contains("[[服务器配置]]"))
    #expect(rendered.contains("## 外部标题"))
    #expect(rendered.contains("### 子标题"))
}

@Test func catalogV3MinimalPatchPreservesUnrelatedMarkdownAndWikiLinks() throws {
    let original = try SensitiveCatalogDocumentCodec.encode(qnapDocument())
    let decorated = original.replacingOccurrences(
        of: "<!-- SVLT-ENTRY {\"aliases\":[\"漫画服务器\",\"Komga\"]",
        with: "这是用户保留的 Markdown 说明，关联 [[QNAP]]。\n\n<!-- SVLT-ENTRY {\"aliases\":[\"漫画服务器\",\"Komga\"]"
    )
    let old = try SensitiveCatalogDocumentCodec.decode(decorated)
    var entries = old.entries
    entries[0] = entries[0].renaming(to: "QNAP 管理后台登录（更新）")
    let new = SecretCatalogDocument(indexes: old.indexes, entries: entries)

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: new
    )
    let patchedText = String(decoding: patched, as: UTF8.self)

    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == new)
    #expect(patchedText.contains("这是用户保留的 Markdown 说明"))
    #expect(patchedText.contains("[[QNAP]]"))
    #expect(patchedText.contains("QNAP 管理后台登录（更新）"))
}

@Test func catalogV3IndexInsertAddsLineBoundaryBeforeTrailingUserMarkdown() throws {
    let old = try SensitiveCatalogDocumentCodec.decode(try SensitiveCatalogDocumentCodec.encode(qnapDocument()))
    var decorated = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        SensitiveCatalogDocumentCodec.encode(qnapDocument()).data(using: .utf8)!,
        from: old,
        to: old
    ), as: UTF8.self)
    decorated = String(decorated.dropLast()) + "\n用户保留的尾注"
    let newIndex = SecretCatalogIndex(id: "0123456789ABCDEFGHJKMNPQRZ", title: "新增")
    let next = SecretCatalogDocument(indexes: old.indexes + [newIndex], entries: old.entries)
    let patched = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8), from: old, to: next
    ), as: UTF8.self)

    let separator = try #require(patched.range(of: "<!-- /SVLT-INDEX -->\n\n---\n\n<!-- SVLT-INDEX"))
    let trailingNote = try #require(patched.range(of: "用户保留的尾注"))
    let newHeading = try #require(patched.range(of: "## 新增"))
    #expect(separator.lowerBound < trailingNote.lowerBound)
    #expect(newHeading.lowerBound < trailingNote.lowerBound)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3FirstIndexIsAppendedAfterPreambleWithoutAnIndexSeparator() throws {
    let preamble = "> [!note]- 我的说明\n> 只属于用户的前言"
    let old = SecretCatalogDocument()
    let source = try SensitiveCatalogDocumentCodec.encode(old, unmanagedMarkdown: preamble)
    let index = SecretCatalogIndex(id: layoutIndexAID, title: "第一个分组")
    let next = SecretCatalogDocument(indexes: [index])

    let patched = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(source.utf8), from: old, to: next
    ), as: UTF8.self)

    let note = try #require(patched.range(of: "我的说明"))
    let heading = try #require(patched.range(of: "## 第一个分组"))
    #expect(note.lowerBound < heading.lowerBound)
    #expect(!patched.contains("\n---\n\n<!-- SVLT-INDEX"))
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3NewIndexesUseOneManagedHorizontalRuleAndPreserveTrailingMarkdown() throws {
    let first = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let second = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let third = SecretCatalogIndex(id: layoutIndexCID, title: "分组 C")
    let old = SecretCatalogDocument(indexes: [first, second])
    let preamble = "> [!note]- 顶部说明\n> 不属于 Catalog"
    var decorated = try SensitiveCatalogDocumentCodec.encode(old, unmanagedMarkdown: preamble)
    decorated = String(decorated.dropLast()) + "\n用户尾部 Markdown\n[[保留链接]]"
    let next = SecretCatalogDocument(indexes: [first, second, third])

    let patched = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8), from: old, to: next
    ), as: UTF8.self)
    let separator = try #require(patched.range(of: "<!-- /SVLT-INDEX -->\n\n---\n\n<!-- SVLT-INDEX"))
    let newHeading = try #require(patched.range(of: "## 分组 C"))
    let tail = try #require(patched.range(of: "用户尾部 Markdown\n[[保留链接]]"))

    #expect(separator.lowerBound < newHeading.lowerBound)
    #expect(newHeading.lowerBound < tail.lowerBound)
    #expect(patched.hasSuffix("用户尾部 Markdown\n[[保留链接]]"))
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3CanonicalRenderUsesDoubleBlankEntrySpacingAndRoundTrips() throws {
    let index = SecretCatalogIndex(id: layoutIndexAID, title: "分组")
    let first = layoutEntry(id: layoutEntryAID, indexID: index.id, title: "条目 A")
    let second = layoutEntry(id: layoutEntryBID, indexID: index.id, title: "条目 B")
    let document = SecretCatalogDocument(indexes: [index], entries: [first, second])
    let rendered = try SensitiveCatalogDocumentCodec.encode(document)

    #expect(rendered.contains("<!-- /SVLT-ENTRY -->\n\n\n<!-- SVLT-ENTRY"))
    #expect(try SensitiveCatalogDocumentCodec.decode(rendered) == document)
    #expect(try SensitiveCatalogDocumentCodec.decode(try SensitiveCatalogDocumentCodec.encode(document)) == document)
}

@Test func catalogV3FormatRepairNormalizesLegacyIndexAndEntrySpacingOnlyInManagedGaps() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let first = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let second = layoutEntry(id: layoutEntryBID, indexID: indexA.id, title: "条目 B")
    let canonical = try SensitiveCatalogDocumentCodec.encode(
        SecretCatalogDocument(indexes: [indexA, indexB], entries: [first, second])
    )
    let legacy = canonical
        .replacingOccurrences(of: "\n\n---\n\n", with: "\n\n")
        .replacingOccurrences(of: "\n\n\n<!-- SVLT-ENTRY", with: "\n<!-- SVLT-ENTRY")
    let plan = try #require(SensitiveCatalogDocumentCodec.formatRepairPlan(Data(legacy.utf8)))

    #expect(plan.canRepair)
    let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(legacy.utf8))
    #expect(repaired == Data(canonical.utf8))
}

@Test func catalogV3FormatRepairNeverMovesAnUnrecognizedUserNote() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let first = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let second = layoutEntry(id: layoutEntryBID, indexID: indexA.id, title: "条目 B")
    let document = SecretCatalogDocument(indexes: [indexA, indexB], entries: [first, second])
    let canonical = try SensitiveCatalogDocumentCodec.encode(document)
    let note = "> [!note]\n> 我的私人说明，不是 SVLT 官方 Note"
    let withUserNote = canonical.replacingOccurrences(
        of: "\n\n---\n\n",
        with: "\n\n\(note)\n\n",
        options: [],
        range: canonical.range(of: "\n\n---\n\n")
    ).replacingOccurrences(of: "<!-- /SVLT-ENTRY -->\n\n\n<!-- SVLT-ENTRY", with: "<!-- /SVLT-ENTRY -->\n<!-- SVLT-ENTRY")

    let repaired = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: Data(withUserNote.utf8))
    let repairedText = String(decoding: repaired, as: UTF8.self)
    #expect(repairedText.contains(note))
    let noteRange = try #require(repairedText.range(of: note))
    let firstIndexHeading = try #require(repairedText.range(of: "## 分组 A"))
    #expect(noteRange.lowerBound > firstIndexHeading.upperBound)
    #expect(try SensitiveCatalogDocumentCodec.decode(repaired) == document)
}

@Test func catalogV3MinimalPatchAppendsEntriesWithCanonicalSpacing() throws {
    let index = SecretCatalogIndex(id: layoutIndexAID, title: "分组")
    let first = layoutEntry(id: layoutEntryAID, indexID: index.id, title: "条目 A")
    let second = layoutEntry(id: layoutEntryBID, indexID: index.id, title: "条目 B")
    let old = SecretCatalogDocument(indexes: [index], entries: [first])
    let next = SecretCatalogDocument(indexes: [index], entries: [first, second])
    let patched = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8), from: old, to: next
    ), as: UTF8.self)

    #expect(patched.contains("<!-- /SVLT-ENTRY -->\n\n\n<!-- SVLT-ENTRY"))
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3MinimalPatchGroupsBatchEntriesIntoOneManagedRun() throws {
    let index = SecretCatalogIndex(id: layoutIndexAID, title: "分组")
    let first = layoutEntry(id: layoutEntryAID, indexID: index.id, title: "条目 A")
    let second = layoutEntry(id: layoutEntryBID, indexID: index.id, title: "条目 B")
    let third = layoutEntry(id: layoutIndexCID, indexID: index.id, title: "条目 C")
    let old = SecretCatalogDocument(indexes: [index], entries: [first])
    let next = SecretCatalogDocument(indexes: [index], entries: [first, second, third])
    let patched = String(decoding: try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8), from: old, to: next
    ), as: UTF8.self)

    #expect(patched.components(separatedBy: "<!-- SVLT-ENTRY ").count == 4)
    #expect(patched.components(separatedBy: "<!-- /SVLT-ENTRY -->\n\n\n<!-- SVLT-ENTRY").count == 3)
    #expect(patched.contains("### 条目 C"))
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3MovesEntryToTheFirstPositionOfAnotherIndex() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let entryA = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let entryB = layoutEntry(id: layoutEntryBID, indexID: indexB.id, title: "条目 B")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA, entryB])
    let moved = layoutEntry(entryA, in: indexB.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [moved, entryB])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.range(of: "### 条目 A")!.lowerBound < text.range(of: "### 条目 B")!.lowerBound)
    #expect(text.components(separatedBy: "<!-- SVLT-ENTRY ").count == 3)
}

@Test func catalogV3MovesEntryToTheLastPositionOfAnotherIndex() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let entryA = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let entryB = layoutEntry(id: layoutEntryBID, indexID: indexB.id, title: "条目 B")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA, entryB])
    let moved = layoutEntry(entryB, in: indexA.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA, moved])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.range(of: "### 条目 A")!.lowerBound < text.range(of: "### 条目 B")!.lowerBound)
}

@Test func catalogV3MovesEntryIntoAnEmptyIndex() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "空分组 B")
    let entryA = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA])
    let moved = layoutEntry(entryA, in: indexB.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [moved])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8),
        from: old,
        to: next
    )
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
}

@Test func catalogV3BatchMovesEntriesUsingOnlyDestinationAnchors() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let entryA1 = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A1")
    let entryA2 = layoutEntry(id: layoutEntryCID, indexID: indexA.id, title: "条目 A2")
    let entryB1 = layoutEntry(id: layoutEntryBID, indexID: indexB.id, title: "条目 B1")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA1, entryA2, entryB1])
    let movedA1 = layoutEntry(entryA1, in: indexB.id)
    let movedA2 = layoutEntry(entryA2, in: indexB.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [movedA1, movedA2, entryB1])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(try SensitiveCatalogDocumentCodec.encode(old).utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.range(of: "### 条目 A1")!.lowerBound < text.range(of: "### 条目 A2")!.lowerBound)
    #expect(text.range(of: "### 条目 A2")!.lowerBound < text.range(of: "### 条目 B1")!.lowerBound)
    #expect(text.components(separatedBy: "<!-- SVLT-ENTRY ").count == 4)
}

@Test func catalogV3MovePreservesUserMarkdownBetweenDestinationEntries() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let entryA = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let entryB1 = layoutEntry(id: layoutEntryBID, indexID: indexB.id, title: "条目 B1")
    let entryB2 = layoutEntry(id: layoutEntryCID, indexID: indexB.id, title: "条目 B2")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA, entryB1, entryB2])
    let canonical = try SensitiveCatalogDocumentCodec.encode(old)
    let firstClose = try #require(canonical.range(of: "<!-- /SVLT-ENTRY -->"))
    let secondClose = try #require(canonical.range(of: "<!-- /SVLT-ENTRY -->", range: firstClose.upperBound..<canonical.endIndex))
    let note = "\n用户备注\n[[WikiLink]]\n"
    var decorated = canonical
    decorated.insert(contentsOf: note, at: secondClose.upperBound)

    let moved = layoutEntry(entryA, in: indexB.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryB1, moved, entryB2])
    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.contains(note))
    #expect(text.range(of: "### 条目 B1")!.lowerBound < text.range(of: "### 条目 A")!.lowerBound)
    #expect(text.range(of: "### 条目 A")!.lowerBound < text.range(of: "### 条目 B2")!.lowerBound)
}

@Test func catalogV3MovePreservesUserNoteBeforeIndexCloseMarker() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let entryA = layoutEntry(id: layoutEntryAID, indexID: indexA.id, title: "条目 A")
    let old = SecretCatalogDocument(indexes: [indexA, indexB], entries: [entryA])
    let canonical = try SensitiveCatalogDocumentCodec.encode(old)
    let note = "用户 close 前注释\n[[CloseWiki]]\n"
    let decorated = canonical.replacingOccurrences(
        of: "<!-- /SVLT-INDEX -->",
        with: note + "<!-- /SVLT-INDEX -->",
        range: canonical.range(of: "<!-- /SVLT-INDEX -->")
    )
    let moved = layoutEntry(entryA, in: indexB.id)
    let next = SecretCatalogDocument(indexes: [indexA, indexB], entries: [moved])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.contains(note))
}

@Test func catalogV3DeletingIndexesRemovesOnlyCanonicalManagedBoundaries() throws {
    let indexes = [
        SecretCatalogIndex(id: layoutIndexAID, title: "分组 A"),
        SecretCatalogIndex(id: layoutIndexBID, title: "分组 B"),
        SecretCatalogIndex(id: layoutIndexCID, title: "分组 C"),
        SecretCatalogIndex(id: layoutIndexDID, title: "分组 D")
    ]
    let old = SecretCatalogDocument(indexes: indexes)
    let source = Data(try SensitiveCatalogDocumentCodec.encode(old).utf8)

    for removed in [Set([layoutIndexAID]), Set([layoutIndexDID]), Set([layoutIndexBID]), Set([layoutIndexBID, layoutIndexCID])] {
        let remaining = indexes.filter { !removed.contains($0.id) }
        let next = SecretCatalogDocument(indexes: remaining)
        let patched = try SensitiveCatalogDocumentCodec.minimalPatch(source, from: old, to: next)
        let text = String(decoding: patched, as: UTF8.self)
        #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
        #expect(text.components(separatedBy: "\n---\n\n").count == max(1, remaining.count))
        #expect(!text.hasPrefix("\n---\n\n"))
        if remaining.count > 1 {
            #expect(text.components(separatedBy: "\n---\n\n").count == remaining.count)
        }
    }
}

@Test func catalogV3DeletingLastIndexPreservesTrailingUserMarkdownWithoutOrphanBoundary() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let old = SecretCatalogDocument(indexes: [indexA, indexB])
    let canonical = try SensitiveCatalogDocumentCodec.encode(old)
    let tail = "\n用户尾注\n[[尾部链接]]"
    let decorated = canonical + tail
    let next = SecretCatalogDocument(indexes: [indexA])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.contains(tail))
    #expect(!text.contains("\n---\n\n用户尾注"))
}

@Test func catalogV3DeletingIndexPreservesUserHorizontalRuleWithUnmanagedText() throws {
    let indexA = SecretCatalogIndex(id: layoutIndexAID, title: "分组 A")
    let indexB = SecretCatalogIndex(id: layoutIndexBID, title: "分组 B")
    let old = SecretCatalogDocument(indexes: [indexA, indexB])
    let canonical = try SensitiveCatalogDocumentCodec.encode(old)
    let userGap = "\n\n---\n\n用户自己的分隔线说明\n\n"
    let decorated = canonical.replacingOccurrences(
        of: "\n---\n\n",
        with: userGap,
        range: canonical.range(of: "\n---\n\n")
    )
    let next = SecretCatalogDocument(indexes: [indexA])

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: next
    )
    let text = String(decoding: patched, as: UTF8.self)
    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == next)
    #expect(text.contains(userGap))
}

@Test func catalogV3MinimalPatchPreservesUnrelatedBytesWhenAnotherEntryChanges() throws {
    let original = try SensitiveCatalogDocumentCodec.encode(qnapDocument())
    let decorated = original.replacingOccurrences(
        of: "<!-- /SVLT-INDEX -->",
        with: "用户手写的段落\n\n[[敏感信息#QNAP]]\n\n<!-- /SVLT-INDEX -->"
    )
    let old = try SensitiveCatalogDocumentCodec.decode(decorated)
    let replacement = old.entries[1].renaming(to: "Komga 漫画服务器（更新）")
    let new = SecretCatalogDocument(
        indexes: old.indexes,
        entries: [old.entries[0], replacement]
    )

    let patched = try SensitiveCatalogDocumentCodec.minimalPatch(
        Data(decorated.utf8),
        from: old,
        to: new
    )
    let patchedText = String(decoding: patched, as: UTF8.self)

    #expect(try SensitiveCatalogDocumentCodec.decode(patched) == new)
    #expect(patchedText.contains("用户手写的段落\n\n[[敏感信息#QNAP]]"))
    #expect(patchedText.contains("QNAP 管理后台登录"))
    #expect(patchedText.contains("Komga 漫画服务器（更新）"))
}

@Test func catalogV2KeepsOpaqueIDsAcrossRenames() throws {
    let index = SecretCatalogIndex(id: v2IndexID, title: "QNAP")
    let entry = SecretCatalogEntry(id: v2EntryID, indexId: v2IndexID, title: "登录")

    #expect(index.renaming(to: "NAS").id == index.id)
    #expect(entry.renaming(to: "管理后台").id == entry.id)
    #expect(try SecretCatalogOpaqueID.validate(v2IndexID) == ())
}

@Test func catalogOpaqueIDsUseLaunchdSafeSystemRandomSource() throws {
    let first = try SecretCatalogOpaqueID.generate()
    let second = try SecretCatalogOpaqueID.generate()

    #expect(first.count == SecretCatalogOpaqueID.length)
    #expect(second.count == SecretCatalogOpaqueID.length)
    #expect(try SecretCatalogOpaqueID.validate(first) == ())
    #expect(try SecretCatalogOpaqueID.validate(second) == ())
    #expect(first != second)
}

@Test func catalogV2RejectsSchemaAndFieldConflicts() throws {
    let index = SecretCatalogIndex(id: v2IndexID, title: "QNAP")
    let both = SecretCatalogFieldValue(
        key: "username",
        label: "用户名",
        type: .text,
        value: .string("admin"),
        secretRef: v2PasswordReference
    )
    let entry = SecretCatalogEntry(id: v2EntryID, indexId: v2IndexID, title: "登录", fields: [both])

    #expect(throws: SecretCatalogValidationError.valueAndSecretReference) {
        try SecretCatalogDocument(indexes: [index], entries: [entry]).validate()
    }

    let plaintextSecret = SecretCatalogFieldValue(
        key: "password",
        label: "密码",
        type: .secret,
        value: .string("password-plaintext-canary")
    )
    let secretEntry = SecretCatalogEntry(id: v2EntryID, indexId: v2IndexID, title: "登录", fields: [plaintextSecret])
    #expect(throws: SecretCatalogValidationError.secretFieldContainsValue) {
        try SecretCatalogDocument(indexes: [index], entries: [secretEntry]).validate()
    }

    let malformed = """
    \(SensitiveCatalogDocumentCodec.v3Marker)
    # 敏感信息

    \(SVLTAgentCatalogPolicy.documentPolicyBlock)

    <!-- SVLT-INDEX {"id":"bad","unexpected":true} -->
    ## QNAP
    <!-- /SVLT-INDEX -->
    """
    #expect(throws: SecretCatalogValidationError.malformedJSON) {
        try SensitiveCatalogDocumentCodec.decode(malformed)
    }

    let unknownIndexJSON = Data("""
    {
      "aliases": [],
      "id": "\(v2IndexID)",
      "schema": "svlt.catalog.index/v2",
      "tags": [],
      "title": "QNAP",
      "unexpected": true
    }
    """.utf8)
    #expect(throws: SecretCatalogValidationError.unknownSchema) {
        try JSONDecoder().decode(SecretCatalogIndex.self, from: unknownIndexJSON)
    }
}

@Test func catalogV3RejectsSecretReferencesOutsideSecretFieldReferenceSlot() throws {
    let reference = v2PasswordReference
    let indexID = v2IndexID
    let entryID = v2EntryID

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: reference)]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组", aliases: [reference])]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
            entries: [SecretCatalogEntry(id: entryID, indexId: indexID, title: "条目", tags: [reference])]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
            entries: [SecretCatalogEntry(id: entryID, indexId: indexID, title: "条目", notes: "备注：\(reference)")]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
            entries: [SecretCatalogEntry(
                id: entryID,
                indexId: indexID,
                title: "条目",
                endpoints: [CatalogEndpoint(type: "https", host: reference)]
            )]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
            entries: [SecretCatalogEntry(
                id: entryID,
                indexId: indexID,
                title: "条目",
                fields: [SecretCatalogFieldValue(
                    key: "备注",
                    label: "备注",
                    type: .text,
                    value: .string("普通字段：\(reference)")
                )]
            )]
        ).validate()
    }

    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
            entries: [SecretCatalogEntry(
                id: entryID,
                indexId: indexID,
                title: "条目",
                fields: [SecretCatalogFieldValue(
                    key: "标签",
                    label: "标签",
                    type: .list,
                    value: .list(["普通项", reference])
                )]
            )]
        ).validate()
    }

    let valid = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: indexID, title: "分组")],
        entries: [SecretCatalogEntry(
            id: entryID,
            indexId: indexID,
            title: "条目",
            fields: [SecretCatalogFieldValue(key: "密码", label: "密码", type: .secret, secretRef: reference)]
        )]
    )
    try valid.validate()
}

@Test func catalogV3RejectsSecretReferencesAndManagedMarkersInDocumentMarkdown() throws {
    let rendered = try SensitiveCatalogDocumentCodec.encode(qnapDocument())
    let firstIndexMarker = "<!-- SVLT-INDEX "

    let ordinaryMarkdown = rendered.replacingOccurrences(
        of: firstIndexMarker,
        with: "> 目录说明：[[QNAP]]\n\n\(firstIndexMarker)",
        options: [],
        range: rendered.range(of: firstIndexMarker)
    )
    #expect(try SensitiveCatalogDocumentCodec.decode(ordinaryMarkdown) == qnapDocument())

    let injectedReference = rendered.replacingOccurrences(
        of: firstIndexMarker,
        with: "> 目录说明：secret://0123456789ABCDEFGHJKMNPQRS\n\n\(firstIndexMarker)",
        options: [],
        range: rendered.range(of: firstIndexMarker)
    )
    #expect(throws: SecretCatalogValidationError.secretReferenceInMetadata) {
        try SensitiveCatalogDocumentCodec.decode(injectedReference)
    }

    let injectedMarker = rendered.replacingOccurrences(
        of: firstIndexMarker,
        with: "<!-- SVLT-FAKE-MARKER -->\n\n\(firstIndexMarker)",
        options: [],
        range: rendered.range(of: firstIndexMarker)
    )
    #expect(throws: SecretCatalogValidationError.unmanagedContent) {
        try SensitiveCatalogDocumentCodec.decode(injectedMarker)
    }
}
