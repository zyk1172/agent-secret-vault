import Foundation
import Testing
@testable import VaultCore

private let v2IndexID = "0123456789ABCDEFGHJKMNPQRS"
private let v2EntryID = "0123456789ABCDEFGHJKMNPQRT"
private let v2KomgaEntryID = "0123456789ABCDEFGHJKMNPQRV"
private let v2PasswordReference = "secret://0123456789ABCDEFGHJKMNPQRW"
private let v2TokenReference = "secret://0123456789ABCDEFGHJKMNPQRY"

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
        of: SVLTAgentCatalogPolicy.documentPolicyBlock + "\n\n",
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
