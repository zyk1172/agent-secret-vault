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

@Test func catalogV2RoundTripsAndCanonicalizesWithoutPlaintext() throws {
    let document = qnapDocument()
    let rendered = try SensitiveCatalogDocumentCodec.encode(document)
    let decoded = try SensitiveCatalogDocumentCodec.decode(rendered)

    #expect(decoded == document)
    #expect(rendered.hasPrefix(SensitiveCatalogDocumentCodec.marker + "\n"))
    #expect(rendered.contains("indexId"))
    #expect(rendered.contains(v2IndexID))
    #expect(rendered.contains("\n  \""))
    #expect(!rendered.contains("\r"))
    #expect(!rendered.contains("password-plaintext-canary"))
    #expect(try SensitiveCatalogDocumentCodec.canonicalData(document) == Data(rendered.utf8))
}

@Test func catalogV2KeepsOpaqueIDsAcrossRenames() throws {
    let index = SecretCatalogIndex(id: v2IndexID, title: "QNAP")
    let entry = SecretCatalogEntry(id: v2EntryID, indexId: v2IndexID, title: "登录")

    #expect(index.renaming(to: "NAS").id == index.id)
    #expect(entry.renaming(to: "管理后台").id == entry.id)
    #expect(try SecretCatalogOpaqueID.validate(v2IndexID) == ())
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
    \(SensitiveCatalogDocumentCodec.marker)
    # 敏感信息

    ## QNAP

    ```json
    {"schema":"svlt.catalog.index/v2","id":"bad"}
    ```
    """
    #expect(throws: SecretCatalogValidationError.malformedJSON) {
        try SensitiveCatalogDocumentCodec.decode(malformed)
    }
}

@Test func legacyMigrationPreservesReferencesAndRetainsSafeUsernameMetadata() throws {
    let markdown = """
    # 敏感信息

    ## QNAP
    ### QNAP 管理后台登录
    地址: 192.168.2.240
    用户名: admin
    密码: \(v2PasswordReference)

    ### Komga 漫画服务器登录
    URL: http://192.168.2.240:25600
    username: zyk
    password: \(v2TokenReference)
    """

    let preview = try LegacySensitiveCatalogMigrator.preview(markdown)
    #expect(preview.referenceSetPreserved)
    #expect(preview.referencesBefore == [v2PasswordReference, v2TokenReference].sorted())
    #expect(preview.referencesAfter == preview.referencesBefore)
    #expect(preview.ambiguousReferences.isEmpty)

    let entries = preview.document.entries
    #expect(entries.count == 2)
    #expect(entries.first?.fields.contains {
        $0.key == "username" && $0.value == .string("admin")
    } == true)
    #expect(entries.last?.fields.contains {
        $0.key == "username" && $0.value == .string("zyk")
    } == true)
    #expect(!String(decoding: try LegacySensitiveCatalogMigrator.canonicalData(for: preview), as: UTF8.self)
        .contains("password-plaintext-canary"))
}

@Test func legacyMigrationMarksUnlabelledReferencesAmbiguousWithoutGuessing() throws {
    let markdown = """
    # 敏感信息

    ## QNAP NAS
    \(v2PasswordReference)
    \(v2TokenReference)
    """

    let preview = try LegacySensitiveCatalogMigrator.preview(markdown)
    #expect(preview.referenceSetPreserved)
    #expect(preview.ambiguousReferences.map(\.reference).sorted() == [v2PasswordReference, v2TokenReference].sorted())
    #expect(preview.requiresUserResolution)
    #expect(preview.document.entries.flatMap(\.fields).allSatisfy { $0.type == .secret })
}

@Test func legacyMigrationDoesNotCarryPlaintextSecretIntoPreview() throws {
    let canary = "ASV_CANARY_LEGACY_SECRET_DO_NOT_PERSIST"
    let markdown = """
    ## QNAP
    password: \(canary)
    username: admin
    """

    let preview = try LegacySensitiveCatalogMigrator.preview(markdown)
    #expect(preview.plaintextSensitiveFields.count == 1)
    let encoded = String(decoding: try LegacySensitiveCatalogMigrator.canonicalData(for: preview), as: UTF8.self)
    #expect(!encoded.contains(canary))
    #expect(preview.document.entries.flatMap(\.fields).contains { $0.key == "username" && $0.value == .string("admin") })
}
