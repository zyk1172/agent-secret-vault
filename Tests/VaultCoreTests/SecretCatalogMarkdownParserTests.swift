import Foundation
import Testing
@testable import VaultCore

private let catalogUsernameReference = "secret://0123456789ABCDEFGHJKMNPQRS"
private let catalogPasswordReference = "secret://0123456789ABCDEFGHJKMNPQRT"
private let catalogTokenReference = "secret://0123456789ABCDEFGHJKMNPQRV"

@Test func markdownParserAssociatesQNAPContextWithoutRetainingFieldValues() throws {
    let canary = "ASV_CANARY_CATALOG_PLAINTEXT_DO_NOT_PERSIST"
    let markdown = """
    # 敏感信息

    ## 设备凭据

    ### QNAP
    设备: NAS
    服务: QNAP
    地址: 192.168.2.240
    用途: 媒体管理与备份
    账号: \(catalogUsernameReference) （\(canary)）
    密码: \(catalogPasswordReference) （\(canary)）

    ### Cloud API
    地址: https://api.example.local
    用途: 自动同步
    Token: \(catalogTokenReference)
    """

    let entries = SecretCatalogMarkdownParser.parse(markdown)
    let username = try #require(entries.first(where: { $0.reference == catalogUsernameReference }))
    let password = try #require(entries.first(where: { $0.reference == catalogPasswordReference }))
    let token = try #require(entries.first(where: { $0.reference == catalogTokenReference }))

    #expect(username.service == "QNAP")
    #expect(username.field == .username)
    #expect(username.destinations == ["192.168.2.240"])
    #expect(username.purpose == "媒体管理与备份")
    #expect(password.field == .password)
    #expect(username.groupID != nil)
    #expect(username.groupID == password.groupID)
    #expect(username.groupID != token.groupID)
    #expect(username.contextTerms.contains("NAS"))

    let encoded = String(decoding: try JSONEncoder().encode(entries), as: UTF8.self)
    #expect(!encoded.contains(canary))
    #expect(entries.map(\.reference).contains(catalogUsernameReference))
}

@Test func markdownParserAcceptsChineseAndEnglishFieldNamesAndDeduplicatesReferences() {
    let markdown = """
    ### QNAP
    service: QNAP
    host: qnap.local
    username: \(catalogUsernameReference)
    password: \(catalogPasswordReference)
    password: \(catalogPasswordReference)
    """

    let entries = SecretCatalogMarkdownParser.parse(markdown)

    #expect(entries.map(\.reference) == [catalogUsernameReference, catalogPasswordReference])
    #expect(entries[0].field == .username)
    #expect(entries[1].field == .password)
    #expect(entries.allSatisfy { $0.destinations == ["qnap.local"] })
}

@Test func selectionManifestContainsOnlyTheSelectedDocumentPath() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-catalog-selection-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let document = root.appendingPathComponent("敏感信息.md")
    let manifest = root.appendingPathComponent("selection.json")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try "# QNAP\n密码: \(catalogPasswordReference)\n".write(to: document, atomically: true, encoding: .utf8)

    let store = SecretCatalogSelectionStore(manifestURL: manifest)
    try store.save(documentURL: document)

    #expect(try store.selectedDocumentURL() == document.standardizedFileURL)
    let manifestText = try String(contentsOf: manifest, encoding: .utf8)
    let decodedManifest = try JSONDecoder().decode(SecretCatalogSelectionStore.Manifest.self, from: Data(manifestText.utf8))
    #expect(decodedManifest.documentPath == document.standardizedFileURL.path)
    #expect(!manifestText.contains(catalogPasswordReference))
}
