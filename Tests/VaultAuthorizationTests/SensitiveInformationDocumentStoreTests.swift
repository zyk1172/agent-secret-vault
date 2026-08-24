import Foundation
import Testing
import VaultCore
@testable import AgentSecretVaultApp

@Test func sensitiveInformationDocumentNormalizesLegacyReferencePresentationAndListsReferences() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let file = directory.appendingPathComponent("敏感信息.md")
    let first = "secret://0123456789ABCDEFGHJKMNPQRS"
    let second = "secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
    try "服务: NewAPI\nAPI: [旧标题](\(first))\n\n密码: `\(second)`\n".write(to: file, atomically: true, encoding: .utf8)
    let store = SensitiveInformationDocumentStore(documentURL: file)

    #expect(try await store.prepareSelectedDocument())
    let updated = try String(contentsOf: file, encoding: .utf8)
    let references = try await store.references()

    #expect(updated.hasPrefix("<!-- agent-secret-vault-sensitive-information: 1 -->"))
    #expect(updated.contains("API: \(first)"))
    #expect(updated.contains("密码: \(second)"))
    #expect(updated.contains("[旧标题](\(first))") == false)
    #expect(updated.contains("`\(second)`") == false)
    #expect(references.map(\.reference) == [first, second])
}

@Test func sensitiveInformationDocumentExposesCatalogContextWithoutSourceFieldsToAgentCatalog() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    let username = "secret://0123456789ABCDEFGHJKMNPQRS"
    let password = "secret://0123456789ABCDEFGHJKMNPQRT"
    let canary = "ASV_CANARY_DOCUMENT_FIELD_VALUE"
    let file = directory.appendingPathComponent("敏感信息.md")
    try """
    ### QNAP
    服务: QNAP
    设备: NAS
    地址: 192.168.2.240
    用途: 媒体管理
    账号: \(username) (\(canary))
    密码: \(password) (\(canary))
    """.write(to: file, atomically: true, encoding: .utf8)

    let store = SensitiveInformationDocumentStore(documentURL: file)
    let references = try await store.references()
    let entries = try await store.catalogEntries()

    #expect(references.map(\.reference) == [username, password])
    #expect(references.map(\.service) == ["QNAP", "QNAP"])
    #expect(references.map(\.destinations) == [["192.168.2.240"], ["192.168.2.240"]])
    #expect(references.map(\.purpose) == ["媒体管理", "媒体管理"])
    #expect(references[0].groupID == references[1].groupID)
    #expect(entries.map(\.field) == [.username, .password])
    let encoded = String(decoding: try JSONEncoder().encode(entries), as: UTF8.self)
    #expect(!encoded.contains(canary))
    #expect(!encoded.contains(file.path))
    #expect(!encoded.contains("line"))
}

@Test func legacySensitiveInformationStoreRefusesCatalogV2Parsing() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("敏感信息.md")
    try "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->\n# 敏感信息\n".write(to: file, atomically: true, encoding: .utf8)

    let store = SensitiveInformationDocumentStore(documentURL: file)
    do {
        _ = try await store.references()
        Issue.record("legacy store unexpectedly parsed a managed catalog")
    } catch let error as SensitiveInformationDocumentStoreError {
        #expect(error == .managedCatalogRequiresCatalogStore)
    }
}
