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

@Test func legacySensitiveInformationStoreCannotWriteManagedCatalogV2() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("敏感信息.md")
    let original = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->\n# 敏感信息\n"
    let reference = "secret://0123456789ABCDEFGHJKMNPQRS"
    try original.write(to: file, atomically: true, encoding: .utf8)

    let store = SensitiveInformationDocumentStore(documentURL: file)
    await #expect(throws: SensitiveInformationDocumentStoreError.managedCatalogRequiresCatalogStore) {
        _ = try await store.prepareSelectedDocument()
    }
    await #expect(throws: SensitiveInformationDocumentStoreError.managedCatalogRequiresCatalogStore) {
        try await store.appendParagraph("密码: \(reference)", title: "QNAP", reference: reference)
    }
    #expect(try String(contentsOf: file, encoding: .utf8) == original)
}
