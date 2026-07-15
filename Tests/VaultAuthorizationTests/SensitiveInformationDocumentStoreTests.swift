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
