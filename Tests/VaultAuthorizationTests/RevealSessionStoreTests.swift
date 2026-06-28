import CryptoKit
import Foundation
import Testing
import VaultCore
import VaultIPC
@testable import AgentSecretVaultApp

@Test func revealSessionStoreStoresResolvedParagraphAndClearsIt() async {
    let store = RevealSessionStore()
    let id = await store.create(resolvedParagraph: "Token: ASV_CANARY_REVEAL")
    #expect(await store.paragraph(id: id) == "Token: ASV_CANARY_REVEAL")
    await store.clear(id: id)
    #expect(await store.paragraph(id: id) == nil)
}

@Test func vaultAppServicesRevealStoresResolvedParagraphAndReturnsOnlySessionID() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x31, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_REVEAL_SERVICE".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let sessionStore = RevealSessionStore()
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: sessionStore
    )

    let sessionID = try await services.openRevealSession(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Reveal current paragraph",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    #expect(sessionID.hasPrefix("session-"))
    #expect(!sessionID.contains("ASV_CANARY_REVEAL_SERVICE"))
    #expect(await sessionStore.paragraph(id: sessionID) == "Token: ASV_CANARY_REVEAL_SERVICE")
}

private struct UnusedTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        throw UnusedTextEncryptorError.unexpectedCall
    }
}

private enum UnusedTextEncryptorError: Error {
    case unexpectedCall
}
