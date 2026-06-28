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

@Test func revealSessionStoreExpiresSessionsAfterTTL() async throws {
    let store = RevealSessionStore(defaultTTLSeconds: 0.01)
    let id = await store.create(resolvedParagraph: "Token: ASV_CANARY_REVEAL_TTL")
    #expect(await store.paragraph(id: id) == "Token: ASV_CANARY_REVEAL_TTL")
    try await Task.sleep(nanoseconds: 50_000_000)
    #expect(await store.paragraph(id: id) == nil)
}

@Test func revealSessionStoreInvokesClearHandlerAfterTTL() async throws {
    let store = RevealSessionStore(defaultTTLSeconds: 0.01)
    let flag = ClearFlag()
    let id = await store.create(resolvedParagraph: "Token: ASV_CANARY_REVEAL_TTL")

    await store.setClearHandler(id: id) {
        await flag.markCleared()
    }

    try await Task.sleep(nanoseconds: 50_000_000)

    #expect(await flag.wasCleared)
}

@Test func revealSessionStoreClearAllRemovesAllSessions() async {
    let store = RevealSessionStore()
    let firstID = await store.create(resolvedParagraph: "first")
    let secondID = await store.create(resolvedParagraph: "second")

    await store.clearAll()

    #expect(await store.paragraph(id: firstID) == nil)
    #expect(await store.paragraph(id: secondID) == nil)
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
    let presenter = SpyRevealSessionPresenter()
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: sessionStore,
        revealSessionPresenter: presenter
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
    #expect(await presenter.presentedSessionIDs == [sessionID])
    #expect(await presenter.presentedParagraphs == ["Token: ASV_CANARY_REVEAL_SERVICE"])
}

@Test func vaultAppServicesRejectsDuplicatePlaceholderContextBeforeResolverAvailability() async {
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: nil,
        masterKey: nil,
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter()
    )

    await expectRevealError(.invalidRevealContext) {
        _ = try await services.openRevealSession(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "Reveal current paragraph",
                template: "Token: {{0}} and literal {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            )
        )
    }
}

private struct UnusedTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        throw UnusedTextEncryptorError.unexpectedCall
    }
}

private enum UnusedTextEncryptorError: Error {
    case unexpectedCall
}

private actor ClearFlag {
    private(set) var wasCleared = false

    func markCleared() {
        wasCleared = true
    }
}

private actor SpyRevealSessionPresenter: RevealSessionPresenting {
    private(set) var presentedSessionIDs: [String] = []
    private(set) var presentedParagraphs: [String] = []

    func present(sessionID: String, store: RevealSessionStore) async {
        presentedSessionIDs.append(sessionID)
        if let paragraph = await store.paragraph(id: sessionID) {
            presentedParagraphs.append(paragraph)
        }
    }
}

private func expectRevealError(
    _ expectedError: VaultAppServicesRevealError,
    operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expectedError), but operation succeeded.")
    } catch let error as VaultAppServicesRevealError {
        #expect(error == expectedError)
    } catch {
        Issue.record("Expected \(expectedError), but received \(error).")
    }
}
