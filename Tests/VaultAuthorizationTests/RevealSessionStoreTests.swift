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

@Test func vaultAppServicesRestoreReturnsResolvedParagraphForExplicitWriteBack() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x32, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_RESTORE_SERVICE".utf8),
        id: "ABCDEFGHJKMNPQRSTVWXYZ0123",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let presenter = SpyRevealSessionPresenter()
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: presenter
    )

    let restored = try await services.restoreReferences(
        references: ["secret://ABCDEFGHJKMNPQRSTVWXYZ0123"],
        context: RevealContext(
            reason: "Restore current paragraph",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    #expect(restored == "Token: ASV_CANARY_RESTORE_SERVICE")
    #expect(await presenter.presentedSessionIDs == [])
}

@Test func vaultAppServicesAuditRecordsDoNotContainResolvedPlaintext() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x34, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_AUDIT_SECRET".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let auditCollector = AuditCollector()
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter(),
        auditObserver: { entry in
            await auditCollector.append(entry)
        }
    )

    let restored = try await services.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Use SSH password for local device",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    #expect(restored == "Token: ASV_CANARY_AUDIT_SECRET")
    let entries = await auditCollector.entries
    #expect(entries.count == 1)
    let auditText = entries.map { "\($0.action) \($0.target) \($0.result)" }.joined(separator: "\n")
    #expect(!auditText.contains("ASV_CANARY_AUDIT_SECRET"))
    #expect(auditText.contains("本机脱密使用"))
}

@Test func vaultAppServicesPersistsEncryptedAgentAutomationAudit() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    let auditDirectory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: auditDirectory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.removeItem(at: auditDirectory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let auditLog = EncryptedAuditLog(directoryURL: auditDirectory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x35, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_PERSISTED_AUDIT_SECRET".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter(),
        auditLog: auditLog
    )

    _ = try await services.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Use SSH password for local device",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    let events = try await auditLog.export(masterKey: key)
    #expect(events.count == 1)
    #expect(events[0].integration == "agent-secret-vault-mcp")
    #expect(events[0].operation == .reveal)
    #expect(events[0].declaredTarget == "Use SSH password for local device")
    let persisted = try allFileBytes(under: auditDirectory)
    #expect(!persisted.contains(Data("ASV_CANARY_PERSISTED_AUDIT_SECRET".utf8)))
    #expect(!persisted.contains(Data("Use SSH password for local device".utf8)))
}

@Test func vaultAppServicesExportsResolvedTextToAllowedLocalFileWithoutRevealSession() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    let exportDirectory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: exportDirectory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.removeItem(at: exportDirectory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x33, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_EXPORT_SERVICE".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let presenter = SpyRevealSessionPresenter()
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKey: key,
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: presenter,
        exportDirectory: exportDirectory
    )
    let destination = exportDirectory.appendingPathComponent("nas.md")

    let exportedPath = try await services.exportResolvedText(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Export resolved local file",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        ),
        destinationPath: destination.path
    )

    #expect(exportedPath == destination.path)
    #expect(try String(contentsOf: destination, encoding: .utf8) == "Token: ASV_CANARY_EXPORT_SERVICE")
    #expect(await presenter.presentedSessionIDs == [])
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

private actor AuditCollector {
    private(set) var entries: [AgentAutomationAuditEntry] = []

    func append(_ entry: AgentAutomationAuditEntry) {
        entries.append(entry)
    }
}

private func allFileBytes(under directory: URL) throws -> Data {
    let urls = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil
    )
    return try urls.reduce(into: Data()) { partial, url in
        partial.append(try Data(contentsOf: url))
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
