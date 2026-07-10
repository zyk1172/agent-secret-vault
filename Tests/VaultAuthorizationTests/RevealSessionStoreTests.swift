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

@Test func vaultAppServicesReusesAuthorizationForMultipleReferencesInOneRevealOperation() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x36, count: 32))
    let first = try cipher.encrypt(
        Data("ASV_CANARY_FIRST".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    let second = try cipher.encrypt(
        Data("ASV_CANARY_SECOND".utf8),
        id: "ABCDEFGHJKMNPQRSTVWXYZ0123",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(first)
    try await recordStore.save(second)

    let provider = CountingMasterKeyProvider(key: key)
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKeyProvider: { policy, reason in
            await provider.masterKey(policy: policy, reason: reason)
        },
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter()
    )

    let restored = try await services.restoreReferences(
        references: [
            "secret://0123456789ABCDEFGHJKMNPQRS",
            "secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
        ],
        context: RevealContext(
            reason: "Reveal NAS credentials once",
            template: "first={{0}}\nsecond={{1}}",
            ranges: [
                ReferenceRange(index: 0, placeholder: "{{0}}"),
                ReferenceRange(index: 1, placeholder: "{{1}}")
            ]
        )
    )

    #expect(restored == "first=ASV_CANARY_FIRST\nsecond=ASV_CANARY_SECOND")
    #expect(await provider.calls == [
        MasterKeyProviderCall(policy: .credential, reason: "Reveal NAS credentials once")
    ])
}

@Test func vaultAppServicesReusesAgentDecryptAuthorizationForFiveMinutes() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x37, count: 32))
    let first = try cipher.encrypt(
        Data("ASV_CANARY_FIRST_AGENT_DECRYPT".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    let second = try cipher.encrypt(
        Data("ASV_CANARY_SECOND_AGENT_DECRYPT".utf8),
        id: "ABCDEFGHJKMNPQRSTVWXYZ0123",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(first)
    try await recordStore.save(second)

    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let provider = CountingMasterKeyProvider(key: key)
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKeyProvider: { policy, reason in
            await provider.masterKey(policy: policy, reason: reason)
        },
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter(),
        agentDecryptAuthorizationTTL: 300,
        now: { clock.now }
    )

    let firstRestored = try await services.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Agent decrypt first credential",
            template: "first={{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )
    clock.now = Date(timeIntervalSinceReferenceDate: 1_299.999)
    let secondRestored = try await services.restoreReferences(
        references: ["secret://ABCDEFGHJKMNPQRSTVWXYZ0123"],
        context: RevealContext(
            reason: "Agent decrypt second credential",
            template: "second={{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    #expect(firstRestored == "first=ASV_CANARY_FIRST_AGENT_DECRYPT")
    #expect(secondRestored == "second=ASV_CANARY_SECOND_AGENT_DECRYPT")
    #expect(await provider.calls == [
        MasterKeyProviderCall(policy: .credential, reason: "Agent decrypt first credential")
    ])
}

@Test func vaultAppServicesRenewsAgentDecryptAuthorizationAfterFiveMinutes() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: directory)
    }

    let recordStore = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x38, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_AGENT_DECRYPT_RENEW".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await recordStore.save(record)

    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 2_000))
    let provider = CountingMasterKeyProvider(key: key)
    let services = VaultAppServices(
        textEncryptor: UnusedTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore, cipher: cipher),
        masterKeyProvider: { policy, reason in
            await provider.masterKey(policy: policy, reason: reason)
        },
        revealSessionStore: RevealSessionStore(),
        revealSessionPresenter: SpyRevealSessionPresenter(),
        agentDecryptAuthorizationTTL: 300,
        now: { clock.now }
    )

    _ = try await services.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Agent decrypt before expiry",
            template: "{{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )
    clock.now = Date(timeIntervalSinceReferenceDate: 2_300)
    _ = try await services.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Agent decrypt after expiry",
            template: "{{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )

    #expect(await provider.calls == [
        MasterKeyProviderCall(policy: .credential, reason: "Agent decrypt before expiry"),
        MasterKeyProviderCall(policy: .credential, reason: "Agent decrypt after expiry")
    ])
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

private struct MasterKeyProviderCall: Equatable, Sendable {
    let policy: SecretPolicy
    let reason: String
}

private actor CountingMasterKeyProvider {
    private let key: SymmetricKey
    private(set) var calls: [MasterKeyProviderCall] = []

    init(key: SymmetricKey) {
        self.key = key
    }

    func masterKey(policy: SecretPolicy, reason: String) -> SymmetricKey {
        calls.append(MasterKeyProviderCall(policy: policy, reason: reason))
        return key
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date

    init(_ now: Date) {
        self.storedNow = now
    }

    var now: Date {
        get {
            lock.withLock {
                storedNow
            }
        }
        set {
            lock.withLock {
                storedNow = newValue
            }
        }
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
