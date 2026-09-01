import Foundation
import CryptoKit
import LocalAuthentication
import Testing
@testable import VaultAuthorization
import VaultCore
import VaultIPC
import VaultService

private let serviceIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let serviceEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let servicePasswordRef = "secret://0123456789ABCDEFGHJKMNPQRS"
private let servicePrivateKeyRef = "secret://0123456789ABCDEFGHJKMNPQRV"
private let serviceFailedReplacementRef = "secret://0123456789ABCDEFGHJKMNPQRW"

private struct CatalogTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference(servicePasswordRef)
    }
}

@Test func catalogRevealUsesOneApprovalContextAndReturnsOnlyTheLocalPlaintext() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }

    let snapshot = try await fixture.store.snapshot()
    let entry = try #require(snapshot.document.entries.first)
    let boundEntry = SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: [
            entry.fields[0],
            SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                secretRef: servicePasswordRef
            )
        ],
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )
    _ = try await fixture.store.updateEntry(boundEntry, expectedRevision: snapshot.revision)

    let recordStore = FileRecordStore(baseDirectory: fixture.root)
    let reference = try SecretReference(servicePasswordRef)
    let masterKey = SymmetricKey(data: Data(repeating: 0x44, count: 32))
    let canary = "svlt-catalog-reveal-canary"
    let record = try VaultCipher().encrypt(
        Data(canary.utf8),
        id: reference.id,
        version: 1,
        label: "QNAP credential",
        policy: .credential,
        masterKey: masterKey
    )
    try await recordStore.save(record)

    let authenticationContext = LocalAuthenticationContext(rawContext: LAContext())
    let approver = CatalogContextApprovalRecorder(context: authenticationContext)
    let keyProvider = CatalogContextKeyProvider(key: masterKey)
    let auditRecorder = CatalogAuditRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        freshMasterKeyProviderWithAuthenticationContext: { _, _, context in
            await keyProvider.resolve(authenticationContext: context)
        },
        operationApprover: approver,
        auditObserver: { entry in
            await auditRecorder.append(entry)
        }
    )

    let plaintext = try await service.catalogRevealField(
        entryID: serviceEntryID,
        key: "password"
    )
    #expect(plaintext == canary)
    #expect(await approver.count == 1)

    let receivedContexts = await keyProvider.recordedContexts()
    #expect(receivedContexts.count == 1)
    let receivedContext = try #require(receivedContexts.first ?? nil)
    #expect(receivedContext === authenticationContext)

    let catalogMarkdown = try String(contentsOf: fixture.documentURL, encoding: .utf8)
    #expect(!catalogMarkdown.contains(canary))
    let auditEntries = await auditRecorder.recordedEntries()
    #expect(!String(describing: auditEntries).contains(canary))
}

@Test func agentWriteAccessRequestRequiresExplicitUserApproval() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await service.createCatalogEntry(CatalogDraftRequest(
            indexID: serviceIndexID,
            title: "Komga"
        ))
    }
    let request = try await awaitAgentWriteRequest(captured)

    let pending = try await service.pendingCatalogWriteAccessRequest(id: request.id)
    #expect(pending.intent?.operation == .createEntry)
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: true)
    let result = try await task.value
    #expect(result.entry?.title == "Komga")
    #expect(result.entryID != nil)
    #expect(result.validation?.status == .found)
    #expect(result.validation?.revision == result.revision)
    #expect(await approver.count == 1)
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
}

@Test func agentCanCreateCatalogStructureWithGeneratedIDsAndOneApproval() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await service.createCatalogStructure(CatalogCreateStructureRequest(
            index: CatalogStructureIndexRequest(title: "数据库"),
            entries: [
                CatalogStructureEntryRequest(
                    clientKey: "postgres",
                    title: "PostgreSQL",
                    endpoints: [CatalogEndpoint(type: "postgresql", host: "db.home", port: 5432)],
                    fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
                ),
                CatalogStructureEntryRequest(
                    clientKey: "redis",
                    title: "Redis",
                    endpoints: [CatalogEndpoint(type: "redis", host: "cache.home", port: 6379)]
                )
            ]
        ))
    }
    let request = try await awaitAgentWriteRequest(captured)

    #expect(request.intent?.operation == .createStructure)
    #expect(request.intent?.indexID?.count == 26)
    #expect(request.intent?.entryID == nil)
    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: true)
    let result = try await task.value

    #expect(result.indexID.count == 26)
    #expect(result.entries.map(\.clientKey) == ["postgres", "redis"])
    #expect(result.entries.allSatisfy { $0.entryID.count == 26 })
    #expect(result.revision == 2)
    #expect(result.validation.status == .found)
    #expect(result.validation.revision == result.revision)
    #expect(await approver.count == 1)

    let snapshot = try await fixture.store.snapshot()
    #expect(snapshot.document.indexes.contains { $0.id == result.indexID && $0.title == "数据库" })
    #expect(snapshot.document.entries.filter { $0.indexId == result.indexID }.count == 2)
}

@Test func rejectedAgentWriteRequestDoesNotGrantAccess() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )
    let task = Task {
        try await service.createCatalogEntry(CatalogDraftRequest(
            indexID: serviceIndexID,
            title: "Komga"
        ))
    }
    let request = try await awaitAgentWriteRequest(captured)
    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: false)
    let error = await serviceCatalogError { try await task.value }
    #expect(error == .agentWriteNotAllowed)
    #expect(await approver.count == 0)
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
}

@Test func appCanDiscoverPendingAgentWriteRequestsAfterColdStart() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: CatalogApprovalRecorder(),
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await service.createCatalogEntry(CatalogDraftRequest(
            indexID: serviceIndexID,
            title: "冷启动待授权"
        ))
    }
    let request = try await awaitAgentWriteRequest(captured)

    let pendingIDs = try await service.pendingCatalogWriteAccessRequestIDs()
    #expect(pendingIDs.contains(request.id))
    #expect(try await service.pendingCatalogWriteAccessRequest(id: request.id).id == request.id)

    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: true)
    _ = try await task.value
    #expect(try await service.pendingCatalogWriteAccessRequestIDs().isEmpty)
}

private struct CatalogMultiSecretEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        let reference = plaintext == "password-canary" ? servicePasswordRef : servicePrivateKeyRef
        return try SecretReference(reference)
    }
}

private actor CatalogEncryptCallCounter {
    private var count = 0

    func next() -> Int {
        count += 1
        return count
    }
}

private struct CatalogFailOnSecondEncryptor: TextEncrypting {
    let counter: CatalogEncryptCallCounter

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        _ = (label, policy)
        guard await counter.next() == 1 else {
            struct SecondSecretCreationError: Error {}
            throw SecondSecretCreationError()
        }
        return try SecretReference(servicePasswordRef)
    }
}

private struct CatalogReplacementEncryptor: TextEncrypting {
    let reference: String

    init(reference: String = servicePrivateKeyRef) {
        self.reference = reference
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        _ = (plaintext, label, policy)
        return try SecretReference(reference)
    }
}

private actor CatalogDeletingRecorder: RecordDeleting {
    private(set) var deletedIDs: [String] = []

    func delete(id: String) async throws {
        deletedIDs.append(id)
    }
}

private actor CatalogFailingDeletingRecorder: RecordDeleting {
    private(set) var attemptedIDs: [String] = []

    func delete(id: String) async throws {
        attemptedIDs.append(id)
        struct DeleteError: Error {}
        throw DeleteError()
    }
}

private struct CatalogRecordLister: RecordListing {
    let ids: [String]

    func recordIDs() async throws -> [String] { ids }
}

private struct CatalogRaceEncryptor: TextEncrypting {
    let store: SensitiveCatalogDocumentStore
    let reference: String

    init(store: SensitiveCatalogDocumentStore, reference: String = servicePasswordRef) {
        self.store = store
        self.reference = reference
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        _ = (plaintext, label, policy)
        let snapshot = try await store.snapshot()
        let entry = try #require(snapshot.document.entries.first)
        let concurrentEntry = SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: "并发修改",
            type: entry.type,
            aliases: entry.aliases,
            endpoints: entry.endpoints,
            fields: entry.fields,
            notes: entry.notes,
            tags: entry.tags,
            schema: entry.schema
        )
        _ = try await store.updateEntry(concurrentEntry, expectedRevision: snapshot.revision)
        return try SecretReference(reference)
    }
}

private enum CatalogMetadataStoreError: Error {
    case unexpectedWrite
    case missingRecord
}

private struct CatalogMetadataRecordStore: RecordStore {
    let records: [EncryptedRecord]

    init(record: EncryptedRecord) {
        records = [record]
    }

    init(records: [EncryptedRecord]) {
        self.records = records
    }

    func save(_: EncryptedRecord) async throws {
        throw CatalogMetadataStoreError.unexpectedWrite
    }

    func latest(id: String) async throws -> EncryptedRecord {
        guard let record = records.first(where: { $0.id == id }) else {
            throw CatalogMetadataStoreError.missingRecord
        }
        return record
    }

    func versions(id: String) async throws -> [Int] {
        guard let record = records.first(where: { $0.id == id }) else {
            throw CatalogMetadataStoreError.missingRecord
        }
        return [record.recordVersion]
    }
}

private actor CatalogApprovalRecorder: OperationApproving {
    private(set) var count = 0
    private(set) var summaries: [String] = []

    func approve(summary: String) async throws {
        count += 1
        summaries.append(summary)
    }
}

private actor CatalogContextApprovalRecorder: OperationApprovalContextProviding {
    private(set) var count = 0
    let context: LocalAuthenticationContext

    init(context: LocalAuthenticationContext) {
        self.context = context
    }

    func approve(summary: String) async throws {
        _ = try await approveWithAuthenticationContext(summary: summary)
    }

    func approveWithAuthenticationContext(summary: String) async throws -> LocalAuthenticationContext? {
        _ = summary
        count += 1
        return context
    }
}

private actor CatalogContextKeyProvider {
    let key: SymmetricKey
    private(set) var contexts: [LocalAuthenticationContext?] = []

    init(key: SymmetricKey) {
        self.key = key
    }

    func resolve(authenticationContext: LocalAuthenticationContext?) -> SymmetricKey {
        contexts.append(authenticationContext)
        return key
    }

    func recordedContexts() -> [LocalAuthenticationContext?] {
        contexts
    }
}

private actor CatalogAuditRecorder {
    private(set) var entries: [AgentAutomationAuditEntry] = []

    func append(_ entry: AgentAutomationAuditEntry) {
        entries.append(entry)
    }

    func recordedEntries() -> [AgentAutomationAuditEntry] {
        entries
    }
}

private actor CatalogApprovalGate: OperationApproving {
    private var started = false
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func approve(summary: String) async throws {
        _ = summary
        started = true
        await withCheckedContinuation { continuation in
            releaseContinuation = continuation
        }
    }

    func waitUntilStarted() async {
        while !started {
            await Task.yield()
        }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private final class TestDateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ value: Date) {
        self.value = value
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        value.addTimeInterval(interval)
        lock.unlock()
    }
}

private func catalogMetadataRecord(id: String, label: String = "QNAP credential") -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: 2,
        id: id,
        recordVersion: 1,
        ciphertext: Data(),
        nonce: Data(),
        tag: Data(),
        wrappedDataKey: Data(),
        wrappedDataKeyNonce: Data(),
        wrappedDataKeyTag: Data(),
        label: label,
        policy: .credential,
        createdAt: Date(),
        updatedAt: Date()
    )
}

private func serviceDocument() -> SecretCatalogDocument {
    SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: serviceIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: serviceEntryID,
            indexId: serviceIndexID,
            title: "QNAP 管理后台登录",
            endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
            fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
                SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
            ]
        )]
    )
}

private struct CatalogFixture {
    let root: URL
    let documentURL: URL
    let selectionURL: URL
    let store: SensitiveCatalogDocumentStore
    let agentAuthorization: CatalogAgentWriteAuthorization

    init(
        secretReferenceExists: (@Sendable (String) async -> Bool)? = nil
    ) async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("svlt-service-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        documentURL = root.appendingPathComponent("敏感信息.md")
        selectionURL = root.appendingPathComponent("selection.json")
        store = SensitiveCatalogDocumentStore(
            documentURL: documentURL,
            integrityURL: root.appendingPathComponent("catalog-integrity.json"),
            keyStore: try FixedCatalogIntegrityKeyStore(key: Data(repeating: 7, count: 32)),
            secretReferenceExists: secretReferenceExists
        )
        try await store.selectDocument(at: documentURL)
        _ = try await store.canonicalWrite(serviceDocument())
        try SecretCatalogSelectionStore(manifestURL: selectionURL).save(documentURL: documentURL)
        agentAuthorization = CatalogAgentWriteAuthorization()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

@Test func agentCatalogValidationLoadsTheSharedSelectedDocument() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let result = try await service.validateCatalog()

    #expect(result.status == .found)
    #expect(result.revision == 1)
    #expect(result.rawSHA256 != nil)
    #expect(result.diagnostics.isEmpty)
}

@Test func agentCatalogCreateIndexIsVisibleThroughAuthoritativeRecentAudit() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let auditDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-\(UUID().uuidString)")
    let auditKey = SymmetricKey(data: Data(repeating: 0x61, count: 32))
    let auditLog = EncryptedAuditLog(directoryURL: auditDirectory) {
        auditKey
    }
    let captured = RequestCapture()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: CatalogApprovalRecorder(),
        auditLog: auditLog,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await AuditContext.$current.withValue(AuditContext(source: .agent)) {
            try await service.createCatalogIndex(title: "审计分组", aliases: [], tags: [])
        }
    }
    let request = try await awaitAgentWriteRequest(captured)
    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: true)
    _ = try await task.value

    let recent = try await service.catalogRecentAuditEntries(limit: 100)
    #expect(recent.entries.contains { entry in
        entry.source == .agent
            && entry.operation == .catalogMutation
            && entry.target == "catalog"
    })
    #expect(recent.diagnostics == .none)
    #expect(try await service.catalogAuditHealth() == nil)

    // Keep the App-control hop in this cross-layer test: the App gets the
    // bounded encrypted-audit projection through this handler, not through
    // the mutation response or a View-owned fabricated row.
    let response = await AppControlRequestHandler(service: service)
        .handle(.catalogRecentAuditEntries(limit: 100))
    guard case let .catalogRecentAuditEntries(appControlResult) = response else {
        Issue.record("AppControl did not return the authoritative audit projection")
        return
    }
    #expect(appControlResult.entries.contains { $0.operation == .catalogMutation && $0.source == .agent })
    #expect(appControlResult.diagnostics == .none)
}

@Test func failedAuditAppendExposesSafeHealthWithoutFailingOperation() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    // The non-nil log without a key provider makes every append fail while
    // the production operation remains allowed to complete.
    let auditLog = EncryptedAuditLog(
        directoryURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-audit-health-\(UUID().uuidString)")
    )
    let auditHealthURL = fixture.root.appendingPathComponent("audit-health.json")
    let captured = RequestCapture()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: CatalogApprovalRecorder(),
        auditLog: auditLog,
        auditHealthURL: auditHealthURL,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await AuditContext.$current.withValue(AuditContext(source: .agent)) {
            try await service.createCatalogIndex(title: "健康检查分组", aliases: [], tags: [])
        }
    }
    let request = try await awaitAgentWriteRequest(captured)
    try await service.respondToCatalogWriteAccessRequest(id: request.id, approved: true)
    let result = try await task.value
    #expect(result.revision == 2)
    #expect(try await service.catalogAuditHealth() == "AUDIT_APPEND_FAILED")

    // The gap is sticky across a later daemon instance and is not hidden by
    // a subsequent successful append.
    let restored = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        auditHealthURL: auditHealthURL
    )
    #expect(await restored.catalogAuditHealth() == "AUDIT_APPEND_FAILED")
}

@Test func appAuditProjectionKeepsHealthyEntriesWhenOneRecordCannotBeRead() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let auditDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-partial-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: auditDirectory)
    }
    let auditKey = SymmetricKey(data: Data(repeating: 0x62, count: 32))
    let auditLog = EncryptedAuditLog(
        directoryURL: auditDirectory,
        auditKeyProvider: { auditKey }
    )
    try await auditLog.append(AuditEvent(
        timestamp: Date(timeIntervalSince1970: 1_900_000_700),
        source: .agent,
        integration: "agent-secret-vault-mcp",
        referenceID: nil,
        operation: .status,
        risk: 0,
        authorizationOutcome: .notRequired,
        declaredTarget: "catalog",
        status: .completed,
        exitCode: nil
    ))
    try Data("{\"truncated\":".utf8).write(
        to: auditDirectory.appendingPathComponent("broken.audit.json"),
        options: [.atomic]
    )
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        auditLog: auditLog
    )

    let result = try await service.catalogRecentAuditEntries(limit: 100)

    #expect(result.entries.count == 1)
    #expect(result.diagnostics.unreadableRecordCount == 1)
    #expect(result.diagnostics.integrityFailureCount == 0)
}

@Test func agentSecureInputSessionIsAtomicAndUsesOneDeviceOwnerApproval() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let approver = CatalogApprovalRecorder()
    let recordStore = CatalogMetadataRecordStore(record: catalogMetadataRecord(
        id: String(servicePasswordRef.dropFirst("secret://".count)),
        label: "用户名凭据"
    ))
    let auditLog = EncryptedAuditLog(
        directoryURL: fixture.root.appendingPathComponent("audit"),
        auditKeyProvider: { SymmetricKey(data: Data(repeating: 0x62, count: 32)) }
    )
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        auditLog: auditLog
    )

    let pending = try await AuditContext.$current.withValue(AuditContext(source: .agent)) {
        try await service.requestCatalogSecureInputs(
            entryID: serviceEntryID,
            targets: [
                CatalogSecureInputTargetRequest(
                    entryID: serviceEntryID,
                    fieldKey: "password",
                    mode: .fillPlaceholder,
                    required: true
                )
            ],
            expectedRevision: 1
        )
    }
    #expect(pending.status == .pending)
    let id = try #require((await service.pendingCatalogSecureInputRequestIDs()).first)
    let request = try await service.catalogSecureInputRequest(id: id)
    #expect(request.targets.first?.label == "密码")
    #expect(await service.catalogSecureInputStatus(requestID: id).status == .pending)

    let completed = try await service.submitCatalogSecureInput(
        id: id,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [request.targets[0].id],
            plaintextByFieldKey: ["password": "admin-updated"]
        )
    )
    #expect(completed.status == .completed)
    #expect(completed.revision == 2)
    #expect(await approver.count == 1)
    #expect(await service.pendingCatalogSecureInputRequestIDs().isEmpty)
    #expect(await service.catalogSecureInputStatus(requestID: id).revision == 2)
    let snapshot = try await fixture.store.snapshot()
    let field = try #require(snapshot.document.entries[0].fields.first(where: { $0.key == "password" }))
    #expect(field.type.isSecret)
    #expect(field.value == nil)
    #expect(field.secretRef == servicePasswordRef)
    let auditEvents = try await auditLog.export()
    #expect(Set(auditEvents.compactMap(\.requestID)) == [id])
    await #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try await service.submitCatalogSecureInput(
            id: id,
            submission: CatalogSecureInputSubmission(
                selectedTargetIDs: [request.targets[0].id],
                plaintextByFieldKey: ["username": "second"]
            )
        )
    }
}

@Test func secureInputTerminalReceiptsSurviveRestartAndExpireAsUnknown() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let clock = TestDateBox(Date(timeIntervalSince1970: 1_800_000_000))
    let receiptURL = fixture.root.appendingPathComponent("secure-input-receipts.json")
    let recordStore = CatalogMetadataRecordStore(record: catalogMetadataRecord(
        id: String(servicePasswordRef.dropFirst("secret://".count))
    ))
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: CatalogApprovalRecorder(),
        now: { clock.now() },
        secureInputReceiptURL: receiptURL
    )

    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(
            entryID: serviceEntryID,
            fieldKey: "password",
            mode: .fillPlaceholder,
            required: true
        )],
        expectedRevision: 1
    )
    let request = try await service.catalogSecureInputRequest(id: pending.requestID)
    _ = try await service.submitCatalogSecureInput(
        id: pending.requestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [request.targets[0].id],
            plaintextByFieldKey: ["password": "persisted-receipt"]
        )
    )

    let restored = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        now: { clock.now() },
        secureInputReceiptURL: receiptURL
    )
    let restoredStatus = await restored.catalogSecureInputStatus(requestID: pending.requestID)
    #expect(restoredStatus.status == .completed)
    #expect(restoredStatus.revision == 2)

    clock.advance(by: 15 * 60 + 1)
    let expiredStatus = await service.catalogSecureInputStatus(requestID: pending.requestID)
    #expect(expiredStatus.status == .unknown)
    #expect(expiredStatus.errorCode == "SECURE_INPUT_REQUEST_UNKNOWN")
    #expect((await restored.catalogSecureInputStatus(requestID: pending.requestID)).status == .unknown)
}

@Test func secureInputReceiptLoaderKeepsNewestDuplicateWithoutTrapping() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let clock = TestDateBox(Date(timeIntervalSince1970: 1_800_000_000))
    let receiptURL = fixture.root.appendingPathComponent("secure-input-receipts.json")
    let requestID = UUID()
    let terminalAt = clock.now().timeIntervalSinceReferenceDate
    let records: [[String: Any]] = [
        [
            "schemaVersion": 1,
            "requestID": requestID.uuidString,
            "status": "COMPLETED",
            "revision": 1,
            "terminalAt": terminalAt - 1
        ],
        [
            "schemaVersion": 1,
            "requestID": requestID.uuidString,
            "status": "COMPLETED",
            "revision": 2,
            "terminalAt": terminalAt
        ]
    ]
    try JSONSerialization.data(withJSONObject: records, options: [.sortedKeys]).write(to: receiptURL)

    let restored = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        now: { clock.now() },
        secureInputReceiptURL: receiptURL
    )
    let status = await restored.catalogSecureInputStatus(requestID: requestID)
    #expect(status.status == .completed)
    #expect(status.revision == 2)
}

@Test func agentSecureInputConvertsExistingCatalogValueWithoutDroppingIt() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let recordStore = CatalogMetadataRecordStore(record: catalogMetadataRecord(
        id: String(servicePasswordRef.dropFirst("secret://".count)),
        label: "本机转换测试"
    ))
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: CatalogApprovalRecorder()
    )

    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [
            CatalogSecureInputTargetRequest(
                entryID: serviceEntryID,
                fieldKey: "username",
                mode: .convertToSecret,
                required: true
            )
        ],
        expectedRevision: 1
    )
    let request = try await service.catalogSecureInputRequest(id: pending.requestID)
    let target = try #require(request.targets.first)
    #expect(target.required)
    #expect(target.usesExistingValue)

    let completed = try await service.submitCatalogSecureInput(
        id: pending.requestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [target.id],
            plaintextByFieldKey: [:]
        )
    )
    #expect(completed.status == .completed)
    let snapshot = try await fixture.store.snapshot()
    let field = try #require(snapshot.document.entries[0].fields.first(where: { $0.key == "username" }))
    #expect(field.type == .secret)
    #expect(field.value == nil)
    #expect(field.secretRef == servicePasswordRef)
}

@Test func agentSecureInputAuthorizesFinalReplaceSecretDiffAfterNewReferenceExists() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let original = serviceDocument()
    let originalEntry = try #require(original.entries.first)
    let entryWithSecret = SecretCatalogEntry(
        id: originalEntry.id,
        indexId: originalEntry.indexId,
        title: originalEntry.title,
        type: originalEntry.type,
        aliases: originalEntry.aliases,
        endpoints: originalEntry.endpoints,
        fields: originalEntry.fields.map { field in
            guard field.key == "password" else { return field }
            return SecretCatalogFieldValue(
                key: field.key,
                label: field.label,
                type: field.type,
                agentVisible: field.agentVisible,
                searchable: field.searchable,
                value: nil,
                secretRef: servicePasswordRef
            )
        },
        notes: originalEntry.notes,
        tags: originalEntry.tags,
        schema: originalEntry.schema
    )
    _ = try await fixture.store.canonicalWrite(
        SecretCatalogDocument(indexes: original.indexes, entries: [entryWithSecret]),
        expectedRevision: 1
    )

    let approver = CatalogApprovalRecorder()
    let recordStore = CatalogMetadataRecordStore(records: [
        catalogMetadataRecord(id: String(servicePasswordRef.dropFirst("secret://".count))),
        catalogMetadataRecord(id: String(servicePrivateKeyRef.dropFirst("secret://".count)), label: "新密码")
    ])
    let service = VaultAppServices(
        textEncryptor: CatalogReplacementEncryptor(reference: servicePrivateKeyRef),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )

    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(
            entryID: serviceEntryID,
            fieldKey: "password",
            mode: .replaceSecret,
            required: true
        )],
        expectedRevision: 2
    )
    let request = try await service.catalogSecureInputRequest(id: pending.requestID)
    let completed = try await service.submitCatalogSecureInput(
        id: pending.requestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [request.targets[0].id],
            plaintextByFieldKey: ["password": "rotated-password"]
        )
    )
    #expect(completed.status == .completed)
    #expect(await approver.count == 1)
    let snapshot = try await fixture.store.snapshot()
    #expect(snapshot.document.entries[0].fields.first(where: { $0.key == "password" })?.secretRef == servicePrivateKeyRef)
}

@Test func concurrentSecureInputRequestsForSameEntryAreRevisionBound() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let approver = CatalogApprovalRecorder()
    let recordStore = CatalogMetadataRecordStore(record: catalogMetadataRecord(
        id: String(servicePasswordRef.dropFirst("secret://".count))
    ))
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )
    let first = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(entryID: serviceEntryID, fieldKey: "password", mode: .fillPlaceholder)],
        expectedRevision: 1
    )
    let second = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(entryID: serviceEntryID, fieldKey: "password", mode: .fillPlaceholder)],
        expectedRevision: 1
    )
    let firstRequest = try await service.catalogSecureInputRequest(id: first.requestID)
    let secondRequest = try await service.catalogSecureInputRequest(id: second.requestID)

    async let firstResult = service.submitCatalogSecureInput(
        id: first.requestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [firstRequest.targets[0].id],
            plaintextByFieldKey: ["password": "first"]
        )
    )
    async let secondResult = service.submitCatalogSecureInput(
        id: second.requestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: [secondRequest.targets[0].id],
            plaintextByFieldKey: ["password": "second"]
        )
    )
    var results: [Result<CatalogSecureInputStatus, Error>] = []
    do {
        results.append(.success(try await firstResult))
    } catch {
        results.append(.failure(error))
    }
    do {
        results.append(.success(try await secondResult))
    } catch {
        results.append(.failure(error))
    }
    let completedCount = results.compactMap { result -> CatalogSecureInputStatus? in
        guard case let .success(status) = result else { return nil }
        return status.status == .completed ? status : nil
    }.count
    #expect(completedCount == 1)
    #expect(await approver.count == 2)
    let snapshot = try await fixture.store.snapshot()
    #expect(snapshot.revision == 2)
}

@Test func staleGenericCatalogEditorCannotCommitWhileSecureInputIsPending() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(entryID: serviceEntryID, fieldKey: "password", mode: .fillPlaceholder)],
        expectedRevision: 1
    )
    let snapshot = try await fixture.store.snapshot()
    let entry = try #require(snapshot.document.entries.first)

    await #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try await service.catalogCommitEntryEdit(
            entry,
            secretInputs: [CatalogSecretInput(key: "password", label: "密码", plaintext: "stale")],
            expectedRevision: 1
        )
    }
    #expect(await service.catalogSecureInputStatus(requestID: pending.requestID).status == .pending)
    #expect(try await fixture.store.snapshot().revision == 1)
}

@Test func cancellingSecureInputDuringAuthenticationPreventsLateCommit() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let approvalGate = CatalogApprovalGate()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approvalGate
    )
    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(
            entryID: serviceEntryID,
            fieldKey: "password",
            mode: .fillPlaceholder,
            required: true
        )],
        expectedRevision: 1
    )

    let submitTask = Task {
        try await service.submitCatalogSecureInput(
            id: pending.requestID,
            submission: CatalogSecureInputSubmission(
                selectedTargetIDs: [serviceEntryID + ":password"],
                plaintextByFieldKey: ["password": "late-input"]
            )
        )
    }
    await approvalGate.waitUntilStarted()
    await service.cancelCatalogSecureInput(id: pending.requestID)
    await approvalGate.release()

    do {
        _ = try await submitTask.value
        Issue.record("cancelled Secure Input unexpectedly committed")
    } catch {
        #expect(error is SecretCatalogAgentError)
    }
    #expect(await service.catalogSecureInputStatus(requestID: pending.requestID).status == .cancelled)
    #expect(try await fixture.store.snapshot().revision == 1)
}

@Test func invalidatingSecurityStateCancelsAwaitingSecureInput() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let pending = try await service.requestCatalogSecureInputs(
        entryID: serviceEntryID,
        targets: [CatalogSecureInputTargetRequest(
            entryID: serviceEntryID,
            fieldKey: "password",
            mode: .fillPlaceholder,
            required: true
        )],
        expectedRevision: 1
    )

    await service.invalidateSecurityState()

    #expect(await service.pendingCatalogSecureInputRequestIDs().isEmpty)
    let status = await service.catalogSecureInputStatus(requestID: pending.requestID)
    #expect(status.status == .cancelled)
    #expect(status.errorCode == "SECURE_INPUT_CANCELLED")
}

private struct ExternalCatalogAdoptionFixture {
    let root: URL
    let documentURL: URL
    let integrityURL: URL
    let selectionURL: URL
    let store: SensitiveCatalogDocumentStore
    let agentAuthorization: CatalogAgentWriteAuthorization

    init(reference: String) async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("svlt-adoption-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        documentURL = root.appendingPathComponent("敏感信息.md")
        integrityURL = root.appendingPathComponent("catalog-integrity.json")
        selectionURL = root.appendingPathComponent("selection.json")
        store = SensitiveCatalogDocumentStore(
            documentURL: documentURL,
            integrityURL: integrityURL,
            keyStore: try FixedCatalogIntegrityKeyStore(key: Data(repeating: 7, count: 32))
        )
        try await store.selectDocument(at: documentURL)
        let document = SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: serviceIndexID, title: "QNAP")],
            entries: [SecretCatalogEntry(
                id: serviceEntryID,
                indexId: serviceIndexID,
                title: "管理后台",
                fields: [SecretCatalogFieldValue(
                    key: "password",
                    label: "密码",
                    type: .secret,
                    secretRef: reference
                )]
            )]
        )
        try SensitiveCatalogDocumentCodec.encode(document).write(to: documentURL, atomically: true, encoding: .utf8)
        try SecretCatalogSelectionStore(manifestURL: selectionURL).save(documentURL: documentURL)
        agentAuthorization = CatalogAgentWriteAuthorization()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

@Test func appServiceUsesEntryCentricCatalogAndNeverReturnsPlaintext() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let result = try await service.searchSecrets(query: "QNAP", field: nil, limit: 10)
    #expect(result.status == .found)
    #expect(result.matches.first?.entry.fields.contains { $0.key == "username" && $0.value == .string("admin") } == true)
    #expect(result.matches.first?.entry.fields.contains { $0.key == "password" && $0.secretRef == nil } == true)
}

@Test func appServiceAllowsSafeCatalogCreationWithoutStructureLease() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )
    let request = CatalogDraftRequest(indexID: serviceIndexID, title: "Komga")

    let draft = try await service.createCatalogDraft(request)
    let task = Task {
        try await service.commitCatalogDraft(draft, expectedRevision: draft.baseRevision)
    }
    let accessRequest = try await awaitAgentWriteRequest(captured)
    try await service.respondToCatalogWriteAccessRequest(id: accessRequest.id, approved: true)
    let result = try await task.value
    #expect(result.entry?.title == "Komga")
    #expect(await approver.count == 1)
}

@Test func appServiceRejectsManualAgentWriteEnable() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        _ = try await service.setCatalogAgentWriteMode(mode: .safe, duration: nil)
    }
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
}

@Test func appServiceKeepsManualEnableFailClosedAndRevokeAvailable() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
    await service.revokeCatalogAgentWrite()
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        _ = try await service.setCatalogAgentWriteMode(mode: .safe, duration: nil)
    }
    await service.revokeCatalogAgentWrite()
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
}

@Test func agentSafeCreateEntryWritesMetadataAndEmptySecretPlaceholderWithoutLease() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let captured = RequestCapture()
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier(present: { request in
            Task { await captured.set(request) }
        })
    )

    let task = Task {
        try await service.createCatalogEntry(CatalogDraftRequest(
        indexID: serviceIndexID,
        title: "音乐服务器",
        endpoints: [CatalogEndpoint(type: "http", host: "192.168.2.240", port: 4533)],
        fields: [
            SecretCatalogFieldValue(
                key: "username",
                label: "用户名",
                type: .text,
                value: .string("zyk")
            ),
            SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
        ]
    ))
    }
    let accessRequest = try await awaitAgentWriteRequest(captured)
    try await service.respondToCatalogWriteAccessRequest(id: accessRequest.id, approved: true)
    let result = try await task.value

    #expect(result.entry?.title == "音乐服务器")
    #expect(result.entry?.fields.first(where: { $0.key == "username" })?.value == .string("zyk"))
    #expect(result.entry?.fields.first(where: { $0.key == "password" })?.secretRef == nil)
    let search = try await service.searchSecrets(query: "音乐服务器", field: nil, limit: 10)
    #expect(search.matches.count == 1)
}

@Test func appServiceDoesNotLetDraftSmuggleExistingSecretBinding() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let request = CatalogDraftRequest(
        indexID: serviceIndexID,
        title: "Komga",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )

    let error = await serviceCatalogError {
        _ = try await service.createCatalogDraft(request)
    }
    #expect(error == .approvalRequired)
}

@Test func appServiceDoesNotLetAgentBindExistingSecretWithoutApproval() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let approvalError = await serviceCatalogError {
        _ = try await service.bindCatalogExistingSecret(
            entryID: serviceEntryID,
            key: "password",
            secretRef: servicePasswordRef,
            expectedRevision: 1
        )
    }
    #expect(approvalError == .approvalRequired)
}

@Test func appServiceRejectsV3AdoptionWhenSecretReferenceDoesNotExist() async throws {
    let fixture = try await ExternalCatalogAdoptionFixture(reference: servicePrivateKeyRef)
    defer { fixture.cleanup() }
    let recordStore = CatalogMetadataRecordStore(record: EncryptedRecord(
        formatVersion: 2,
        id: String(servicePasswordRef.dropFirst("secret://".count)),
        recordVersion: 1,
        ciphertext: Data(),
        nonce: Data(),
        tag: Data(),
        wrappedDataKey: Data(),
        wrappedDataKeyNonce: Data(),
        wrappedDataKeyTag: Data(),
        label: "QNAP credential",
        policy: .credential,
        createdAt: Date(),
        updatedAt: Date()
    ))
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let error = await serviceCatalogError {
        _ = try await service.adoptCatalogExternalV3()
    }

    #expect(error == .invalidOperation)
    #expect(!FileManager.default.fileExists(atPath: fixture.integrityURL.path))
}

@Test func appServiceRequiresLocalApprovalForExistingSecretDuringV3Adoption() async throws {
    let fixture = try await ExternalCatalogAdoptionFixture(reference: servicePasswordRef)
    defer { fixture.cleanup() }
    let recordStore = CatalogMetadataRecordStore(record: EncryptedRecord(
        formatVersion: 2,
        id: String(servicePasswordRef.dropFirst("secret://".count)),
        recordVersion: 1,
        ciphertext: Data(),
        nonce: Data(),
        tag: Data(),
        wrappedDataKey: Data(),
        wrappedDataKeyNonce: Data(),
        wrappedDataKeyTag: Data(),
        label: "QNAP credential",
        policy: .credential,
        createdAt: Date(),
        updatedAt: Date()
    ))
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )

    let result = try await service.adoptCatalogExternalV3()

    #expect(result.status == .found)
    #expect(result.revision == 1)
    #expect(await approver.count == 1)
    #expect(FileManager.default.fileExists(atPath: fixture.integrityURL.path))
}

@Test func appControlSecretEndpointChangeRequiresAndUsesLocalApproval() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }

    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
        fields: [
            SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
            SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                secretRef: servicePasswordRef
            )
        ]
    )
    let boundSnapshot = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    let recordStore = CatalogMetadataRecordStore(record: EncryptedRecord(
        formatVersion: 2,
        id: String(servicePasswordRef.dropFirst("secret://".count)),
        recordVersion: 1,
        ciphertext: Data(),
        nonce: Data(),
        tag: Data(),
        wrappedDataKey: Data(),
        wrappedDataKeyNonce: Data(),
        wrappedDataKeyTag: Data(),
        label: "QNAP credential",
        policy: .credential,
        allowedDestinations: ["192.168.2.240"],
        allowedProtocols: ["https"],
        createdAt: Date(),
        updatedAt: Date()
    ))
    let approver = CatalogApprovalRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )

    let changed = SecretCatalogEntry(
        id: boundEntry.id,
        indexId: boundEntry.indexId,
        title: boundEntry.title,
        endpoints: [CatalogEndpoint(type: "https", host: "evil.example.com", port: 443)],
        fields: boundEntry.fields
    )
    let result = try await service.catalogUpdateEntry(changed, expectedRevision: boundSnapshot.revision)

    #expect(result.entry?.endpoints.first?.host == "evil.example.com")
    #expect(await approver.count == 1)
}

@Test func appServiceKeepsMultipleSecureFieldsIndependentAndNeverStoresPlaintext() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogMultiSecretEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let initial = try await fixture.store.snapshot()
    let oldEntry = try #require(initial.document.entries.first)
    let sshEntry = SecretCatalogEntry(
        id: oldEntry.id,
        indexId: oldEntry.indexId,
        title: "SSH 登录",
        type: oldEntry.type,
        aliases: oldEntry.aliases,
        endpoints: [CatalogEndpoint(type: "ssh", host: "192.168.2.240", port: 22)],
        fields: [
            SecretCatalogFieldValue(key: "password", label: "密码", type: .secret),
            SecretCatalogFieldValue(key: "privateKey", label: "私钥", type: .secret)
        ],
        notes: oldEntry.notes,
        tags: ["SSH"],
        schema: oldEntry.schema
    )
    _ = try await fixture.store.updateEntry(sshEntry, expectedRevision: initial.revision)

    let password = try await service.catalogSecureInput(
        entryID: oldEntry.id,
        key: "password",
        label: "密码",
        plaintext: "password-canary",
        policy: .credential
    )
    let privateKey = try await service.catalogSecureInput(
        entryID: oldEntry.id,
        key: "privateKey",
        label: "私钥",
        plaintext: "private-key-canary",
        policy: .credential
    )
    #expect(password.reference == servicePasswordRef)
    #expect(privateKey.reference == servicePrivateKeyRef)
    #expect(password.reference != privateKey.reference)

    let final = try await fixture.store.snapshot()
    let fields = try #require(final.document.entries.first?.fields)
    #expect(fields.first(where: { $0.key == "password" })?.secretRef == servicePasswordRef)
    #expect(fields.first(where: { $0.key == "privateKey" })?.secretRef == servicePrivateKeyRef)
    let markdown = try String(contentsOf: fixture.documentURL, encoding: .utf8)
    #expect(!markdown.contains("password-canary"))
    #expect(!markdown.contains("private-key-canary"))
}

@Test func appServiceCommitsNewSecretFieldWithEntryMetadataInOneCall() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let initial = try await fixture.store.snapshot()
    let entry = try #require(initial.document.entries.first)
    let draft = SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: "QNAP 管理后台登录（已编辑）",
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: entry.fields + [SecretCatalogFieldValue(key: "apiKey", label: "API 密钥", type: .secret)],
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )

    let result = try await service.catalogCommitEntryEdit(
        draft,
        secretInputs: [CatalogSecretInput(key: "apiKey", label: "API 密钥", plaintext: "commit-canary")],
        expectedRevision: initial.revision
    )

    #expect(result.entry?.title == "QNAP 管理后台登录（已编辑）")
    let final = try await fixture.store.snapshot()
    #expect(final.document.entries.first?.fields.first(where: { $0.key == "apiKey" })?.secretRef == servicePasswordRef)
    #expect(try String(contentsOf: fixture.documentURL, encoding: .utf8).contains("commit-canary") == false)
    #expect(await deleter.deletedIDs.isEmpty)
}

@Test func appServiceRollsBackNewSecretRecordWhenEntryCommitConflicts() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogRaceEncryptor(store: fixture.store),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let initial = try await fixture.store.snapshot()
    let entry = try #require(initial.document.entries.first)
    let draft = SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: entry.fields + [SecretCatalogFieldValue(key: "apiKey", label: "API 密钥", type: .secret)],
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )

    await #expect(throws: SecretCatalogAgentError.revisionConflict) {
        _ = try await service.catalogCommitEntryEdit(
            draft,
            secretInputs: [CatalogSecretInput(key: "apiKey", label: "API 密钥", plaintext: "rollback-canary")],
            expectedRevision: initial.revision
        )
    }
    #expect(await deleter.deletedIDs == [String(servicePasswordRef.dropFirst("secret://".count))])
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs().isEmpty)
    let final = try await fixture.store.snapshot()
    #expect(final.document.entries.first?.fields.contains(where: { $0.key == "apiKey" }) == false)
}

@Test func appServiceReportsCleanupRequiredAndPersistsOpaqueReferenceWhenCompensationFails() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let deleter = CatalogFailingDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogRaceEncryptor(store: fixture.store),
        activeRoot: nil,
        recordLister: CatalogRecordLister(ids: [String(servicePasswordRef.dropFirst("secret://".count))]),
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let initial = try await fixture.store.snapshot()
    let entry = try #require(initial.document.entries.first)
    let draft = SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: entry.fields + [SecretCatalogFieldValue(key: "apiKey", label: "API 密钥", type: .secret)],
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )

    await #expect(throws: SecretCatalogAgentError.cleanupRequired) {
        _ = try await service.catalogCommitEntryEdit(
            draft,
            secretInputs: [CatalogSecretInput(key: "apiKey", label: "API 密钥", plaintext: "cleanup-canary")],
            expectedRevision: initial.revision
        )
    }
    #expect(await deleter.attemptedIDs == [String(servicePasswordRef.dropFirst("secret://".count))])
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs() == [String(servicePasswordRef.dropFirst("secret://".count))])
    let orphanScan = try await service.scanOrphans(markdownReferences: [])
    #expect(orphanScan.unreferencedRecords == [servicePasswordRef])
    let markdown = try String(contentsOf: fixture.documentURL, encoding: .utf8)
    #expect(!markdown.contains("cleanup-canary"))
}

@Test func appServiceCompensatesEverySecretCreatedBeforeLaterCreationFails() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogFailOnSecondEncryptor(counter: CatalogEncryptCallCounter()),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let initial = try await fixture.store.snapshot()
    let entry = try #require(initial.document.entries.first)
    let draft = SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: entry.fields + [
            SecretCatalogFieldValue(key: "apiKey", label: "API 密钥", type: .secret),
            SecretCatalogFieldValue(key: "privateKey", label: "私钥", type: .secret)
        ],
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )

    do {
        _ = try await service.catalogCommitEntryEdit(
            draft,
            secretInputs: [
                CatalogSecretInput(key: "apiKey", label: "API 密钥", plaintext: "first-secret"),
                CatalogSecretInput(key: "privateKey", label: "私钥", plaintext: "second-secret")
            ],
            expectedRevision: initial.revision
        )
        Issue.record("第二个 secret 创建失败时不应提交 Entry")
    } catch {
        #expect(String(describing: error).contains("SecondSecretCreationError"))
    }
    #expect(await deleter.deletedIDs == [String(servicePasswordRef.dropFirst("secret://".count))])
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs().isEmpty)
    let final = try await fixture.store.snapshot()
    #expect(final.document.entries.first?.fields.contains(where: { $0.key == "apiKey" }) == false)
    #expect(final.document.entries.first?.fields.contains(where: { $0.key == "privateKey" }) == false)
}

@Test func appServiceReplacementUsesApprovalAndDoesNotDeleteThePreviousRecord() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )
    _ = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    let recordStore = CatalogMetadataRecordStore(records: [
        catalogMetadataRecord(id: String(servicePasswordRef.dropFirst("secret://".count))),
        catalogMetadataRecord(id: String(servicePrivateKeyRef.dropFirst("secret://".count)))
    ])
    let approver = CatalogApprovalRecorder()
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogReplacementEncryptor(),
        activeRoot: nil,
        recordDeleter: deleter,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )

    let result = try await service.catalogSecureInput(
        entryID: serviceEntryID,
        key: "password",
        label: "密码",
        plaintext: "replacement-canary",
        policy: .credential
    )
    #expect(result.reference == servicePrivateKeyRef)
    #expect(await approver.count == 1)
    #expect(await approver.summaries.first?.contains("替换目录密码") == true)
    #expect(await deleter.deletedIDs.isEmpty)
    #expect(try await fixture.store.snapshot().document.entries.first?.fields.first?.secretRef == servicePrivateKeyRef)
    let markdown = try String(contentsOf: fixture.documentURL, encoding: .utf8)
    #expect(!markdown.contains("replacement-canary"))
}

@Test func appServiceEmptyReplacementInputLeavesExistingSecretUntouched() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )
    let before = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogReplacementEncryptor(),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    await #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try await service.catalogSecureInput(
            entryID: serviceEntryID,
            key: "password",
            label: "密码",
            plaintext: "",
            policy: .credential
        )
    }

    let after = try await fixture.store.snapshot()
    #expect(after.revision == before.revision)
    #expect(after.document.entries.first?.fields.first?.secretRef == servicePasswordRef)
    #expect(await deleter.deletedIDs.isEmpty)
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs().isEmpty)
}

@Test func appServiceReplacementFailureKeepsOldBindingAndPersistsNewOrphanID() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )
    _ = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    let recordStore = CatalogMetadataRecordStore(records: [
        catalogMetadataRecord(id: String(servicePasswordRef.dropFirst("secret://".count))),
        catalogMetadataRecord(id: String(serviceFailedReplacementRef.dropFirst("secret://".count)))
    ])
    let approver = CatalogApprovalRecorder()
    let deleter = CatalogFailingDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogRaceEncryptor(
            store: fixture.store,
            reference: serviceFailedReplacementRef
        ),
        activeRoot: nil,
        recordLister: CatalogRecordLister(ids: [
            String(servicePasswordRef.dropFirst("secret://".count)),
            String(serviceFailedReplacementRef.dropFirst("secret://".count))
        ]),
        recordDeleter: deleter,
        recordResolver: VaultRecordResolver(recordStore: recordStore),
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization,
        operationApprover: approver
    )

    await #expect(throws: SecretCatalogAgentError.cleanupRequired) {
        _ = try await service.catalogSecureInput(
            entryID: serviceEntryID,
            key: "password",
            label: "密码",
            plaintext: "replacement-failure-canary",
            policy: .credential
        )
    }

    let final = try await fixture.store.snapshot()
    #expect(final.document.entries.first?.fields.first?.secretRef == servicePasswordRef)
    #expect(await approver.count == 1)
    #expect(await deleter.attemptedIDs == [String(serviceFailedReplacementRef.dropFirst("secret://".count))])
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs() == [String(serviceFailedReplacementRef.dropFirst("secret://".count))])
    let orphanScan = try await service.scanOrphans(markdownReferences: [servicePasswordRef])
    #expect(orphanScan.unreferencedRecords == [serviceFailedReplacementRef])
    let markdown = try String(contentsOf: fixture.documentURL, encoding: .utf8)
    #expect(!markdown.contains("replacement-failure-canary"))
}

@Test func appServiceReconciliationNeverDeletesAReferenceThatWasBoundAfterFailure() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )
    _ = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    try await fixture.store.recordPendingSecretCleanup(referenceIDs: [
        String(servicePasswordRef.dropFirst("secret://".count))
    ])
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let remaining = try await service.reconcilePendingCatalogSecretCleanup()

    #expect(remaining.isEmpty)
    #expect(await deleter.deletedIDs.isEmpty)
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs().isEmpty)
}

@Test func appServiceReconciliationDeletesOnlyStillOrphanedCleanupReferences() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let boundEntry = SecretCatalogEntry(
        id: serviceEntryID,
        indexId: serviceIndexID,
        title: "QNAP 管理后台登录",
        fields: [SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: servicePasswordRef
        )]
    )
    _ = try await fixture.store.updateEntry(boundEntry, expectedRevision: 1)
    let orphanID = String(serviceFailedReplacementRef.dropFirst("secret://".count))
    try await fixture.store.recordPendingSecretCleanup(referenceIDs: [
        String(servicePasswordRef.dropFirst("secret://".count)),
        orphanID
    ])
    let deleter = CatalogDeletingRecorder()
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        recordDeleter: deleter,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let remaining = try await service.reconcilePendingCatalogSecretCleanup()

    #expect(remaining.isEmpty)
    #expect(await deleter.deletedIDs == [orphanID])
    #expect(try await fixture.store.pendingSecretCleanupReferenceIDs().isEmpty)
}

private func serviceCatalogError(
    _ operation: () async throws -> Void
) async -> SecretCatalogAgentError? {
    do {
        try await operation()
        return nil
    } catch let error as SecretCatalogAgentError {
        return error
    } catch {
        return nil
    }
}

private actor RequestCapture {
    private var value: CatalogAgentWriteAccessRequest?

    func set(_ newValue: CatalogAgentWriteAccessRequest) { value = newValue }
    func current() -> CatalogAgentWriteAccessRequest? { value }
}

private func awaitAgentWriteRequest(
    _ captured: RequestCapture
) async throws -> CatalogAgentWriteAccessRequest {
    var request: CatalogAgentWriteAccessRequest?
    for _ in 0..<200 where request == nil {
        request = await captured.current()
        if request == nil {
            try await Task.sleep(for: .milliseconds(10))
        }
    }
    guard let request else {
        throw CancellationError()
    }
    return request
}
