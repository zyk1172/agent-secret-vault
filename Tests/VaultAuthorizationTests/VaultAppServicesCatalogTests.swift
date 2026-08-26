import Foundation
import Testing
import VaultAuthorization
import VaultCore
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
    #expect(await approver.count == 1)
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
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

    init() async throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("svlt-service-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        documentURL = root.appendingPathComponent("敏感信息.md")
        selectionURL = root.appendingPathComponent("selection.json")
        store = SensitiveCatalogDocumentStore(
            documentURL: documentURL,
            integrityURL: root.appendingPathComponent("catalog-integrity.json"),
            keyStore: try FixedCatalogIntegrityKeyStore(key: Data(repeating: 7, count: 32))
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
