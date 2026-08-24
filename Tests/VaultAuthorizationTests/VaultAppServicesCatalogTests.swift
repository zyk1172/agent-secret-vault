import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultService

private let serviceIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let serviceEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let servicePasswordRef = "secret://0123456789ABCDEFGHJKMNPQRS"
private let servicePrivateKeyRef = "secret://0123456789ABCDEFGHJKMNPQRV"

private struct CatalogTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference(servicePasswordRef)
    }
}

private struct CatalogMultiSecretEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        let reference = plaintext == "password-canary" ? servicePasswordRef : servicePrivateKeyRef
        return try SecretReference(reference)
    }
}

private enum CatalogMetadataStoreError: Error {
    case unexpectedWrite
    case missingRecord
}

private struct CatalogMetadataRecordStore: RecordStore {
    let record: EncryptedRecord

    func save(_: EncryptedRecord) async throws {
        throw CatalogMetadataStoreError.unexpectedWrite
    }

    func latest(id: String) async throws -> EncryptedRecord {
        guard id == record.id else {
            throw CatalogMetadataStoreError.missingRecord
        }
        return record
    }

    func versions(id: String) async throws -> [Int] {
        guard id == record.id else {
            throw CatalogMetadataStoreError.missingRecord
        }
        return [record.recordVersion]
    }
}

private actor CatalogApprovalRecorder: OperationApproving {
    private(set) var count = 0

    func approve(summary _: String) async throws {
        count += 1
    }
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
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    let request = CatalogDraftRequest(indexID: serviceIndexID, title: "Komga")

    let draft = try await service.createCatalogDraft(request)
    let result = try await service.commitCatalogDraft(draft, expectedRevision: draft.baseRevision)
    #expect(result.entry?.title == "Komga")
}

@Test func appServiceHonorsAppControlledSafeWriteDisable() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )
    await fixture.agentAuthorization.revoke()

    let error = await serviceCatalogError {
        _ = try await service.createCatalogDraft(CatalogDraftRequest(indexID: serviceIndexID, title: "Komga"))
    }
    #expect(error == .agentWriteNotAllowed)
}

@Test func appServiceKeepsAgentCatalogWriteToggleOperational() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    #expect(await service.catalogAgentWriteStatus().mode == .safe)
    await service.revokeCatalogAgentWrite()
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
    let enabled = try await service.setCatalogAgentWriteMode(mode: .safe, duration: nil)
    #expect(enabled.mode == .safe)
    #expect(await service.catalogAgentWriteStatus().mode == .safe)
    await service.revokeCatalogAgentWrite()
    #expect(await service.catalogAgentWriteStatus().mode == .disabled)
}

@Test func agentSafeCreateEntryWritesMetadataAndEmptySecretPlaceholderWithoutLease() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogAgentWriteAuthorization: fixture.agentAuthorization
    )

    let result = try await service.createCatalogEntry(CatalogDraftRequest(
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
    _ = try await fixture.agentAuthorization.enable(mode: .structure, duration: 60)
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
