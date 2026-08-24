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

@Test func appServiceRequiresAppControlledAuthorizationAndUsesActiveStructureMode() async throws {
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

    let disabledError = await serviceCatalogError {
        _ = try await service.createCatalogDraft(request)
    }
    #expect(disabledError == .agentWriteNotAllowed)

    _ = try await fixture.agentAuthorization.enable(mode: .structure, duration: 60)
    let draft = try await service.createCatalogDraft(request)
    let result = try await service.commitCatalogDraft(draft, expectedRevision: draft.baseRevision)
    #expect(result.entry?.title == "Komga")
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
    _ = try await fixture.agentAuthorization.enable(mode: .structure, duration: 60)

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
