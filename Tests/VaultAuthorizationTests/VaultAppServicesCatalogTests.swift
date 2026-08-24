import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultService

private let serviceIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let serviceEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let servicePasswordRef = "secret://0123456789ABCDEFGHJKMNPQRS"

private struct CatalogTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference(servicePasswordRef)
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
    let leaseManager: CatalogWriteLeaseManager

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
        leaseManager = CatalogWriteLeaseManager()
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
        catalogLeaseManager: fixture.leaseManager
    )

    let result = try await service.searchSecrets(query: "QNAP", field: nil, limit: 10)
    #expect(result.status == .found)
    #expect(result.matches.first?.entry.fields.contains { $0.key == "username" && $0.value == .string("admin") } == true)
    #expect(result.matches.first?.entry.fields.contains { $0.key == "password" && $0.secretRef == nil } == true)
}

@Test func appServiceRejectsUnissuedLeaseAndCommitsIssuedStructureLease() async throws {
    let fixture = try await CatalogFixture()
    defer { fixture.cleanup() }
    let service = VaultAppServices(
        textEncryptor: CatalogTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: fixture.store,
        catalogSelectionManifestURL: fixture.selectionURL,
        catalogLeaseManager: fixture.leaseManager
    )
    let forged = try CatalogWriteLease.generated(scope: .structure)
    let request = CatalogDraftRequest(indexID: serviceIndexID, title: "Komga")

    let leaseError = await serviceCatalogError {
        _ = try await service.createCatalogDraft(request, lease: forged)
    }
    #expect(leaseError == .invalidLease)

    let lease = try await fixture.leaseManager.issue(scope: .structure, duration: 60)
    let draft = try await service.createCatalogDraft(request, lease: lease)
    let result = try await service.commitCatalogDraft(draft, expectedRevision: draft.baseRevision, lease: lease)
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
        catalogLeaseManager: fixture.leaseManager
    )
    let lease = try await fixture.leaseManager.issue(scope: .structure, duration: 60)
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
        _ = try await service.createCatalogDraft(request, lease: lease)
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
        catalogLeaseManager: fixture.leaseManager
    )
    let lease = try await fixture.leaseManager.issue(scope: .structure, duration: 60)

    let approvalError = await serviceCatalogError {
        _ = try await service.bindCatalogExistingSecret(
            entryID: serviceEntryID,
            key: "password",
            secretRef: servicePasswordRef,
            expectedRevision: 1,
            lease: lease
        )
    }
    #expect(approvalError == .approvalRequired)
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
