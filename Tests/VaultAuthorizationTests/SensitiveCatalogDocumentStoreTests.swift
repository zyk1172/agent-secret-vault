import Foundation
import Testing
@testable import VaultAuthorization
@testable import VaultCore
@testable import VaultService

private let storeIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let storeEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let storeSecretReference = "secret://0123456789ABCDEFGHJKMNPQRV"

private struct CatalogStoreFixture {
    let root: URL
    let document: URL
    let integrity: URL
    let keyStore: FixedCatalogIntegrityKeyStore

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-catalog-store-\(UUID().uuidString)", isDirectory: true)
        document = root.appendingPathComponent("敏感信息.md")
        integrity = root.appendingPathComponent("catalog-integrity.json")
        keyStore = try FixedCatalogIntegrityKeyStore(key: Data(repeating: 7, count: 32))
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }
}

@Test func catalogStoreWritesCanonicalDocumentAndIntegritySidecar() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )

    let first = try await store.createIndex(title: "QNAP")
    #expect(first.revision == 1)
    #expect(first.integrity == .verified)
    #expect(FileManager.default.fileExists(atPath: fixture.document.path))
    #expect(FileManager.default.fileExists(atPath: fixture.integrity.path))

    let index = try #require(first.document.indexes.first)
    let entry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: index.id,
        title: "QNAP 管理后台",
        fields: [
            SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
            SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: storeSecretReference)
        ]
    )
    let second = try await store.createEntry(entry, expectedRevision: first.revision)
    #expect(second.revision == 2)

    let reopened = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let snapshot = try await reopened.snapshot()
    #expect(snapshot == second)
    let markdown = try String(contentsOf: fixture.document, encoding: .utf8)
    #expect(markdown.contains(SensitiveCatalogDocumentCodec.marker))
    #expect(markdown.contains(storeSecretReference))
    #expect(!markdown.contains("password-plaintext-canary"))
}

@Test func catalogStoreRejectsExternalModificationAndRevisionConflicts() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let first = try await store.createIndex(title: "QNAP")
    do {
        _ = try await store.createIndex(title: "Komga", expectedRevision: 0)
        Issue.record("expected a revision conflict")
    } catch {
        #expect(error as? SensitiveCatalogDocumentStoreError == .revisionConflict)
    }

    try "\(try String(contentsOf: fixture.document, encoding: .utf8))\n<!-- external -->\n"
        .write(to: fixture.document, atomically: true, encoding: .utf8)
    #expect(await store.integrityStatus() == .externalModification)
    do {
        _ = try await store.snapshot()
        Issue.record("expected external modification detection")
    } catch {
        #expect(error as? SensitiveCatalogDocumentStoreError == .externalModification)
    }
    _ = first
}

@Test func catalogStoreFailsClosedForLegacyDocumentAndCanBackupIt() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let legacy = """
    # 敏感信息
    ## QNAP
    密码: \(storeSecretReference)
    """
    try legacy.write(to: fixture.document, atomically: true, encoding: .utf8)

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    #expect(await store.integrityStatus() == .migrationRequired)
    do {
        _ = try await store.snapshot()
        Issue.record("expected migration required")
    } catch {
        #expect(error as? SensitiveCatalogDocumentStoreError == .migrationRequired)
    }
    let backup = try await store.backupCurrentDocument()
    #expect(backup?.lastPathComponent.contains("敏感信息.md.bak-") == true)
    #expect(try String(contentsOf: fixture.document, encoding: .utf8) == legacy)
}
