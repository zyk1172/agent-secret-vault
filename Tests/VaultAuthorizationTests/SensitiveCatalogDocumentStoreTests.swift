import CryptoKit
import Foundation
import Testing
@testable import VaultAuthorization
@testable import VaultCore
@testable import VaultService

private let storeIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let storeSecondIndexID = "0123456789ABCDEFGHJKMNPQRX"
private let storeThirdIndexID = "0123456789ABCDEFGHJKMNPQRY"
private let storeEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let storeSecondEntryID = "0123456789ABCDEFGHJKMNPQRV"
private let storeTemporaryEntryID = "0123456789ABCDEFGHJKMNPQRW"
private let storeSecretReference = "secret://0123456789ABCDEFGHJKMNPQRV"
private let storeAlternateSecretReference = "secret://0123456789ABCDEFGHJKMNPQRW"
private let storeThirdSecretReference = "secret://0123456789ABCDEFGHJKMNPQRY"

private struct LegacyCatalogIntegritySidecarV2: Codable {
    let schemaVersion: Int
    let revision: UInt64
    let canonicalSHA256: String
    let hmac: String
    let updatedAt: String
}

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

private final class FailOnceCatalogIntegrityWrite: @unchecked Sendable, CatalogAtomicWriteFaultInjecting {
    private let lock = NSLock()
    private var shouldFail = true

    func beforeAtomicReplace(to url: URL) throws {
        guard url.lastPathComponent == "catalog-integrity.json" else { return }
        lock.lock()
        defer { lock.unlock() }
        guard shouldFail else { return }
        shouldFail = false
        throw NSError(domain: "SVLTTest", code: 1)
    }
}

private func writeManagedV2WithLegacySidecar(
    document: SecretCatalogDocument,
    fixture: CatalogStoreFixture,
    revision: UInt64 = 9
) throws -> (document: Data, sidecar: Data) {
    let v2 = Data(try SensitiveCatalogDocumentCodec.encodeV2(document).utf8)
    let hash = SHA256.hash(data: v2).map { String(format: "%02x", $0) }.joined()
    var payload = Data("SVLT-CATALOG-INTEGRITY-V2\n\(revision)\n\(hash)\n".utf8)
    payload.append(v2)
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: fixture.keyStore.key))
    let sidecar = LegacyCatalogIntegritySidecarV2(
        schemaVersion: 2,
        revision: revision,
        canonicalSHA256: hash,
        hmac: Data(mac).base64EncodedString(),
        updatedAt: "2026-08-25T00:00:00Z"
    )
    let sidecarData = try JSONEncoder().encode(sidecar)
    try v2.write(to: fixture.document, options: [.atomic])
    try sidecarData.write(to: fixture.integrity, options: [.atomic])
    return (v2, sidecarData)
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

@Test func catalogStoreScopesDefaultIntegrityPerDocumentAndIgnoresAStaleLegacySidecar() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let integrityDirectory = fixture.root.appendingPathComponent("CatalogIntegrity", isDirectory: true)
    let legacyIntegrity = integrityDirectory.appendingPathComponent("catalog-integrity.json")
    let firstDocument = fixture.root.appendingPathComponent("first.md")
    let secondDocument = fixture.root.appendingPathComponent("second.md")

    // Simulate a PR #14-era installation whose single sidecar belongs to the
    // first selected document.
    let legacyStore = SensitiveCatalogDocumentStore(
        documentURL: firstDocument,
        integrityURL: legacyIntegrity,
        keyStore: fixture.keyStore
    )
    let first = try await legacyStore.createIndex(title: "第一个目录")

    // The same document can migrate its valid legacy state into the new
    // document-scoped location.
    let scopedFirstStore = SensitiveCatalogDocumentStore(
        documentURL: firstDocument,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: integrityDirectory
    )
    #expect(try await scopedFirstStore.snapshot() == first)

    let secondDocumentModel = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "第二个目录")],
        entries: [SecretCatalogEntry(
            id: storeEntryID,
            indexId: storeIndexID,
            title: "带引用的条目",
            fields: [SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                secretRef: storeSecretReference
            )]
        )]
    )
    try SensitiveCatalogDocumentCodec.encode(secondDocumentModel).write(
        to: secondDocument,
        atomically: true,
        encoding: .utf8
    )

    let scopedSecondStore = SensitiveCatalogDocumentStore(
        documentURL: secondDocument,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: integrityDirectory
    )
    let candidate = try await scopedSecondStore.externalV3AdoptionCandidate()
    #expect(candidate.semanticDiff.referencedSecretRefs == [storeSecretReference])
    await #expect(throws: SensitiveCatalogDocumentStoreError.integrityMissing) {
        _ = try await scopedSecondStore.snapshot()
    }
}

@Test func catalogStoreReconcilesSafeExternalMarkdownWithoutTreatingRawHashAsSemanticState() async throws {
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

    try "\(try String(contentsOf: fixture.document, encoding: .utf8))\n<!-- 用户保留的 Markdown 注释 -->\n"
        .write(to: fixture.document, atomically: true, encoding: .utf8)
    let formattingOnly = try await store.snapshot()
    #expect(formattingOnly.revision == first.revision)
    #expect(formattingOnly.integrity == .verified)

    var sidecar = try JSONDecoder().decode(
        CatalogIntegrityRecord.self,
        from: Data(contentsOf: fixture.integrity)
    )
    #expect(sidecar.revision == first.revision)
    let semanticDigest = sidecar.semanticSHA256

    let markdown = try String(contentsOf: fixture.document, encoding: .utf8)
    try markdown.replacingOccurrences(of: "## QNAP", with: "## NAS 管理").write(
        to: fixture.document,
        atomically: true,
        encoding: .utf8
    )
    let semanticChange = try await store.snapshot()
    #expect(semanticChange.revision == first.revision + 1)
    #expect(semanticChange.document.indexes.first?.title == "NAS 管理")
    #expect(try String(contentsOf: fixture.document, encoding: .utf8).contains("## NAS 管理"))
    sidecar = try JSONDecoder().decode(CatalogIntegrityRecord.self, from: Data(contentsOf: fixture.integrity))
    #expect(sidecar.revision == semanticChange.revision)
    #expect(sidecar.semanticSHA256 != semanticDigest)
}

@Test func catalogStoreAcceptsHandCreatedV3WithoutReferencesAndKeepsMarkdownBytes() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "手工分组")],
        entries: [
            SecretCatalogEntry(
                id: storeEntryID,
                indexId: storeIndexID,
                title: "手工条目",
                notes: "保留 [[部署说明]]"
            )
        ]
    )
    let original = Data(try SensitiveCatalogDocumentCodec.encode(document).utf8)
    try original.write(to: fixture.document, options: [.atomic])

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let accepted = try await store.snapshot()

    #expect(accepted.revision == 1)
    #expect(accepted.integrity == .verified)
    #expect(accepted.document == document)
    #expect(try Data(contentsOf: fixture.document) == original)
    #expect(FileManager.default.fileExists(atPath: fixture.integrity.path))
}

@Test func catalogStoreRequiresExplicitAdoptionForHandCreatedV3WithSecretReferences() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "手工分组")],
        entries: [
            SecretCatalogEntry(
                id: storeEntryID,
                indexId: storeIndexID,
                title: "手工条目",
                fields: [
                    SecretCatalogFieldValue(
                        key: "password",
                        label: "密码",
                        type: .secret,
                        secretRef: storeSecretReference
                    )
                ]
            )
        ]
    )
    let original = Data(try SensitiveCatalogDocumentCodec.encode(document).utf8)
    try original.write(to: fixture.document, options: [.atomic])

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    await #expect(throws: SensitiveCatalogDocumentStoreError.integrityMissing) {
        _ = try await store.snapshot()
    }
    let candidate = try await store.externalV3AdoptionCandidate()
    let adopted = try await store.adoptExternalV3(
        expectedRawSHA256: candidate.rawSHA256,
        expectedSemanticSHA256: candidate.semanticSHA256
    )

    #expect(adopted.revision == 1)
    #expect(adopted.document == document)
    #expect(try Data(contentsOf: fixture.document) == original)
}

@Test func catalogStoreRejectsAnOpaqueReferenceInjectedIntoOrdinaryMetadata() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )

    let first = try await store.createIndex(title: "QNAP")
    let entry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: try #require(first.document.indexes.first?.id),
        title: "QNAP 登录",
        fields: [SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin"))],
        notes: "普通备注"
    )
    _ = try await store.createEntry(entry, expectedRevision: first.revision)

    let original = try String(contentsOf: fixture.document, encoding: .utf8)
    try original.replacingOccurrences(of: "admin", with: storeSecretReference)
        .write(to: fixture.document, atomically: true, encoding: .utf8)

    await #expect(throws: SensitiveCatalogDocumentStoreError.malformedDocument) {
        _ = try await store.snapshot()
    }
    #expect(await store.integrityStatus() == .invalid)
}

@Test func catalogStorePausesHighRiskExternalSecretChangesUntilExplicitAcceptance() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )

    let first = try await store.createIndex(title: "QNAP")
    let indexID = try #require(first.document.indexes.first?.id)
    let entry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: indexID,
        title: "QNAP 登录",
        fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
    )
    let withEntry = try await store.createEntry(entry, expectedRevision: first.revision)
    let bound = try await store.bindSecret(
        storeSecretReference,
        toFieldKey: "password",
        entryID: entry.id,
        expectedRevision: withEntry.revision
    )
    let before = try Data(contentsOf: fixture.document)
    let originalMarkdown = String(decoding: before, as: UTF8.self)
    try originalMarkdown.replacingOccurrences(
        of: storeSecretReference,
        with: storeAlternateSecretReference
    ).write(to: fixture.document, atomically: true, encoding: .utf8)

    #expect(await store.integrityStatus() == .pendingExternalChange)
    let pending = try await store.pendingExternalChange()
    #expect(pending.acceptedRevision == bound.revision)
    #expect(pending.semanticDiff.requiresApproval)
    #expect(pending.semanticDiff.referencedSecretRefs == [storeAlternateSecretReference, storeSecretReference].sorted())
    await #expect(throws: SensitiveCatalogDocumentStoreError.pendingExternalChange) {
        _ = try await store.snapshot()
    }

    let accepted = try await store.acceptPendingExternalChange(
        expectedRevision: pending.acceptedRevision,
        expectedRawSHA256: pending.rawSHA256,
        expectedSemanticSHA256: pending.semanticSHA256
    )
    #expect(accepted.revision == bound.revision + 1)
    #expect(accepted.document.entries.first?.fields.first?.secretRef == storeAlternateSecretReference)
    #expect(try Data(contentsOf: fixture.document) != before)

    let acceptedMarkdown = try String(contentsOf: fixture.document, encoding: .utf8)
    try acceptedMarkdown.replacingOccurrences(
        of: storeAlternateSecretReference,
        with: "password-plaintext-canary"
    ).write(to: fixture.document, atomically: true, encoding: .utf8)
    #expect(await store.integrityStatus() == .invalid)
    await #expect(throws: SensitiveCatalogDocumentStoreError.malformedDocument) {
        _ = try await store.snapshot()
    }
}

@Test func catalogStoreRejectsApprovalWhenThePendingFileChangesAfterApprovalSnapshot() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )

    let first = try await store.createIndex(title: "QNAP")
    let entry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: try #require(first.document.indexes.first?.id),
        title: "QNAP 登录",
        fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: storeSecretReference)]
    )
    _ = try await store.createEntry(entry, expectedRevision: first.revision)

    let original = try String(contentsOf: fixture.document, encoding: .utf8)
    try original.replacingOccurrences(of: storeSecretReference, with: storeAlternateSecretReference)
        .write(to: fixture.document, atomically: true, encoding: .utf8)
    let pendingA = try await store.pendingExternalChange()

    try String(contentsOf: fixture.document, encoding: .utf8)
        .replacingOccurrences(of: storeAlternateSecretReference, with: storeThirdSecretReference)
        .write(to: fixture.document, atomically: true, encoding: .utf8)

    await #expect(throws: SensitiveCatalogDocumentStoreError.revisionConflict) {
        _ = try await store.acceptPendingExternalChange(
            expectedRevision: pendingA.acceptedRevision,
            expectedRawSHA256: pendingA.rawSHA256,
            expectedSemanticSHA256: pendingA.semanticSHA256
        )
    }
    let pendingB = try await store.pendingExternalChange()
    #expect(pendingB.rawSHA256 != pendingA.rawSHA256)
    #expect(pendingB.semanticSHA256 != pendingA.semanticSHA256)
}

@Test func catalogStoreAppliesMixedBatchAsOneRevisionAndOneMarkdownWrite() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let first = try await store.createIndex(title: "原分组")
    let originalIndexID = try #require(first.document.indexes.first?.id)
    let entry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: originalIndexID,
        title: "保留条目",
        fields: [
            SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin"))
        ]
    )
    let withEntry = try await store.createEntry(entry, expectedRevision: first.revision)
    let secondEntry = SecretCatalogEntry(
        id: storeSecondEntryID,
        indexId: originalIndexID,
        title: "待删除条目"
    )
    let withSecondEntry = try await store.createEntry(secondEntry, expectedRevision: withEntry.revision)
    let secondIndex = SecretCatalogIndex(id: storeSecondIndexID, title: "目标分组")
    let withSecondIndex = try await store.updateIndex(
        SecretCatalogIndex(id: originalIndexID, title: "原分组", aliases: ["旧别名"]),
        expectedRevision: withSecondEntry.revision
    )
    let seeded = try await store.createIndex(title: "待删除分组", expectedRevision: withSecondIndex.revision)
    let beforeRevision = seeded.revision

    let mutation = CatalogBatchMutation(operations: [
        .createIndex(secondIndex),
        .createIndex(SecretCatalogIndex(id: storeThirdIndexID, title: "临时分组")),
        .updateIndex(SecretCatalogIndex(id: storeSecondIndexID, title: "目标分组", aliases: ["新别名"])),
        .addField(
            entryID: storeEntryID,
            field: SecretCatalogFieldValue(key: "temporary", label: "临时", type: .text, value: .string("x"))
        ),
        .updateField(
            entryID: storeEntryID,
            field: SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("operator"))
        ),
        .removeField(entryID: storeEntryID, key: "temporary"),
        .moveEntry(id: storeEntryID, toIndexID: storeSecondIndexID),
        .createEntry(SecretCatalogEntry(id: storeTemporaryEntryID, indexId: storeSecondIndexID, title: "临时条目")),
        .updateEntry(SecretCatalogEntry(id: storeTemporaryEntryID, indexId: storeSecondIndexID, title: "更新后临时条目")),
        .deleteEntry(id: storeTemporaryEntryID),
        .deleteEntry(id: storeSecondEntryID),
        .deleteIndex(id: storeThirdIndexID),
        .deleteIndex(id: originalIndexID),
        .deleteIndex(id: seeded.document.indexes.last?.id ?? "")
    ])
    let expectedDocument = try mutation.applying(to: seeded.document)
    let current = try await store.snapshot()
    #expect(current.document == seeded.document)
    let expectedCurrentDocument = try mutation.applying(to: current.document)
    #expect(expectedCurrentDocument == expectedDocument)
    let result = try await store.applyBatch(mutation, expectedRevision: beforeRevision)

    #expect(result.revision == beforeRevision + 1)
    #expect(expectedDocument.indexes.map(\.id) == [storeSecondIndexID])
    #expect(result.document == expectedDocument)
    #expect(result.document.indexes.map(\.id) == [storeSecondIndexID])
    #expect(result.document.indexes.first?.aliases == ["新别名"])
    #expect(result.document.entries.count == 1)
    #expect(result.document.entries.first?.id == storeEntryID)
    #expect(result.document.entries.first?.indexId == storeSecondIndexID)
    #expect(result.document.entries.first?.fields.first?.value == .string("operator"))
}

@Test func catalogStoreSerializesConcurrentMutationsAcrossStoreInstances() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let firstStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let secondStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let first = try await firstStore.createIndex(title: "QNAP")

    func attempt(_ store: SensitiveCatalogDocumentStore, title: String) async -> Bool {
        do {
            _ = try await store.createIndex(title: title, expectedRevision: first.revision)
            return true
        } catch {
            return false
        }
    }

    async let firstAttempt = attempt(firstStore, title: "音乐服务器")
    async let secondAttempt = attempt(secondStore, title: "漫画服务器")
    let outcomes = await (firstAttempt, secondAttempt)
    #expect([outcomes.0, outcomes.1].filter { $0 }.count == 1)

    let reopened = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let snapshot = try await reopened.snapshot()
    #expect(snapshot.revision == 2)
    #expect(snapshot.document.indexes.count == 2)
}

@Test func catalogStoreRejectsUnsupportedLegacyDocumentAndCanBackupItWithoutChangingIt() async throws {
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
    #expect(await store.integrityStatus() == .legacyCatalogUnsupported)
    do {
        _ = try await store.snapshot()
        Issue.record("expected legacy catalog unsupported")
    } catch {
        #expect(error as? SensitiveCatalogDocumentStoreError == .legacyCatalogUnsupported)
    }
    let backup = try await store.backupCurrentDocument()
    #expect(backup?.lastPathComponent.contains("敏感信息.md.bak-") == true)
    #expect(try String(contentsOf: fixture.document, encoding: .utf8) == legacy)
}

@Test func catalogStoreAdoptsValidExternalV2WithBackupAndRevisionOne() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let index = SecretCatalogIndex(id: storeIndexID, title: "QNAP")
    let document = SecretCatalogDocument(indexes: [index], entries: [
        SecretCatalogEntry(
            id: storeEntryID,
            indexId: storeIndexID,
            title: "QNAP 登录",
            fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
                SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: storeSecretReference)
            ]
        )
    ])
    let original = try SensitiveCatalogDocumentCodec.encodeV2(document)
    try original.write(to: fixture.document, atomically: true, encoding: .utf8)

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    #expect(await store.integrityStatus() == .integrityMissing)
    let adopted = try await store.adoptExternalV2()
    #expect(adopted.revision == 1)
    #expect(adopted.integrity == .verified)
    #expect(FileManager.default.fileExists(atPath: fixture.integrity.path))
    #expect(try String(contentsOf: fixture.document, encoding: .utf8).contains(storeSecretReference))
    let backups = try FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
        .filter { $0.lastPathComponent.hasPrefix("敏感信息.md.bak-") }
    #expect(backups.count == 1)
}

@Test func catalogStoreMigratesManagedV2WithThePR13IntegritySidecar() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: storeEntryID,
            indexId: storeIndexID,
            title: "QNAP 登录",
            fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: storeSecretReference)]
        )]
    )
    let v2 = Data(try SensitiveCatalogDocumentCodec.encodeV2(document).utf8)
    let revision: UInt64 = 9
    let hash = SHA256.hash(data: v2).map { String(format: "%02x", $0) }.joined()
    var payload = Data("SVLT-CATALOG-INTEGRITY-V2\n\(revision)\n\(hash)\n".utf8)
    payload.append(v2)
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: fixture.keyStore.key))
    let sidecar = LegacyCatalogIntegritySidecarV2(
        schemaVersion: 2,
        revision: revision,
        canonicalSHA256: hash,
        hmac: Data(mac).base64EncodedString(),
        updatedAt: "2026-08-25T00:00:00Z"
    )
    try v2.write(to: fixture.document, options: [.atomic])
    try JSONEncoder().encode(sidecar).write(to: fixture.integrity, options: [.atomic])

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let adopted = try await store.adoptExternalV2()

    #expect(adopted.revision == 10)
    #expect(adopted.document == document)
    #expect(SensitiveCatalogDocumentCodec.format(try Data(contentsOf: fixture.document)) == .managedV3)
    let backups = try FileManager.default.contentsOfDirectory(at: fixture.root, includingPropertiesForKeys: nil)
    #expect(backups.contains { $0.lastPathComponent.hasPrefix("敏感信息.md.bak-") })
    #expect(backups.contains { $0.lastPathComponent.hasPrefix("catalog-integrity.json.bak-") })
    let current = try JSONDecoder().decode(CatalogIntegrityRecord.self, from: Data(contentsOf: fixture.integrity))
    #expect(current.revision == 10)
    #expect(current.acceptedDocument == document)
    await #expect(throws: SensitiveCatalogDocumentStoreError.revisionConflict) {
        _ = try await store.createIndex(title: "stale revision", expectedRevision: 1)
    }
}

@Test func catalogStoreRejectsLegacyRevisionOverflowWithoutChangingEitherFile() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(id: storeEntryID, indexId: storeIndexID, title: "登录")]
    )
    let original = try writeManagedV2WithLegacySidecar(
        document: document,
        fixture: fixture,
        revision: UInt64.max
    )
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    await #expect(throws: SensitiveCatalogDocumentStoreError.writeFailed) {
        _ = try await store.adoptExternalV2()
    }
    #expect(try Data(contentsOf: fixture.document) == original.document)
    #expect(try Data(contentsOf: fixture.integrity) == original.sidecar)
}

@Test func catalogStoreFollowsAnObsidianRenameWithTheAuthenticatedV3Sidecar() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let directory = fixture.root.appendingPathComponent("CatalogIntegrity", isDirectory: true)
    let oldURL = fixture.root.appendingPathComponent("旧名称.md")
    let newURL = fixture.root.appendingPathComponent("新名称.md")
    let keyStore = fixture.keyStore
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(id: storeEntryID, indexId: storeIndexID, title: "登录")]
    )
    let oldStore = SensitiveCatalogDocumentStore(
        documentURL: oldURL,
        keyStore: keyStore,
        fileManager: .default,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: directory
    )
    _ = try await oldStore.canonicalWrite(document)
    try FileManager.default.copyItem(at: oldURL, to: newURL)

    let newStore = SensitiveCatalogDocumentStore(
        documentURL: newURL,
        keyStore: keyStore,
        fileManager: .default,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: directory
    )
    let migrated = try await newStore.snapshot()
    #expect(migrated.revision == 1)
    #expect(migrated.integrity == .verified)
    let sidecars = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        .filter { $0.pathExtension == "json" && $0.lastPathComponent.hasPrefix("catalog-integrity-") }
    #expect(sidecars.count == 2)

    let changed = SecretCatalogDocument(
        indexes: document.indexes,
        entries: [SecretCatalogEntry(id: storeEntryID, indexId: storeIndexID, title: "登录（已改名）")]
    )
    let updated = try await newStore.updateEntry(changed.entries[0], expectedRevision: migrated.revision)
    #expect(updated.revision == 2)
}

@Test func catalogStoreMigratesTheRealV2LegacyPolicyCatalogOutOfBusinessData() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let policyIndex = SecretCatalogIndex(id: storeSecondIndexID, title: "SVLT 管理规范")
    let legacyAgentPolicy = SecretCatalogEntry(
        id: storeSecondEntryID,
        indexId: policyIndex.id,
        title: "Agent 写入规范",
        notes: "Agent 必须通过 SVLT Catalog 工具写入；普通字段可写入，密码绑定需要批准。"
    )
    let legacyCatalogDescription = SecretCatalogEntry(
        id: storeTemporaryEntryID,
        indexId: policyIndex.id,
        title: "目录说明",
        fields: [
            SecretCatalogFieldValue(key: "purpose", label: "用途", type: .text, value: .string("保存家庭 NAS 登录信息")),
            SecretCatalogFieldValue(key: "placeholderRule", label: "placeholderRule", type: .text, value: .string("未绑定时显示占位符")),
            SecretCatalogFieldValue(key: "relatedNotes", label: "relatedNotes", type: .text, value: .string("[[QNAP NAS]]")),
            SecretCatalogFieldValue(key: "legacyUpdatedAt", label: "legacyUpdatedAt", type: .text, value: .string("2026-08-20T00:00:00Z"))
        ],
        notes: "SVLT 目录使用 Markdown 作为真实主文档。\n相关笔记：[[QNAP NAS]]"
    )
    let businessDocument = SecretCatalogDocument(
        indexes: [
            SecretCatalogIndex(id: storeIndexID, title: "QNAP"),
            policyIndex
        ],
        entries: [
            SecretCatalogEntry(
                id: storeEntryID,
                indexId: storeIndexID,
                title: "QNAP 登录",
                fields: [SecretCatalogFieldValue(
                    key: "password",
                    label: "密码",
                    type: .secret,
                    secretRef: storeSecretReference
                )]
            ),
            legacyAgentPolicy,
            legacyCatalogDescription
        ]
    )
    _ = try writeManagedV2WithLegacySidecar(document: businessDocument, fixture: fixture)

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let adopted = try await store.adoptExternalV2()

    #expect(adopted.document.indexes.map(\.title) == ["QNAP"])
    #expect(adopted.document.entries.map(\.title) == ["QNAP 登录"])
    #expect(adopted.revision == 10)
    #expect(adopted.document.entries.first?.fields.first?.secretRef == storeSecretReference)
    let rewritten = try String(contentsOf: fixture.document, encoding: .utf8)
    #expect(rewritten.contains("SVLT-POLICY-BEGIN"))
    #expect(rewritten.contains("## SVLT 管理规范") == false)
    #expect(rewritten.contains("### Agent 写入规范") == false)
    #expect(rewritten.contains("### 目录说明") == false)
    #expect(rewritten.contains("> [!note]- 目录说明"))
    #expect(rewritten.contains("用途：保存家庭 NAS 登录信息"))
    #expect(rewritten.contains("placeholderRule：未绑定时显示占位符"))
    #expect(rewritten.contains("relatedNotes：[[QNAP NAS]]"))
    #expect(rewritten.contains("legacyUpdatedAt：2026-08-20T00:00:00Z"))
}

@Test func catalogStoreFailsClosedForAnAmbiguousPolicyShapedV2Index() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let ambiguous = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeSecondIndexID, title: "SVLT 管理规范")],
        entries: [SecretCatalogEntry(
            id: storeSecondEntryID,
            indexId: storeSecondIndexID,
            title: "业务条目",
            notes: "这是用户自己的业务数据。"
        )]
    )
    let original = try writeManagedV2WithLegacySidecar(document: ambiguous, fixture: fixture).document
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )

    await #expect(throws: SensitiveCatalogDocumentStoreError.malformedDocument) {
        _ = try await store.adoptExternalV2()
    }
    #expect(try Data(contentsOf: fixture.document) == original)
}

@Test func catalogStoreRollsBackV2MigrationWhenNewSidecarCreationFails() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(id: storeEntryID, indexId: storeIndexID, title: "QNAP 登录")]
    )
    let original = Data(try SensitiveCatalogDocumentCodec.encodeV2(document).utf8)
    try original.write(to: fixture.document, options: [.atomic])

    let failingStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: FailOnceCatalogIntegrityWrite()
    )
    await #expect(throws: SensitiveCatalogDocumentStoreError.writeFailed) {
        _ = try await failingStore.adoptExternalV2()
    }

    #expect(try Data(contentsOf: fixture.document) == original)
    #expect(!FileManager.default.fileExists(atPath: fixture.integrity.path))
    #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("catalog-migration-state.json").path))

    let retryStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let adopted = try await retryStore.adoptExternalV2()
    #expect(adopted.revision == 1)
    #expect(adopted.document == document)
}

@Test func catalogStoreRollsBackV2MigrationAndPreservesThePR13SidecarWhenCommitFails() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: storeEntryID,
            indexId: storeIndexID,
            title: "QNAP 登录",
            fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: storeSecretReference)]
        )]
    )
    let original = try writeManagedV2WithLegacySidecar(document: document, fixture: fixture)

    let failingStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: FailOnceCatalogIntegrityWrite()
    )
    await #expect(throws: SensitiveCatalogDocumentStoreError.writeFailed) {
        _ = try await failingStore.adoptExternalV2()
    }

    #expect(try Data(contentsOf: fixture.document) == original.document)
    #expect(try Data(contentsOf: fixture.integrity) == original.sidecar)

    // The restored legacy sidecar is still valid and can be used for a retry.
    let retryStore = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let adopted = try await retryStore.adoptExternalV2()
    #expect(adopted.revision == 10)
    #expect(adopted.document == document)
}

@Test func catalogStoreRecoversAnInterruptedV2MigrationBeforeServingTheDocument() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(indexes: [SecretCatalogIndex(id: storeIndexID, title: "QNAP")])
    let original = Data(try SensitiveCatalogDocumentCodec.encodeV2(document).utf8)
    let rendered = Data(try SensitiveCatalogDocumentCodec.encode(document).utf8)
    let backup = fixture.root.appendingPathComponent("敏感信息.md.bak-crash-test")
    try original.write(to: fixture.document, options: [.atomic])
    try original.write(to: backup, options: [.atomic])
    try rendered.write(to: fixture.document, options: [.atomic])

    let journal: [String: Any] = [
        "documentBackupPath": backup.path,
        "documentPath": fixture.document.path,
        "expectedDocumentSHA256": "expected-document",
        "expectedIntegritySHA256": "expected-integrity",
        "integrityBackupPath": NSNull(),
        "integrityPath": fixture.integrity.path,
        "phase": "committing",
        "schemaVersion": 1,
        "targetRevision": 1
    ]
    let journalData = try JSONSerialization.data(withJSONObject: journal, options: [.prettyPrinted, .sortedKeys])
    try journalData.write(to: fixture.root.appendingPathComponent("catalog-migration-state.json"), options: [.atomic])

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    await #expect(throws: SensitiveCatalogDocumentStoreError.integrityMissing) {
        _ = try await store.snapshot()
    }
    #expect(try Data(contentsOf: fixture.document) == original)
    #expect(!FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("catalog-migration-state.json").path))
}

@Test func catalogStoreDoesNotAdoptMalformedExternalV2OrChangeTheFile() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let malformed = """
    \(SensitiveCatalogDocumentCodec.v2Marker)
    # 敏感信息

    ## QNAP
    ```json
    {"schema":"svlt.catalog.index/v2","id":"bad"}
    ```
    """
    try malformed.write(to: fixture.document, atomically: true, encoding: .utf8)
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    do {
        _ = try await store.adoptExternalV2()
        Issue.record("expected malformed v2 adoption failure")
    } catch {
        #expect(error as? SensitiveCatalogDocumentStoreError == .malformedDocument)
    }
    #expect(try String(contentsOf: fixture.document, encoding: .utf8) == malformed)
    #expect(!FileManager.default.fileExists(atPath: fixture.integrity.path))
}

@Test func catalogAdoptionKeepsPolicyBlockOutsideCatalogModelAndPreservesReferences() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let credentialIndex = SecretCatalogIndex(id: storeIndexID, title: "QNAP")
    let credentialEntry = SecretCatalogEntry(
        id: storeEntryID,
        indexId: storeIndexID,
        title: "QNAP 登录",
        fields: [
            SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                searchable: false,
                secretRef: storeSecretReference
            )
        ]
    )
    let document = SecretCatalogDocument(
        indexes: [credentialIndex],
        entries: [credentialEntry]
    )
    let originalReferences = Set(document.entries.flatMap { entry in
        entry.fields.compactMap(\.secretRef)
    })
    let originalMarkdown = try SensitiveCatalogDocumentCodec.encodeV2(document)
    try originalMarkdown.write(to: fixture.document, atomically: true, encoding: .utf8)

    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    let adopted = try await store.adoptExternalV2()

    let adoptedReferences = Set(adopted.document.entries.flatMap { entry in
        entry.fields.compactMap(\.secretRef)
    })
    #expect(adopted.revision == 1)
    #expect(adopted.integrity == .verified)
    #expect(adoptedReferences == originalReferences)
    #expect(adopted.document.indexes.count == 1)
    #expect(adopted.document.entries.count == 1)
    #expect(!adopted.document.indexes.contains { $0.title == "SVLT 管理规范" })
    #expect(!adopted.document.entries.contains { $0.title == "Agent 写入规范" })

    let rewritten = try String(contentsOf: fixture.document, encoding: .utf8)
    #expect(rewritten.contains("SVLT-POLICY-BEGIN"))
    #expect(rewritten.contains("SVLT 智能体写入规范"))
    #expect(rewritten.contains(storeSecretReference))
    #expect(FileManager.default.fileExists(atPath: fixture.integrity.path))
}

@Test func catalogStoreRejectsTamperedCleanupRecordBeforeItCanBecomeDeletionAuthority() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    _ = try await store.createIndex(title: "QNAP")
    try await store.recordPendingSecretCleanup(referenceIDs: [String(storeSecretReference.dropFirst("secret://".count))])

    let cleanupURL = fixture.integrity
        .deletingLastPathComponent()
        .appendingPathComponent("\(fixture.integrity.lastPathComponent).cleanup.json")
    var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: cleanupURL)) as? [String: Any])
    object["referenceIDs"] = [String(storeAlternateSecretReference.dropFirst("secret://".count))]
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .prettyPrinted])
        .write(to: cleanupURL, options: [.atomic])

    await #expect(throws: SensitiveCatalogDocumentStoreError.invalidIntegrity) {
        _ = try await store.pendingSecretCleanupReferenceIDs()
    }
}

@Test func catalogStoreDoesNotSilentlyAcceptASecretReferenceInUnmanagedMarkdown() async throws {
    let fixture = try CatalogStoreFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(
        documentURL: fixture.document,
        integrityURL: fixture.integrity,
        keyStore: fixture.keyStore
    )
    _ = try await store.createIndex(title: "QNAP")
    let original = try String(contentsOf: fixture.document, encoding: .utf8)
    let injected = original.replacingOccurrences(
        of: "<!-- SVLT-INDEX ",
        with: "> 说明：secret://0123456789ABCDEFGHJKMNPQRS\n\n<!-- SVLT-INDEX ",
        options: [],
        range: original.range(of: "<!-- SVLT-INDEX ")
    )
    try injected.write(to: fixture.document, atomically: true, encoding: .utf8)

    await #expect(throws: SensitiveCatalogDocumentStoreError.malformedDocument) {
        _ = try await store.snapshot()
    }
}
