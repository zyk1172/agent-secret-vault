import Foundation
import Testing
import VaultCore
import VaultIPC
@testable import AgentSecretVaultApp

private let storedReferencedID = "0123456789ABCDEFGHJKMNPQRS"
private let storedUnreferencedID = "01J33333333333333333333333"
private let missingReferencedID = "01J44444444444444444444444"

@Test func vaultAppServicesScanOrphansComparesMarkdownReferencesWithStoredRecords() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("VaultAppServicesOrphanScanTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    try await store.save(makeOrphanScanRecord(id: storedReferencedID, version: 1))
    try await store.save(makeOrphanScanRecord(id: storedUnreferencedID, version: 1))

    let services = VaultAppServices(
        textEncryptor: UnusedOrphanScanTextEncryptor(),
        activeRoot: directory,
        recordLister: store
    )

    let result = try await services.scanOrphans(markdownReferences: [
        "secret://\(storedReferencedID)",
        "secret://\(missingReferencedID)"
    ])

    #expect(result == OrphanScanResult(
        missingRecords: ["secret://\(missingReferencedID)"],
        unreferencedRecords: ["secret://\(storedUnreferencedID)"]
    ))
}

@Test func vaultAppServicesScanOrphansThrowsWhenRecordListingIsUnavailable() async throws {
    let services = VaultAppServices(
        textEncryptor: UnusedOrphanScanTextEncryptor(),
        activeRoot: nil
    )

    await #expect(throws: VaultAppServicesOrphanScanError.scanUnavailable) {
        _ = try await services.scanOrphans(markdownReferences: [
            "secret://\(missingReferencedID)"
        ])
    }
}

private struct UnusedOrphanScanTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://\(storedReferencedID)")
    }
}

private func makeOrphanScanRecord(id: String, version: Int) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: VaultFormat.current,
        id: id,
        recordVersion: version,
        ciphertext: Data([0x20, UInt8(version)]),
        nonce: Data([0x21, UInt8(version)]),
        tag: Data([0x22, UInt8(version)]),
        wrappedDataKey: Data([0x23, UInt8(version)]),
        wrappedDataKeyNonce: Data([0x24, UInt8(version)]),
        wrappedDataKeyTag: Data([0x25, UInt8(version)]),
        label: "orphan-scan-\(version)",
        policy: .credential,
        createdAt: Date(timeIntervalSinceReferenceDate: 3_000_000),
        updatedAt: Date(timeIntervalSinceReferenceDate: 3_000_000 + Double(version))
    )
}
