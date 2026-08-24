import CryptoKit
import Foundation
import Testing
import VaultCore
@testable import VaultService

@Test func legacyMigrationVerifierAcceptsRecordsEncryptedWithTheCandidateKey() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("SVLT-MigrationVerifier-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

    let key = Data(repeating: 0x5A, count: 32)
    let recordID = "0123456789ABCDEFGHJKMNPQRS"
    let record = try VaultCipher().encrypt(
        Data(repeating: 0xA1, count: 32),
        id: recordID,
        version: 1,
        label: nil,
        policy: .read,
        masterKey: SymmetricKey(data: key),
        formatVersion: VaultFormat.legacyV1
    )
    let store = FileRecordStore(baseDirectory: root)
    try await store.save(record)

    try await LegacyVaultMigrationVerifier().verifyExistingRecords(
        masterKey: key,
        in: store
    )
}

@Test func legacyMigrationVerifierRejectsTheWrongCandidateWithoutCreatingOutput() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("SVLT-MigrationVerifier-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

    let key = Data(repeating: 0x6A, count: 32)
    let recordID = "0123456789ABCDEFGHJKMNPQRS"
    let record = try VaultCipher().encrypt(
        Data(repeating: 0xB2, count: 32),
        id: recordID,
        version: 1,
        label: nil,
        policy: .read,
        masterKey: SymmetricKey(data: key),
        formatVersion: VaultFormat.current
    )
    let store = FileRecordStore(baseDirectory: root)
    try await store.save(record)

    await #expect(throws: LegacyVaultMigrationError.integrityFailed) {
        try await LegacyVaultMigrationVerifier().verifyExistingRecords(
            masterKey: Data(repeating: 0x7A, count: 32),
            in: store
        )
    }
    #expect(try await store.recordIDs() == [recordID])
}
