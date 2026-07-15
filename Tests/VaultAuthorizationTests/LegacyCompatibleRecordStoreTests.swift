import CryptoKit
import Foundation
import Testing
import VaultCore
@testable import AgentSecretVaultApp

@Test func compatibleRecordStoreReadsLegacyRecordWhenNoIndexIsSelected() async throws {
    let directory = try makeCompatibilityTemporaryDirectory()
    let legacyDirectory = directory.appendingPathComponent("Legacy Vault", isDirectory: true)
    try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: true)
    let legacy = FileRecordStore(baseDirectory: legacyDirectory)
    let record = makeCompatibilityRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 1)
    try await legacy.save(record)

    let store = LegacyCompatibleRecordStore(primary: MarkdownSensitiveIndexStore(), legacy: legacy)

    #expect(try await store.latest(id: record.id) == record)
    #expect(try await store.versions(id: record.id) == [1])
    #expect(try await store.recordIDs() == [record.id])
}

@Test func compatibleRecordStoreDecryptsLegacyRecordWhenNoIndexIsSelected() async throws {
    let directory = try makeCompatibilityTemporaryDirectory()
    let legacyDirectory = directory.appendingPathComponent("Legacy Vault", isDirectory: true)
    try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: true)
    let legacy = FileRecordStore(baseDirectory: legacyDirectory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 4, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_LEGACY_COMPATIBILITY".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await legacy.save(record)

    let store = LegacyCompatibleRecordStore(primary: MarkdownSensitiveIndexStore(), legacy: legacy)
    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let plaintext = try await resolver.resolve(reference: "secret://\(record.id)", masterKey: key)

    #expect(String(decoding: plaintext, as: UTF8.self) == "ASV_CANARY_LEGACY_COMPATIBILITY")
}

@Test func compatibleRecordStorePrefersSelectedIndexOverLegacyRecord() async throws {
    let directory = try makeCompatibilityTemporaryDirectory()
    let index = MarkdownSensitiveIndexStore(indexURL: directory.appendingPathComponent("Sensitive Information.md"))
    let legacyDirectory = directory.appendingPathComponent("Legacy Vault", isDirectory: true)
    try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: true)
    let legacy = FileRecordStore(baseDirectory: legacyDirectory)
    let legacyRecord = makeCompatibilityRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 1)
    let indexedRecord = makeCompatibilityRecord(id: legacyRecord.id, version: 2)
    try await legacy.save(legacyRecord)
    try await index.save(indexedRecord)

    let store = LegacyCompatibleRecordStore(primary: index, legacy: legacy)

    #expect(try await store.latest(id: legacyRecord.id) == indexedRecord)
    #expect(try await store.versions(id: legacyRecord.id) == [2])
}

private func makeCompatibilityTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("LegacyCompatibleRecordStoreTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func makeCompatibilityRecord(id: String, version: Int) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: VaultFormat.current,
        id: id,
        recordVersion: version,
        ciphertext: Data([0x01, UInt8(version)]),
        nonce: Data([0x02, UInt8(version)]),
        tag: Data([0x03, UInt8(version)]),
        wrappedDataKey: Data([0x04, UInt8(version)]),
        wrappedDataKeyNonce: Data([0x05, UInt8(version)]),
        wrappedDataKeyTag: Data([0x06, UInt8(version)]),
        label: "Legacy secret",
        policy: .credential,
        createdAt: Date(timeIntervalSinceReferenceDate: 1_234_567.25),
        updatedAt: Date(timeIntervalSinceReferenceDate: 1_234_567.5 + Double(version))
    )
}
