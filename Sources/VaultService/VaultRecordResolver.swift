import CryptoKit
import Foundation
import VaultCore
import VaultIPC

public struct VaultRecordResolver: Sendable {
    private let recordStore: any RecordStore
    private let cipher: VaultCipher

    public init(recordStore: any RecordStore, cipher: VaultCipher = VaultCipher()) {
        self.recordStore = recordStore
        self.cipher = cipher
    }

    public func resolve(reference: String, masterKey: SymmetricKey) async throws -> Data {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        return try cipher.decrypt(record, masterKey: masterKey)
    }

    public func metadata(reference: String) async throws -> SecretReferenceMetadata {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        return SecretReferenceMetadata(
            reference: parsed.description,
            policy: record.policy,
            label: record.label,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )
    }

    public func resolve(
        reference: String,
        masterKeyProvider: @Sendable (SecretPolicy) async throws -> SymmetricKey
    ) async throws -> Data {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        let masterKey = try await masterKeyProvider(record.policy)
        return try cipher.decrypt(record, masterKey: masterKey)
    }
}
