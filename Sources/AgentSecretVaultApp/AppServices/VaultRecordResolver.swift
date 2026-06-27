import CryptoKit
import Foundation
import VaultCore

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
}
