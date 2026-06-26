import CryptoKit
import Foundation

public enum VaultCryptoError: Error, Equatable, Sendable {
    case integrityFailed
    case randomGenerationFailed
}

public struct VaultCipher: Sendable {
    public init() {}

    public func encrypt(
        _ plaintext: Data,
        id: String,
        version: Int,
        label: String?,
        policy: SecretPolicy,
        masterKey: SymmetricKey
    ) throws -> EncryptedRecord {
        let dataKeyBytes = try RandomBytes.generate(count: 32)
        let dataKey = SymmetricKey(data: dataKeyBytes)
        let authenticatedData = Self.authenticatedData(for: id)

        let sealedPlaintext = try AES.GCM.seal(
            plaintext,
            using: dataKey,
            authenticating: authenticatedData
        )
        let wrappedDataKey = try AES.GCM.seal(
            dataKeyBytes,
            using: masterKey,
            authenticating: authenticatedData
        )
        let now = Date()

        return EncryptedRecord(
            formatVersion: VaultFormat.current,
            id: id,
            recordVersion: version,
            ciphertext: sealedPlaintext.ciphertext,
            nonce: sealedPlaintext.nonce.data,
            tag: sealedPlaintext.tag,
            wrappedDataKey: wrappedDataKey.ciphertext,
            wrappedDataKeyNonce: wrappedDataKey.nonce.data,
            wrappedDataKeyTag: wrappedDataKey.tag,
            label: label,
            policy: policy,
            createdAt: now,
            updatedAt: now
        )
    }

    public func decrypt(
        _ record: EncryptedRecord,
        masterKey: SymmetricKey
    ) throws -> Data {
        guard record.formatVersion == VaultFormat.current else {
            throw VaultCryptoError.integrityFailed
        }

        let authenticatedData = Self.authenticatedData(for: record.id)

        do {
            let wrappedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.wrappedDataKeyNonce),
                ciphertext: record.wrappedDataKey,
                tag: record.wrappedDataKeyTag
            )
            let dataKeyBytes = try AES.GCM.open(
                wrappedBox,
                using: masterKey,
                authenticating: authenticatedData
            )
            let dataKey = SymmetricKey(data: dataKeyBytes)
            let ciphertextBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )

            return try AES.GCM.open(
                ciphertextBox,
                using: dataKey,
                authenticating: authenticatedData
            )
        } catch {
            throw VaultCryptoError.integrityFailed
        }
    }

    private static func authenticatedData(for id: String) -> Data {
        Data("\(id):\(VaultFormat.current)".utf8)
    }
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
