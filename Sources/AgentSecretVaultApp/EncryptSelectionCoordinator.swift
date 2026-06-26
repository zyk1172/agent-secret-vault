import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore

public enum EncryptSelectionResult: Equatable, Sendable {
    case replaced(SecretReference)
    case unlinkedRecord(SecretReference)
}

public enum EncryptSelectionError: Error, Equatable, Sendable {
    case emptyPlaintext
    case labelContainsPlaintext
    case invalidDeviceKeySize(Int)
}

public protocol SecretIDGenerating: Sendable {
    func nextID() throws -> String
}

public protocol EncryptSelectionCoordinating: Sendable {
    func encryptAndReplace(
        plaintext: String,
        label: String?,
        policy: SecretPolicy
    ) async throws -> EncryptSelectionResult
}

public struct EncryptSelectionCoordinator: EncryptSelectionCoordinating {
    private let recordStore: any RecordStore
    private let selectionReplacer: any SelectionReplacing
    private let deviceKeyStore: any DeviceKeyStoring
    private let idGenerator: any SecretIDGenerating
    private let cipher: VaultCipher

    public init(
        recordStore: any RecordStore,
        selectionReplacer: any SelectionReplacing,
        deviceKeyStore: any DeviceKeyStoring,
        idGenerator: any SecretIDGenerating = RandomSecretIDGenerator(),
        cipher: VaultCipher = VaultCipher()
    ) {
        self.recordStore = recordStore
        self.selectionReplacer = selectionReplacer
        self.deviceKeyStore = deviceKeyStore
        self.idGenerator = idGenerator
        self.cipher = cipher
    }

    public func encryptAndReplace(
        plaintext: String,
        label: String?,
        policy: SecretPolicy
    ) async throws -> EncryptSelectionResult {
        guard !plaintext.isEmpty else {
            throw EncryptSelectionError.emptyPlaintext
        }

        if let label, label.contains(plaintext) {
            throw EncryptSelectionError.labelContainsPlaintext
        }

        let id = try idGenerator.nextID()
        let reference = try SecretReference("secret://\(id)")
        let keyData = try await deviceKeyStore.deviceKey(reason: "Encrypt selected secret")
        guard keyData.count == 32 else {
            throw EncryptSelectionError.invalidDeviceKeySize(keyData.count)
        }

        let record = try cipher.encrypt(
            Data(plaintext.utf8),
            id: reference.id,
            version: 1,
            label: label,
            policy: policy,
            masterKey: SymmetricKey(data: keyData)
        )

        try await recordStore.save(record)

        do {
            try await selectionReplacer.replaceSelection(with: reference.description)
            return .replaced(reference)
        } catch {
            return .unlinkedRecord(reference)
        }
    }
}

public struct RandomSecretIDGenerator: SecretIDGenerating {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let idLength = 26

    public init() {}

    public func nextID() throws -> String {
        let bytes = try RandomBytes.generate(count: Self.idLength)
        let characters = bytes.map { byte in
            Self.alphabet[Int(byte) % Self.alphabet.count]
        }

        return String(characters)
    }
}
