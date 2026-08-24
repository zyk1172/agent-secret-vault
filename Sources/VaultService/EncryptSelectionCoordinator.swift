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
    case invalidMasterKeySize(Int)
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

public protocol DestinationBindingTextEncrypting: TextEncrypting {
    func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    ) async throws -> SecretReference
}

public struct EncryptSelectionCoordinator: EncryptSelectionCoordinating, DestinationBindingTextEncrypting {
    private let recordStore: any RecordStore
    private let selectionReplacer: any SelectionReplacing
    private let masterKeyProvider: @Sendable (SecretPolicy, String) async throws -> Data
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
        self.masterKeyProvider = { _, reason in
            try await deviceKeyStore.deviceKey(reason: reason)
        }
        self.idGenerator = idGenerator
        self.cipher = cipher
    }

    public init(
        recordStore: any RecordStore,
        selectionReplacer: any SelectionReplacing,
        masterKeyProvider: @escaping @Sendable (SecretPolicy, String) async throws -> Data,
        idGenerator: any SecretIDGenerating = RandomSecretIDGenerator(),
        cipher: VaultCipher = VaultCipher()
    ) {
        self.recordStore = recordStore
        self.selectionReplacer = selectionReplacer
        self.masterKeyProvider = masterKeyProvider
        self.idGenerator = idGenerator
        self.cipher = cipher
    }

    public func encryptAndReplace(
        plaintext: String,
        label: String?,
        policy: SecretPolicy
    ) async throws -> EncryptSelectionResult {
        let reference = try await encryptText(plaintext, label: label, policy: policy)

        do {
            try await selectionReplacer.replaceSelection(with: reference.description)
            return .replaced(reference)
        } catch {
            return .unlinkedRecord(reference)
        }
    }

    public func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy
    ) async throws -> SecretReference {
        try await encryptText(
            plaintext,
            label: label,
            policy: policy,
            allowedDestinations: [],
            allowedProtocols: []
        )
    }

    public func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    ) async throws -> SecretReference {
        guard !plaintext.isEmpty else {
            throw EncryptSelectionError.emptyPlaintext
        }

        if let label, label.contains(plaintext) {
            throw EncryptSelectionError.labelContainsPlaintext
        }

        let id = try idGenerator.nextID()
        let reference = try SecretReference("secret://\(id)")
        let keyData = try await masterKeyProvider(policy, "Encrypt selected secret")
        guard keyData.count == 32 else {
            throw EncryptSelectionError.invalidMasterKeySize(keyData.count)
        }

        let record = try cipher.encrypt(
            Data(plaintext.utf8),
            id: reference.id,
            version: 1,
            label: label,
            policy: policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            masterKey: SymmetricKey(data: keyData)
        )

        try await recordStore.save(record)
        return reference
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
