import CryptoKit
import Foundation
import VaultCore
import VaultIPC

public enum VaultRecordBindingError: Error, Equatable, Sendable {
    case invalidReference
    case invalidDestination
    case tooManyDestinations
    case tooManyProtocols
}

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
        return metadata(for: parsed, record: record)
    }

    /// Adds one exact destination/protocol binding and re-seals the record so
    /// the binding stays covered by the record's authenticated data. The
    /// method never returns or logs the resolved plaintext.
    public func bindDestination(
        reference: String,
        destination: String,
        protocolType: SecretOperationProtocol,
        masterKey: SymmetricKey,
        now: Date = Date()
    ) async throws -> SecretReferenceMetadata {
        let parsed: SecretReference
        do {
            parsed = try SecretReference(reference)
        } catch {
            throw VaultRecordBindingError.invalidReference
        }

        let normalizedDestination = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedDestination.isEmpty,
              normalizedDestination.utf8.count <= 512,
              normalizedDestination.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F })
        else {
            throw VaultRecordBindingError.invalidDestination
        }

        let current = try await recordStore.latest(id: parsed.id)
        var destinations = current.allowedDestinations
        if !containsDestination(
            normalizedDestination,
            in: destinations,
            protocolType: protocolType
        ) {
            destinations.append(normalizedDestination)
        }
        guard destinations.count <= 32 else {
            throw VaultRecordBindingError.tooManyDestinations
        }

        var protocols = current.allowedProtocols
        if !protocols.contains(where: { $0.caseInsensitiveCompare(protocolType.rawValue) == .orderedSame }) {
            protocols.append(protocolType.rawValue)
        }
        guard protocols.count <= 16 else {
            throw VaultRecordBindingError.tooManyProtocols
        }

        guard destinations != current.allowedDestinations || protocols != current.allowedProtocols else {
            return metadata(for: parsed, record: current)
        }

        let updated = try cipher.rebind(
            current,
            allowedDestinations: destinations,
            allowedProtocols: protocols,
            masterKey: masterKey,
            updatedAt: now
        )
        try await recordStore.save(updated)
        return metadata(for: parsed, record: updated)
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

    private func metadata(
        for reference: SecretReference,
        record: EncryptedRecord
    ) -> SecretReferenceMetadata {
        SecretReferenceMetadata(
            reference: reference.description,
            policy: record.policy,
            label: record.label,
            allowedDestinations: record.allowedDestinations,
            allowedProtocols: record.allowedProtocols,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )
    }

    private func containsDestination(
        _ destination: String,
        in existing: [String],
        protocolType: SecretOperationProtocol
    ) -> Bool {
        if protocolType == .http || protocolType == .https {
            let expectedScheme = protocolType.rawValue
            guard let normalized = SecretOperationDescriptor.normalizeHTTPOrigin(
                destination,
                expectedScheme: expectedScheme,
                requireExplicitPort: true
            ) else {
                return existing.contains(destination)
            }
            return existing.contains {
                SecretOperationDescriptor.normalizeHTTPOrigin(
                    $0,
                    expectedScheme: expectedScheme,
                    requireExplicitPort: true
                ) == normalized
            }
        }

        let normalized = SecretOperationDescriptor.normalizeDestination(destination)
        return existing.contains {
            SecretOperationDescriptor.normalizeDestination($0) == normalized
        }
    }
}
