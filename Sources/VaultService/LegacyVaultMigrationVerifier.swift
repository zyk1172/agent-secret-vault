import CryptoKit
import Foundation
import VaultCore

/// Verifies the legacy relationship between the device wrapping key and the
/// record master key without returning plaintext to the caller.
public enum LegacyVaultMigrationError: Error, Equatable, Sendable {
    case invalidMasterKeySize(Int)
    case noRecords
    case integrityFailed
}

public struct LegacyVaultMigrationVerifier: Sendable {
    private let cipher = VaultCipher()

    public init() {}

    /// Decrypts and immediately wipes each selected record in memory. This is
    /// deliberately a precondition for creating a new master-key wrapper.
    /// A wrong Keychain candidate therefore cannot create a valid-looking but
    /// unusable `master-key.json`.
    public func verifyExistingRecords<Store: RecordStore & RecordListing>(
        masterKey: Data,
        in recordStore: Store,
        requireAtLeastOne: Bool = true
    ) async throws {
        guard masterKey.count == 32 else {
            throw LegacyVaultMigrationError.invalidMasterKeySize(masterKey.count)
        }

        let recordIDs: [String]
        do {
            recordIDs = try await recordStore.recordIDs()
        } catch {
            throw LegacyVaultMigrationError.integrityFailed
        }
        guard !requireAtLeastOne || !recordIDs.isEmpty else {
            throw LegacyVaultMigrationError.noRecords
        }

        do {
            for id in recordIDs {
                let record = try await recordStore.latest(id: id)
                do {
                    var plaintext = try cipher.decrypt(
                        record,
                        masterKey: SymmetricKey(data: masterKey)
                    )
                    plaintext.resetBytes(in: 0..<plaintext.count)
                }
            }
        } catch let error as LegacyVaultMigrationError {
            throw error
        } catch {
            throw LegacyVaultMigrationError.integrityFailed
        }
    }

    /// Verifies one usable record without turning every ordinary unlock into
    /// a full-vault scan. A corrupt first record does not hide a later usable
    /// record; a wrong key still fails after all candidates have been tried.
    public func verifyAtLeastOneExistingRecord<Store: RecordStore & RecordListing>(
        masterKey: Data,
        in recordStore: Store,
        requireAtLeastOne: Bool = true
    ) async throws {
        guard masterKey.count == 32 else {
            throw LegacyVaultMigrationError.invalidMasterKeySize(masterKey.count)
        }

        let recordIDs: [String]
        do {
            recordIDs = try await recordStore.recordIDs()
        } catch {
            throw LegacyVaultMigrationError.integrityFailed
        }
        guard !recordIDs.isEmpty else {
            if requireAtLeastOne {
                throw LegacyVaultMigrationError.noRecords
            }
            return
        }

        let key = SymmetricKey(data: masterKey)
        for id in recordIDs {
            do {
                let record = try await recordStore.latest(id: id)
                var plaintext = try cipher.decrypt(record, masterKey: key)
                plaintext.resetBytes(in: 0..<plaintext.count)
                return
            } catch {
                continue
            }
        }
        throw LegacyVaultMigrationError.integrityFailed
    }
}
