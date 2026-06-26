import CryptoKit
import Foundation
import Testing
@testable import VaultCore

private let migrationRecordID = "01J22222222222222222222222"

@Test(arguments: RecordMigrationFailureStage.allCases)
func migrationFailureLeavesPriorVersionDecryptable(stage: RecordMigrationFailureStage) async throws {
    let baseDirectory = try makeMigrationTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xC3, count: 32))
    let cipher = VaultCipher()
    let priorRecord = try cipher.encrypt(
        Data("prior plaintext".utf8),
        id: migrationRecordID,
        version: 1,
        label: "prior",
        policy: .credential,
        masterKey: masterKey
    )
    try await store.save(priorRecord)

    let migrator = RecordMigrator(baseDirectory: baseDirectory) { currentStage in
        if currentStage == stage {
            throw InjectedMigrationFailure()
        }
    }

    do {
        _ = try await migrator.migrate(
            id: migrationRecordID,
            masterKey: masterKey
        ) { plaintext, current in
            #expect(String(decoding: plaintext, as: UTF8.self) == "prior plaintext")
            return RecordMigrationOutput(
                plaintext: Data("migrated plaintext".utf8),
                label: current.label,
                policy: current.policy
            )
        }
        Issue.record("Expected migration to fail at \(stage).")
    } catch is InjectedMigrationFailure {
        let latest = try await store.latest(id: migrationRecordID)
        #expect(latest.recordVersion == 1)
        #expect(try cipher.decrypt(latest, masterKey: masterKey) == Data("prior plaintext".utf8))
    }
}

@Test func successfulMigrationCreatesNextDecryptableVersion() async throws {
    let baseDirectory = try makeMigrationTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xD4, count: 32))
    let cipher = VaultCipher()
    let priorRecord = try cipher.encrypt(
        Data("prior plaintext".utf8),
        id: migrationRecordID,
        version: 1,
        label: "prior",
        policy: .credential,
        masterKey: masterKey
    )
    try await store.save(priorRecord)

    let migrated = try await RecordMigrator(baseDirectory: baseDirectory).migrate(
        id: migrationRecordID,
        masterKey: masterKey
    ) { plaintext, _ in
        #expect(String(decoding: plaintext, as: UTF8.self) == "prior plaintext")
        return RecordMigrationOutput(
            plaintext: Data("migrated plaintext".utf8),
            label: "migrated",
            policy: .externalSend
        )
    }

    #expect(migrated.recordVersion == 2)
    #expect(try await store.versions(id: migrationRecordID) == [1, 2])
    #expect(try cipher.decrypt(try await store.latest(id: migrationRecordID), masterKey: masterKey) == Data("migrated plaintext".utf8))
}

private struct InjectedMigrationFailure: Error {}

private func makeMigrationTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("RecordMigratorTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}
