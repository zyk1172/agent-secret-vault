import CryptoKit
import Foundation

public enum RecordMigrationFailureStage: CaseIterable, Equatable, Sendable {
    case beforeWrite
    case afterTemporaryWrite
    case beforeFinalRename
}

public struct RecordMigrationOutput: Equatable, Sendable {
    public let plaintext: Data
    public let label: String?
    public let policy: SecretPolicy

    public init(
        plaintext: Data,
        label: String?,
        policy: SecretPolicy
    ) {
        self.plaintext = plaintext
        self.label = label
        self.policy = policy
    }
}

public enum RecordMigratorError: Error, Equatable, Sendable {
    case verificationFailed
}

public struct RecordMigrator: Sendable {
    public typealias FailureInjector = @Sendable (RecordMigrationFailureStage) throws -> Void
    public typealias Migration = @Sendable (Data, EncryptedRecord) throws -> RecordMigrationOutput

    private let baseDirectory: URL
    private let failureInjector: FailureInjector
    private let cipher: VaultCipher

    public init(
        baseDirectory: URL,
        failureInjector: @escaping FailureInjector = { _ in }
    ) {
        self.baseDirectory = baseDirectory
        self.failureInjector = failureInjector
        cipher = VaultCipher()
    }

    @discardableResult
    public func migrate(
        id: String,
        masterKey: SymmetricKey,
        _ migration: Migration
    ) async throws -> EncryptedRecord {
        let store = FileRecordStore(baseDirectory: baseDirectory)
        let current = try await store.latest(id: id)
        let plaintext = try cipher.decrypt(current, masterKey: masterKey)
        let output = try migration(plaintext, current)
        let migrated = try cipher.encrypt(
            output.plaintext,
            id: current.id,
            version: current.recordVersion + 1,
            label: output.label,
            policy: output.policy,
            masterKey: masterKey
        )

        try writeVerifiedMigration(migrated, masterKey: masterKey)
        return migrated
    }

    private func writeVerifiedMigration(
        _ record: EncryptedRecord,
        masterKey: SymmetricKey
    ) throws {
        try validate(id: record.id)
        guard record.recordVersion > 0 else {
            throw FileRecordStoreError.invalidVersion
        }

        let directory = recordDirectory(id: record.id)
        try createDirectoryRejectingSymlinks(directory)

        let finalURL = versionURL(id: record.id, version: record.recordVersion)
        guard !FileManager.default.fileExists(atPath: finalURL.path) else {
            throw FileRecordStoreError.versionAlreadyExists
        }

        try failureInjector(.beforeWrite)

        let temporaryURL = directory.appendingPathComponent(".migration-\(UUID().uuidString).tmp")
        do {
            try Self.encode(record).write(to: temporaryURL, options: [.atomic])
            try rejectSymlink(at: temporaryURL)
            try failureInjector(.afterTemporaryWrite)

            let verified = try Self.decode(Data(contentsOf: temporaryURL))
            guard verified == record else {
                throw RecordMigratorError.verificationFailed
            }
            _ = try cipher.decrypt(verified, masterKey: masterKey)

            try failureInjector(.beforeFinalRename)
            try FileManager.default.moveItem(at: temporaryURL, to: finalURL)
            try rejectSymlink(at: finalURL)
        } catch {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw error
        }
    }

    private func validate(id: String) throws {
        guard (try? SecretReference("secret://\(id)")).map(\.id) == id else {
            throw FileRecordStoreError.invalidID
        }
    }

    private func recordDirectory(id: String) -> URL {
        baseDirectory
            .appendingPathComponent(".agent-secret-vault", isDirectory: true)
            .appendingPathComponent("records", isDirectory: true)
            .appendingPathComponent(id, isDirectory: true)
    }

    private func versionURL(id: String, version: Int) -> URL {
        recordDirectory(id: id)
            .appendingPathComponent(Self.versionFileName(version: version))
    }

    private func createDirectoryRejectingSymlinks(_ directory: URL) throws {
        let sidecarDirectory = baseDirectory
            .appendingPathComponent(".agent-secret-vault", isDirectory: true)
        let recordsDirectory = sidecarDirectory
            .appendingPathComponent("records", isDirectory: true)

        try createSingleDirectoryRejectingSymlink(sidecarDirectory)
        try createSingleDirectoryRejectingSymlink(recordsDirectory)
        try createSingleDirectoryRejectingSymlink(directory)
    }

    private func createSingleDirectoryRejectingSymlink(_ directory: URL) throws {
        if FileManager.default.fileExists(atPath: directory.path) {
            try rejectSymlink(at: directory)

            let values = try directory.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else {
                throw CocoaError(.fileWriteFileExists)
            }
        } else {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false
            )
            try rejectSymlink(at: directory)
        }
    }

    private func rejectSymlink(at url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw FileRecordStoreError.symlinkRejected
        }
    }

    private static func versionFileName(version: Int) -> String {
        String(format: "%08d.json", version)
    }

    private static func encode(_ record: EncryptedRecord) throws -> Data {
        try makeEncoder().encode(record)
    }

    private static func decode(_ data: Data) throws -> EncryptedRecord {
        try makeDecoder().decode(EncryptedRecord.self, from: data)
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(date.timeIntervalSinceReferenceDate.bitPattern)
        }
        return encoder
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let bitPattern = try container.decode(UInt64.self)
            return Date(timeIntervalSinceReferenceDate: Double(bitPattern: bitPattern))
        }
        return decoder
    }
}
