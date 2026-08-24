import CryptoKit
import Darwin
import Foundation
import VaultAuthorization
import VaultCore

public enum SensitiveCatalogDocumentStoreError: Error, Equatable, Sendable {
    case noSelectedDocument
    case malformedDocument
    case migrationRequired
    case symlinkRejected
    case integrityMissing
    case externalModification
    case invalidIntegrity
    case revisionConflict
    case invalidOperation
    case referenceSetChanged
    case writeFailed
}

public enum SensitiveCatalogIntegrityStatus: String, Codable, Equatable, Sendable {
    case uninitialized
    case verified
    case migrationRequired = "MIGRATION_REQUIRED"
    case integrityMissing = "INTEGRITY_MISSING"
    case externalModification = "EXTERNAL_CATALOG_MODIFICATION"
    case invalid = "CATALOG_INVALID"
}

public struct CatalogIntegrityRecord: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let canonicalSHA256: String
    public let hmac: String
    public let updatedAt: String

    public init(
        schemaVersion: Int = SecretCatalogDocument.currentSchemaVersion,
        revision: UInt64,
        canonicalSHA256: String,
        hmac: String,
        updatedAt: String
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.canonicalSHA256 = canonicalSHA256
        self.hmac = hmac
        self.updatedAt = updatedAt
    }
}

public struct SensitiveCatalogSnapshot: Equatable, Sendable {
    public let document: SecretCatalogDocument
    public let revision: UInt64
    public let integrity: SensitiveCatalogIntegrityStatus

    public init(
        document: SecretCatalogDocument,
        revision: UInt64,
        integrity: SensitiveCatalogIntegrityStatus
    ) {
        self.document = document
        self.revision = revision
        self.integrity = integrity
    }
}

/// The only writer for a managed `敏感信息.md`.  It owns validation,
/// optimistic concurrency, atomic replacement and the integrity sidecar.
public actor SensitiveCatalogDocumentStore {
    private let fileManager: FileManager
    private let keyStore: any CatalogIntegrityKeyStoring
    private let suppliedIntegrityURL: URL?
    private var documentURL: URL?

    public init(
        documentURL: URL? = nil,
        integrityURL: URL? = nil,
        keyStore: any CatalogIntegrityKeyStoring = KeychainCatalogIntegrityKeyStore(),
        fileManager: FileManager = .default
    ) {
        self.documentURL = documentURL?.standardizedFileURL
        self.suppliedIntegrityURL = integrityURL?.standardizedFileURL
        self.keyStore = keyStore
        self.fileManager = fileManager
    }

    public func selectDocument(at url: URL?) throws {
        if let url {
            guard url.pathExtension.lowercased() == "md" else {
                throw SensitiveCatalogDocumentStoreError.malformedDocument
            }
            try assertSafeParent(url)
            if fileManager.fileExists(atPath: url.path) {
                try assertSafeFile(url)
            }
            documentURL = url.standardizedFileURL
        } else {
            documentURL = nil
        }
    }

    public func selectedDocumentURL() -> URL? { documentURL }

    public func snapshot() throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        guard fileManager.fileExists(atPath: url.path) else {
            return SensitiveCatalogSnapshot(
                document: SecretCatalogDocument(),
                revision: 0,
                integrity: .uninitialized
            )
        }
        return try verifiedSnapshot(at: url)
    }

    public func validate() throws -> SensitiveCatalogSnapshot {
        try snapshot()
    }

    public func integrityStatus() -> SensitiveCatalogIntegrityStatus {
        do {
            return try snapshot().integrity
        } catch SensitiveCatalogDocumentStoreError.migrationRequired {
            return .migrationRequired
        } catch SensitiveCatalogDocumentStoreError.integrityMissing {
            return .integrityMissing
        } catch SensitiveCatalogDocumentStoreError.externalModification {
            return .externalModification
        } catch {
            return .invalid
        }
    }

    @discardableResult
    public func canonicalWrite(
        _ document: SecretCatalogDocument,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try document.validate()
        let current = try mutationBase(expectedRevision: expectedRevision)
        return try write(document, previousRevision: current.revision)
    }

    /// Commits an App-confirmed legacy migration.  It deliberately bypasses
    /// the normal verified snapshot because the old file has no v2 sidecar,
    /// but it re-scans the current file immediately before writing so a stale
    /// preview cannot replace a changed document or drop a reference.
    @discardableResult
    public func commitMigration(
        _ preview: SecretCatalogMigrationPreview
    ) throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        try assertSafeFile(url)
        let currentReferences = MarkdownReferenceScanner.references(
            in: try String(contentsOf: url, encoding: .utf8)
        ).sorted()
        guard currentReferences == preview.referencesBefore,
              preview.referenceSetPreserved,
              !preview.requiresUserResolution
        else {
            throw SensitiveCatalogDocumentStoreError.referenceSetChanged
        }
        _ = try backupCurrentDocument()
        return try write(preview.document, previousRevision: 0)
    }

    @discardableResult
    public func createIndex(
        title: String,
        aliases: [String] = [],
        tags: [String] = [],
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        let index = try SecretCatalogIndex.generated(title: title, aliases: aliases, tags: tags)
        return try mutate(expectedRevision: expectedRevision) { document in
            guard !document.indexes.contains(where: { $0.id == index.id }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return SecretCatalogDocument(
                indexes: document.indexes + [index],
                entries: document.entries
            )
        }
    }

    @discardableResult
    public func updateIndex(
        _ index: SecretCatalogIndex,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.indexes.firstIndex(where: { $0.id == index.id }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            var indexes = document.indexes
            indexes[offset] = index
            return SecretCatalogDocument(indexes: indexes, entries: document.entries)
        }
    }

    @discardableResult
    public func deleteIndex(
        id: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == id }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return SecretCatalogDocument(
                indexes: document.indexes.filter { $0.id != id },
                entries: document.entries.filter { $0.indexId != id }
            )
        }
    }

    @discardableResult
    public func createEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == entry.indexId }),
                  !document.entries.contains(where: { $0.id == entry.id })
            else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return SecretCatalogDocument(
                indexes: document.indexes,
                entries: document.entries + [entry]
            )
        }
    }

    @discardableResult
    public func updateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entry.id }),
                  document.indexes.contains(where: { $0.id == entry.indexId })
            else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            var entries = document.entries
            entries[offset] = entry
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func moveEntry(
        id: String,
        toIndexID: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == toIndexID }),
                  let offset = document.entries.firstIndex(where: { $0.id == id })
            else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let old = document.entries[offset]
            var entries = document.entries
            entries[offset] = SecretCatalogEntry(
                id: old.id,
                indexId: toIndexID,
                title: old.title,
                type: old.type,
                aliases: old.aliases,
                endpoints: old.endpoints,
                fields: old.fields,
                notes: old.notes,
                tags: old.tags,
                schema: old.schema
            )
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func deleteEntry(
        id: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.entries.contains(where: { $0.id == id }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return SecretCatalogDocument(
                indexes: document.indexes,
                entries: document.entries.filter { $0.id != id }
            )
        }
    }

    @discardableResult
    public func addField(
        _ field: SecretCatalogFieldValue,
        toEntryID entryID: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entryID }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let old = document.entries[offset]
            guard !old.fields.contains(where: { $0.key == field.key }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            var entries = document.entries
            entries[offset] = replacingFields(in: old, with: old.fields + [field])
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func updateField(
        _ field: SecretCatalogFieldValue,
        inEntryID entryID: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == field.key }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            var fields = old.fields
            fields[fieldOffset] = field
            var entries = document.entries
            entries[entryOffset] = replacingFields(in: old, with: fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func removeField(
        key: String,
        fromEntryID entryID: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let old = document.entries[entryOffset]
            guard old.fields.contains(where: { $0.key == key }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            var entries = document.entries
            entries[entryOffset] = replacingFields(in: old, with: old.fields.filter { $0.key != key })
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func bindSecret(
        _ secretRef: String,
        toFieldKey key: String,
        entryID: String,
        expectedRevision: UInt64? = nil
    ) throws -> SensitiveCatalogSnapshot {
        guard (try? SecretReference(secretRef)) != nil else {
            throw SensitiveCatalogDocumentStoreError.invalidOperation
        }
        return try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == key }),
                  old.fields[fieldOffset].type.isSecret
            else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let oldField = old.fields[fieldOffset]
            var fields = old.fields
            fields[fieldOffset] = SecretCatalogFieldValue(
                key: oldField.key,
                label: oldField.label,
                type: oldField.type,
                agentVisible: oldField.agentVisible,
                searchable: oldField.searchable,
                secretRef: secretRef
            )
            var entries = document.entries
            entries[entryOffset] = replacingFields(in: old, with: fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    /// Creates the timestamped backup used by the App migration wizard.
    public func backupCurrentDocument() throws -> URL? {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        try assertSafeFile(url)
        let parent = url.deletingLastPathComponent()
        let timestamp = backupTimestampString(Date())
        let backup = parent.appendingPathComponent(
            "\(url.lastPathComponent).bak-\(timestamp)-\(UUID().uuidString.lowercased())"
        )
        do {
            try Data(contentsOf: url).write(to: backup, options: [.withoutOverwriting])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
            try fsyncFile(at: backup)
            return backup
        } catch {
            try? fileManager.removeItem(at: backup)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    /// Replaces an externally edited file only after strict v2 parsing.  The
    /// caller must make the user-visible import decision; this is never called
    /// by search automatically.
    @discardableResult
    public func verifyAndImportExternal() throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        try assertSafeFile(url)
        let document = try decodeDocument(at: url)
        let oldRevision = (try? readIntegrityRecord()).map(\.revision) ?? 0
        return try write(document, previousRevision: oldRevision)
    }

    @discardableResult
    public func restoreV2Document(from backupURL: URL) throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        try assertSafeFile(backupURL)
        let data = try Data(contentsOf: backupURL)
        let document: SecretCatalogDocument
        do {
            document = try SensitiveCatalogDocumentCodec.decode(data)
        } catch {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }
        let oldRevision = (try? readIntegrityRecord()).map(\.revision) ?? 0
        _ = url
        return try write(document, previousRevision: oldRevision)
    }

    private func mutate(
        expectedRevision: UInt64?,
        _ transform: (SecretCatalogDocument) throws -> SecretCatalogDocument
    ) throws -> SensitiveCatalogSnapshot {
        let base = try mutationBase(expectedRevision: expectedRevision)
        let document = try transform(base.document)
        return try write(document, previousRevision: base.revision)
    }

    private func mutationBase(expectedRevision: UInt64?) throws -> SensitiveCatalogSnapshot {
        let current = try snapshot()
        if let expectedRevision, expectedRevision != current.revision {
            throw SensitiveCatalogDocumentStoreError.revisionConflict
        }
        return current
    }

    private func verifiedSnapshot(at url: URL) throws -> SensitiveCatalogSnapshot {
        try assertSafeFile(url)
        let data = try Data(contentsOf: url)
        let record: CatalogIntegrityRecord
        do {
            record = try readIntegrityRecord()
        } catch SensitiveCatalogDocumentStoreError.integrityMissing {
            do {
                _ = try SensitiveCatalogDocumentCodec.decode(data)
            } catch SecretCatalogValidationError.legacyDocument,
                    SecretCatalogValidationError.invalidMarker {
                throw SensitiveCatalogDocumentStoreError.migrationRequired
            } catch {
                // A v2 file without a sidecar remains unavailable; the
                // caller must explicitly validate/import it.
            }
            throw SensitiveCatalogDocumentStoreError.integrityMissing
        }
        try verify(data: data, record: record)
        let document = try decodeDocument(data: data)
        return SensitiveCatalogSnapshot(document: document, revision: record.revision, integrity: .verified)
    }

    private func decodeDocument(at url: URL) throws -> SecretCatalogDocument {
        try decodeDocument(data: Data(contentsOf: url))
    }

    private func decodeDocument(data: Data) throws -> SecretCatalogDocument {
        do {
            return try SensitiveCatalogDocumentCodec.decode(data)
        } catch SecretCatalogValidationError.legacyDocument,
                SecretCatalogValidationError.invalidMarker {
            throw SensitiveCatalogDocumentStoreError.migrationRequired
        } catch {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }
    }

    private func write(
        _ document: SecretCatalogDocument,
        previousRevision: UInt64
    ) throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        let data: Data
        do {
            data = try SensitiveCatalogDocumentCodec.canonicalData(document)
        } catch {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }
        do {
            guard try SensitiveCatalogDocumentCodec.decode(data) == document else {
                throw SensitiveCatalogDocumentStoreError.malformedDocument
            }
            _ = try makeIntegrityRecord(data: data, revision: previousRevision + 1, hash: sha256Hex(data))
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }

        do {
            try atomicWrite(data, to: url)
            let revision = previousRevision + 1
            let hash = sha256Hex(data)
            let record = try makeIntegrityRecord(data: data, revision: revision, hash: hash)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: document, revision: revision, integrity: .verified)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func makeIntegrityRecord(
        data: Data,
        revision: UInt64,
        hash: String
    ) throws -> CatalogIntegrityRecord {
        let key: Data
        do {
            key = try keyStore.loadOrCreateKey()
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        let mac = HMAC<SHA256>.authenticationCode(
            for: integrityPayload(data: data, revision: revision, hash: hash),
            using: SymmetricKey(data: key)
        )
        return CatalogIntegrityRecord(
            revision: revision,
            canonicalSHA256: hash,
            hmac: Data(mac).base64EncodedString(),
            updatedAt: iso8601String(Date())
        )
    }

    private func verify(data: Data, record: CatalogIntegrityRecord) throws {
        guard record.schemaVersion == SecretCatalogDocument.currentSchemaVersion,
              record.revision > 0,
              let expectedMAC = Data(base64Encoded: record.hmac)
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let hash = sha256Hex(data)
        guard hash == record.canonicalSHA256 else {
            throw SensitiveCatalogDocumentStoreError.externalModification
        }

        let key: Data
        do {
            key = try keyStore.loadOrCreateKey()
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
        let computedMAC = Data(HMAC<SHA256>.authenticationCode(
            for: integrityPayload(data: data, revision: record.revision, hash: hash),
            using: SymmetricKey(data: key)
        ))
        guard constantTimeEqual(computedMAC, expectedMAC) else {
            throw SensitiveCatalogDocumentStoreError.externalModification
        }
    }

    private func readIntegrityRecord() throws -> CatalogIntegrityRecord {
        let url = try integrityURL()
        guard fileManager.fileExists(atPath: url.path) else {
            throw SensitiveCatalogDocumentStoreError.integrityMissing
        }
        try assertSafeFile(url)
        do {
            return try JSONDecoder().decode(CatalogIntegrityRecord.self, from: Data(contentsOf: url))
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func atomicWriteIntegrity(_ record: CatalogIntegrityRecord) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(record)
        try atomicWrite(data, to: try integrityURL())
    }

    private func integrityPayload(data: Data, revision: UInt64, hash: String) -> Data {
        var payload = Data("SVLT-CATALOG-INTEGRITY-V2\n\(revision)\n\(hash)\n".utf8)
        payload.append(data)
        return payload
    }

    private func integrityURL() throws -> URL {
        if let suppliedIntegrityURL { return suppliedIntegrityURL }
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = appSupport.appendingPathComponent("AgentSecretVault", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return directory.appendingPathComponent("catalog-integrity.json")
    }

    private func atomicWrite(_ data: Data, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        try assertSafeParent(url)
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temporary = parent.appendingPathComponent(".svlt-catalog-\(UUID().uuidString).tmp")
        do {
            try data.write(to: temporary, options: [.withoutOverwriting])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            try fsyncFile(at: temporary)

            if fileManager.fileExists(atPath: url.path) {
                try assertSafeFile(url)
                _ = try fileManager.replaceItemAt(url, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: url)
            }
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            try fsyncFile(at: url)
            try fsyncDirectory(at: parent)
        } catch {
            try? fileManager.removeItem(at: temporary)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func assertSafeParent(_ url: URL) throws {
        let parent = url.deletingLastPathComponent()
        guard fileManager.fileExists(atPath: parent.path) else { return }
        let values = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }
        guard values.isSymbolicLink != true else {
            throw SensitiveCatalogDocumentStoreError.symlinkRejected
        }
    }

    private func assertSafeFile(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw SensitiveCatalogDocumentStoreError.malformedDocument
        }
        guard values.isSymbolicLink != true else {
            throw SensitiveCatalogDocumentStoreError.symlinkRejected
        }
    }

    private func fsyncFile(at url: URL) throws {
        let descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func fsyncDirectory(at url: URL) throws {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY)
        guard descriptor >= 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    private func iso8601String(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private func backupTimestampString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }
}

private func replacingFields(
    in entry: SecretCatalogEntry,
    with fields: [SecretCatalogFieldValue]
) -> SecretCatalogEntry {
    SecretCatalogEntry(
        id: entry.id,
        indexId: entry.indexId,
        title: entry.title,
        type: entry.type,
        aliases: entry.aliases,
        endpoints: entry.endpoints,
        fields: fields,
        notes: entry.notes,
        tags: entry.tags,
        schema: entry.schema
    )
}
