import Foundation

public struct SensitiveIndexMetadata: Equatable, Sendable {
    public let category: String
    public let title: String
    public let source: SensitiveSourceLocation?

    public init(category: String, title: String, source: SensitiveSourceLocation?) {
        self.category = category
        self.title = title
        self.source = source
    }
}

public enum MarkdownSensitiveIndexStoreError: Error, Equatable, Sendable {
    case noSelectedIndex
    case symlinkRejected
    case malformedIndex
    case invalidRecord
    case recordNotFound(String)
    case replacementVersionIsNotNewer
    case legacyRecordConflict(String)
    case verificationFailed
}

public actor MarkdownSensitiveIndexStore: RecordStore, RecordListing {
    private var indexURL: URL?

    public init(indexURL: URL? = nil) {
        self.indexURL = indexURL
    }

    public func selectIndex(at url: URL?) throws {
        if let url {
            try assertSafeIndexURL(url)
        }
        indexURL = url
    }

    public func selectedIndexURL() -> URL? {
        indexURL
    }

    public func initializeSelectedIndex() throws {
        let url = try requiredIndexURL()
        if FileManager.default.fileExists(atPath: url.path) {
            try assertSafeIndexURL(url)
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else {
                throw MarkdownSensitiveIndexStoreError.malformedIndex
            }
            guard !(try Data(contentsOf: url)).isEmpty else {
                try writeEntries([])
                return
            }
            _ = try readEntries()
            return
        }
        try writeEntries([])
    }

    public func entries() throws -> [IndexedEncryptedRecord] {
        try readEntries()
    }

    public func save(_ record: EncryptedRecord) throws {
        try save(record, metadata: defaultMetadata(for: record))
    }

    public func save(_ record: EncryptedRecord, metadata: SensitiveIndexMetadata) throws {
        guard record.recordVersion > 0,
              (try? SecretReference("secret://\(record.id)"))?.id == record.id
        else {
            throw MarkdownSensitiveIndexStoreError.invalidRecord
        }

        var updatedEntries = try readEntries()
        if let index = updatedEntries.firstIndex(where: { $0.record.id == record.id }) {
            let existing = updatedEntries[index]
            guard record.recordVersion > existing.record.recordVersion else {
                throw MarkdownSensitiveIndexStoreError.replacementVersionIsNotNewer
            }

            updatedEntries[index] = IndexedEncryptedRecord(
                displayID: existing.displayID,
                category: existing.category,
                title: existing.title,
                source: existing.source,
                record: record
            )
        } else {
            updatedEntries.append(
                IndexedEncryptedRecord(
                    displayID: try nextDisplayID(in: updatedEntries),
                    category: metadata.category,
                    title: metadata.title,
                    source: metadata.source,
                    record: record
                )
            )
        }

        try writeEntries(updatedEntries)
    }

    public func updateMetadata(id: String, metadata: SensitiveIndexMetadata) throws {
        var updatedEntries = try readEntries()
        guard let index = updatedEntries.firstIndex(where: { $0.record.id == id }) else {
            throw MarkdownSensitiveIndexStoreError.recordNotFound(id)
        }

        let existing = updatedEntries[index]
        updatedEntries[index] = IndexedEncryptedRecord(
            displayID: existing.displayID,
            category: metadata.category,
            title: metadata.title,
            source: metadata.source,
            record: existing.record
        )
        try writeEntries(updatedEntries)
    }

    public func latest(id: String) throws -> EncryptedRecord {
        guard let entry = try readEntries().first(where: { $0.record.id == id }) else {
            throw MarkdownSensitiveIndexStoreError.recordNotFound(id)
        }
        return entry.record
    }

    public func versions(id: String) throws -> [Int] {
        guard let entry = try readEntries().first(where: { $0.record.id == id }) else {
            return []
        }
        return [entry.record.recordVersion]
    }

    public func recordIDs() throws -> [String] {
        try readEntries().map(\ .record.id).sorted()
    }

    /// Imports encrypted legacy records without decrypting or rewriting their envelopes.
    @discardableResult
    public func importLegacyRecords(from legacyStore: FileRecordStore) async throws -> Int {
        let legacyIDs = try await legacyStore.recordIDs()
        guard !legacyIDs.isEmpty else {
            return 0
        }

        var updatedEntries = try readEntries()
        var importedCount = 0

        for id in legacyIDs {
            let legacyRecord = try await legacyStore.latest(id: id)
            if let index = updatedEntries.firstIndex(where: { $0.record.id == id }) {
                let existing = updatedEntries[index]
                if existing.record == legacyRecord || existing.record.recordVersion > legacyRecord.recordVersion {
                    continue
                }
                guard legacyRecord.recordVersion > existing.record.recordVersion else {
                    throw MarkdownSensitiveIndexStoreError.legacyRecordConflict(id)
                }

                updatedEntries[index] = IndexedEncryptedRecord(
                    displayID: existing.displayID,
                    category: existing.category,
                    title: existing.title,
                    source: existing.source,
                    record: legacyRecord
                )
            } else {
                updatedEntries.append(
                    IndexedEncryptedRecord(
                        displayID: try nextDisplayID(in: updatedEntries),
                        category: legacyRecord.policy.rawValue,
                        title: legacyRecord.label ?? "Imported legacy record",
                        source: nil,
                        record: legacyRecord
                    )
                )
            }
            importedCount += 1
        }

        if importedCount > 0 {
            try writeEntries(updatedEntries)
        }
        return importedCount
    }

    private func readEntries() throws -> [IndexedEncryptedRecord] {
        let url = try requiredIndexURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }
        try assertSafeIndexURL(url)

        let values = try url.resourceValues(forKeys: [.isRegularFileKey])
        guard values.isRegularFile == true else {
            throw MarkdownSensitiveIndexStoreError.malformedIndex
        }

        do {
            return try MarkdownSensitiveIndexCodec.decode(String(contentsOf: url, encoding: .utf8))
        } catch is MarkdownSensitiveIndexError {
            throw MarkdownSensitiveIndexStoreError.malformedIndex
        }
    }

    private func writeEntries(_ entries: [IndexedEncryptedRecord]) throws {
        let url = try requiredIndexURL()
        let parent = url.deletingLastPathComponent()
        try assertSafeDirectory(parent)
        if FileManager.default.fileExists(atPath: url.path) {
            try assertSafeIndexURL(url)
        }

        let data = try MarkdownSensitiveIndexCodec.encode(entries).data(using: .utf8)
        guard let data else {
            throw MarkdownSensitiveIndexStoreError.verificationFailed
        }

        let temporaryURL = parent.appendingPathComponent(".asv-index-\(UUID().uuidString).tmp")
        do {
            try data.write(to: temporaryURL, options: .withoutOverwriting)
            try assertSafeIndexURL(temporaryURL)
            let verified = try readEntries(from: temporaryURL)
            guard verified == entries else {
                throw MarkdownSensitiveIndexStoreError.verificationFailed
            }

            if FileManager.default.fileExists(atPath: url.path) {
                _ = try FileManager.default.replaceItemAt(url, withItemAt: temporaryURL)
            } else {
                try FileManager.default.moveItem(at: temporaryURL, to: url)
            }
            try assertSafeIndexURL(url)
        } catch {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw error
        }
    }

    private func readEntries(from url: URL) throws -> [IndexedEncryptedRecord] {
        do {
            return try MarkdownSensitiveIndexCodec.decode(String(contentsOf: url, encoding: .utf8))
        } catch is MarkdownSensitiveIndexError {
            throw MarkdownSensitiveIndexStoreError.malformedIndex
        }
    }

    private func requiredIndexURL() throws -> URL {
        guard let indexURL else {
            throw MarkdownSensitiveIndexStoreError.noSelectedIndex
        }
        return indexURL
    }

    private func nextDisplayID(in entries: [IndexedEncryptedRecord]) throws -> String {
        let highest = try entries.map { entry -> Int in
            guard entry.displayID.hasPrefix("S-"), let number = Int(entry.displayID.dropFirst(2)) else {
                throw MarkdownSensitiveIndexStoreError.malformedIndex
            }
            return number
        }.max() ?? 0
        return String(format: "S-%03d", highest + 1)
    }

    private func defaultMetadata(for record: EncryptedRecord) -> SensitiveIndexMetadata {
        SensitiveIndexMetadata(
            category: record.policy.rawValue,
            title: record.label ?? "Sensitive value",
            source: nil
        )
    }

    private func assertSafeIndexURL(_ url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw MarkdownSensitiveIndexStoreError.symlinkRejected
        }
    }

    private func assertSafeDirectory(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else {
            throw MarkdownSensitiveIndexStoreError.malformedIndex
        }
        if values.isSymbolicLink == true {
            throw MarkdownSensitiveIndexStoreError.symlinkRejected
        }
    }
}
