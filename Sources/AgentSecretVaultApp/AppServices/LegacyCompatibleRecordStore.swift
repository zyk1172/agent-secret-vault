import VaultCore

public struct LegacyCompatibleRecordStore: RecordStore, RecordListing, RecordDeleting, Sendable {
    private let primary: MarkdownSensitiveIndexStore
    private let legacy: FileRecordStore

    public init(primary: MarkdownSensitiveIndexStore, legacy: FileRecordStore) {
        self.primary = primary
        self.legacy = legacy
    }

    public func save(_ record: EncryptedRecord) async throws {
        try await primary.save(record)
    }

    public func latest(id: String) async throws -> EncryptedRecord {
        do {
            return try await primary.latest(id: id)
        } catch MarkdownSensitiveIndexStoreError.noSelectedIndex,
                MarkdownSensitiveIndexStoreError.recordNotFound {
            return try await legacy.latest(id: id)
        }
    }

    public func versions(id: String) async throws -> [Int] {
        do {
            let primaryVersions = try await primary.versions(id: id)
            return primaryVersions.isEmpty ? try await legacy.versions(id: id) : primaryVersions
        } catch MarkdownSensitiveIndexStoreError.noSelectedIndex {
            return try await legacy.versions(id: id)
        }
    }

    public func recordIDs() async throws -> [String] {
        let primaryIDs: [String]
        do {
            primaryIDs = try await primary.recordIDs()
        } catch MarkdownSensitiveIndexStoreError.noSelectedIndex {
            primaryIDs = []
        }
        let legacyIDs = try await legacy.recordIDs()
        return Array(Set(primaryIDs).union(legacyIDs)).sorted()
    }

    public func delete(id: String) async throws {
        do {
            try await primary.delete(id: id)
        } catch MarkdownSensitiveIndexStoreError.noSelectedIndex,
                MarkdownSensitiveIndexStoreError.recordNotFound {
            // Legacy records are the fallback store when the primary index is absent.
        }
        try await legacy.delete(id: id)
    }
}
