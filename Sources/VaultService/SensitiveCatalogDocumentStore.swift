import CryptoKit
import Darwin
import Foundation
import VaultAuthorization
import VaultCore

public enum SensitiveCatalogDocumentStoreError: Error, Equatable, Sendable {
    case noSelectedDocument
    case malformedDocument
    case legacyCatalogUnsupported
    case symlinkRejected
    case integrityMissing
    case externalModification
    case pendingExternalChange
    case invalidIntegrity
    case revisionConflict
    case invalidOperation
    case referenceSetChanged
    case writeFailed
}

public enum SensitiveCatalogIntegrityStatus: String, Codable, Equatable, Sendable {
    case uninitialized
    case verified
    case legacyCatalogUnsupported = "LEGACY_CATALOG_UNSUPPORTED"
    case integrityMissing = "INTEGRITY_MISSING"
    case externalModification = "EXTERNAL_CATALOG_MODIFICATION"
    case pendingExternalChange = "PENDING_EXTERNAL_CHANGE"
    case invalid = "CATALOG_INVALID"
}

/// Accepted state is semantic. rawSHA256 is retained only as an optimistic
/// concurrency aid and is never used as the integrity/security decision.
public struct CatalogAcceptedState: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let semanticSHA256: String
    public let acceptedDocument: SecretCatalogDocument
    public let rawSHA256: String
    public let updatedAt: String

    public init(
        schemaVersion: Int = SecretCatalogDocument.currentSchemaVersion,
        revision: UInt64,
        semanticSHA256: String,
        acceptedDocument: SecretCatalogDocument,
        rawSHA256: String,
        updatedAt: String
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.semanticSHA256 = semanticSHA256
        self.acceptedDocument = acceptedDocument
        self.rawSHA256 = rawSHA256
        self.updatedAt = updatedAt
    }
}

public struct CatalogIntegrityRecord: Codable, Equatable, Sendable {
    public let acceptedState: CatalogAcceptedState
    public let hmac: String

    public init(acceptedState: CatalogAcceptedState, hmac: String) {
        self.acceptedState = acceptedState
        self.hmac = hmac
    }

    public var schemaVersion: Int { acceptedState.schemaVersion }
    public var revision: UInt64 { acceptedState.revision }
    /// Compatibility name for callers that used the old raw sidecar field.
    public var canonicalSHA256: String { acceptedState.rawSHA256 }
    public var semanticSHA256: String { acceptedState.semanticSHA256 }
    public var acceptedDocument: SecretCatalogDocument { acceptedState.acceptedDocument }
    public var rawSHA256: String { acceptedState.rawSHA256 }
    public var updatedAt: String { acceptedState.updatedAt }
}

public struct CatalogExternalChange: Codable, Equatable, Sendable {
    public let rawSHA256: String
    public let acceptedRevision: UInt64
    public let candidateDocument: SecretCatalogDocument
    public let semanticDiff: CatalogSemanticDiff

    public init(rawSHA256: String, acceptedRevision: UInt64, candidateDocument: SecretCatalogDocument, semanticDiff: CatalogSemanticDiff) {
        self.rawSHA256 = rawSHA256
        self.acceptedRevision = acceptedRevision
        self.candidateDocument = candidateDocument
        self.semanticDiff = semanticDiff
    }
}

public struct SensitiveCatalogSnapshot: Equatable, Sendable {
    public let document: SecretCatalogDocument
    public let revision: UInt64
    public let integrity: SensitiveCatalogIntegrityStatus

    public init(document: SecretCatalogDocument, revision: UInt64, integrity: SensitiveCatalogIntegrityStatus) {
        self.document = document
        self.revision = revision
        self.integrity = integrity
    }
}

/// Persistent catalog coordinator. App/MCP and external writers share the
/// sidecar flock; external Markdown changes are reconciled by semantic diff.
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
            guard url.pathExtension.lowercased() == "md" else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
            try assertSafeParent(url)
            if fileManager.fileExists(atPath: url.path) { try assertSafeFile(url) }
            documentURL = url.standardizedFileURL
        } else {
            documentURL = nil
        }
    }

    public func selectedDocumentURL() -> URL? { documentURL }

    public func snapshot() throws -> SensitiveCatalogSnapshot {
        // Reconciliation may update raw auxiliary data or accepted state.
        try withCatalogLock(exclusive: true) { try snapshotUnlocked() }
    }

    public func validate() throws -> SensitiveCatalogSnapshot { try snapshot() }

    public func integrityStatus() -> SensitiveCatalogIntegrityStatus {
        do { return try snapshot().integrity }
        catch SensitiveCatalogDocumentStoreError.legacyCatalogUnsupported { return .legacyCatalogUnsupported }
        catch SensitiveCatalogDocumentStoreError.integrityMissing { return .integrityMissing }
        catch SensitiveCatalogDocumentStoreError.pendingExternalChange { return .pendingExternalChange }
        catch SensitiveCatalogDocumentStoreError.externalModification { return .externalModification }
        catch { return .invalid }
    }

    @discardableResult
    public func canonicalWrite(_ document: SecretCatalogDocument, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try document.validate()
        return try withCatalogLock(exclusive: true) {
            let current = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            return try writeUnlocked(document, previous: current.revision, basedOn: current.document)
        }
    }

    @discardableResult
    public func applyBatch(_ mutation: CatalogBatchMutation, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            let current = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            let document: SecretCatalogDocument
            do { document = try mutation.applying(to: current.document) }
            catch { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return try writeUnlocked(document, previous: current.revision, basedOn: current.document)
        }
    }

    @discardableResult
    public func createIndex(title: String, aliases: [String] = [], tags: [String] = [], expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        let index = try SecretCatalogIndex.generated(title: title, aliases: aliases, tags: tags)
        return try mutate(expectedRevision: expectedRevision) { document in
            guard !document.indexes.contains(where: { $0.id == index.id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes + [index], entries: document.entries)
        }
    }

    @discardableResult
    public func updateIndex(_ index: SecretCatalogIndex, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.indexes.firstIndex(where: { $0.id == index.id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var indexes = document.indexes
            indexes[offset] = index
            return SecretCatalogDocument(indexes: indexes, entries: document.entries)
        }
    }

    @discardableResult
    public func deleteIndex(id: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes.filter { $0.id != id }, entries: document.entries.filter { $0.indexId != id })
        }
    }

    @discardableResult
    public func createEntry(_ entry: SecretCatalogEntry, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == entry.indexId }), !document.entries.contains(where: { $0.id == entry.id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes, entries: document.entries + [entry])
        }
    }

    @discardableResult
    public func updateEntry(_ entry: SecretCatalogEntry, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entry.id }), document.indexes.contains(where: { $0.id == entry.indexId }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries
            entries[offset] = entry
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func moveEntry(id: String, toIndexID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == toIndexID }), let offset = document.entries.firstIndex(where: { $0.id == id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[offset]
            var entries = document.entries
            entries[offset] = SecretCatalogEntry(id: old.id, indexId: toIndexID, title: old.title, type: old.type, aliases: old.aliases, endpoints: old.endpoints, fields: old.fields, notes: old.notes, tags: old.tags, schema: old.schema)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func deleteEntry(id: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.entries.contains(where: { $0.id == id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes, entries: document.entries.filter { $0.id != id })
        }
    }

    @discardableResult
    public func addField(_ field: SecretCatalogFieldValue, toEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[offset]
            guard !old.fields.contains(where: { $0.key == field.key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries
            entries[offset] = replacingFields(old, old.fields + [field])
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func updateField(_ field: SecretCatalogFieldValue, inEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == field.key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var fields = old.fields; fields[fieldOffset] = field
            var entries = document.entries; entries[entryOffset] = replacingFields(old, fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func removeField(key: String, fromEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard old.fields.contains(where: { $0.key == key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries; entries[entryOffset] = replacingFields(old, old.fields.filter { $0.key != key })
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func bindSecret(_ secretRef: String, toFieldKey key: String, entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        guard (try? SecretReference(secretRef)) != nil else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
        return try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == key }), old.fields[fieldOffset].type.isSecret else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let oldField = old.fields[fieldOffset]
            var fields = old.fields
            fields[fieldOffset] = SecretCatalogFieldValue(key: oldField.key, label: oldField.label, type: oldField.type, agentVisible: oldField.agentVisible, searchable: oldField.searchable, secretRef: secretRef)
            var entries = document.entries; entries[entryOffset] = replacingFields(old, fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    public func pendingExternalChange() throws -> CatalogExternalChange {
        try withCatalogLock(exclusive: true) {
            guard let candidate = try externalCandidateUnlocked(), candidate.semanticDiff.requiresApproval else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return candidate
        }
    }

    @discardableResult
    public func acceptPendingExternalChange() throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let candidate = try externalCandidateUnlocked(), candidate.semanticDiff.requiresApproval else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let raw = try readDocumentData()
            guard sha256Hex(raw) == candidate.rawSHA256 else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            let record = try makeRecord(document: candidate.candidateDocument, revision: candidate.acceptedRevision + 1, raw: raw)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: candidate.candidateDocument, revision: record.revision, integrity: .verified)
        }
    }

    public func backupCurrentDocument() throws -> URL? {
        try withCatalogLock(exclusive: true) { try backupCurrentDocumentUnlocked() }
    }

    /// Explicit v2 to v3 migration. Parsing, re-encoding, re-parsing and
    /// secret-reference equality are completed before the source is touched.
    @discardableResult
    public func adoptExternalV2() throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try assertSafeFile(url)
            let raw = try Data(contentsOf: url)
            guard SensitiveCatalogDocumentCodec.format(raw) == .managedV2 else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let document = try decodeV2(raw)
            let rendered = try SensitiveCatalogDocumentCodec.canonicalData(document)
            let reparsed = try SensitiveCatalogDocumentCodec.decode(rendered)
            guard reparsed == document, referenceSet(document) == referenceSet(reparsed) else { throw SensitiveCatalogDocumentStoreError.referenceSetChanged }
            let stateURL = try integrityURL()
            guard !fileManager.fileExists(atPath: stateURL.path) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            _ = try backupCurrentDocumentUnlocked()
            try atomicWrite(rendered, to: url)
            let record = try makeRecord(document: reparsed, revision: 1, raw: rendered)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: reparsed, revision: 1, integrity: .verified)
        }
    }

    /// Explicit adoption for a hand-created v3 file with no accepted state.
    @discardableResult
    public func adoptExternalV3() throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try assertSafeFile(url)
            let raw = try Data(contentsOf: url)
            guard SensitiveCatalogDocumentCodec.format(raw) == .managedV3 else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let document = try decodeV3(raw)
            let stateURL = try integrityURL()
            guard !fileManager.fileExists(atPath: stateURL.path) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let record = try makeRecord(document: document, revision: 1, raw: raw)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: document, revision: 1, integrity: .verified)
        }
    }

    @discardableResult
    public func restoreV2Document(from backupURL: URL) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            try assertSafeFile(backupURL)
            let document = try SensitiveCatalogDocumentCodec.decode(Data(contentsOf: backupURL))
            let current = try snapshotUnlocked()
            return try writeUnlocked(document, previous: current.revision, basedOn: current.document)
        }
    }

    private func mutate(expectedRevision: UInt64?, _ transform: (SecretCatalogDocument) throws -> SecretCatalogDocument) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            let base = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            let document: SecretCatalogDocument
            do { document = try transform(base.document); try document.validate() }
            catch let error as SensitiveCatalogDocumentStoreError { throw error }
            catch { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return try writeUnlocked(document, previous: base.revision, basedOn: base.document)
        }
    }

    private func mutationBaseUnlocked(expectedRevision: UInt64?) throws -> SensitiveCatalogSnapshot {
        let value = try snapshotUnlocked()
        if let expectedRevision, expectedRevision != value.revision { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        return value
    }

    private func snapshotUnlocked() throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        guard fileManager.fileExists(atPath: url.path) else {
            return SensitiveCatalogSnapshot(document: SecretCatalogDocument(), revision: 0, integrity: .uninitialized)
        }
        try assertSafeFile(url)
        let raw = try Data(contentsOf: url)
        switch SensitiveCatalogDocumentCodec.format(raw) {
        case .managedV2:
            // A valid v2 document is an explicit migration candidate. Do not
            // collapse it into the unsupported legacy-v1 state, otherwise the
            // App cannot offer the backup-and-migrate path.
            _ = try decodeV2(raw)
            throw SensitiveCatalogDocumentStoreError.integrityMissing
        case .legacy, .unmanaged:
            throw SensitiveCatalogDocumentStoreError.legacyCatalogUnsupported
        case .managedV3:
            break
        }
        let candidate = try decodeV3(raw)
        let stateURL = try integrityURL()
        guard fileManager.fileExists(atPath: stateURL.path) else {
            // A hand-created v3 document containing only ordinary metadata is
            // safe to initialize without rewriting the user's Markdown. A
            // document that introduces opaque references still needs the
            // explicit local App adoption path because it has no accepted
            // baseline against which to classify the binding.
            guard referenceSet(candidate).isEmpty else {
                throw SensitiveCatalogDocumentStoreError.integrityMissing
            }
            let initialized = try makeRecord(document: candidate, revision: 1, raw: raw)
            try atomicWriteIntegrity(initialized)
            return SensitiveCatalogSnapshot(document: candidate, revision: 1, integrity: .verified)
        }
        let record = try readIntegrityRecord()
        try verify(record)
        let diff = CatalogSemanticDiff.between(old: record.acceptedDocument, new: candidate)
        if diff.requiresApproval {
            throw SensitiveCatalogDocumentStoreError.pendingExternalChange
        }
        if candidate != record.acceptedDocument || record.rawSHA256 != sha256Hex(raw) {
            let revision = candidate == record.acceptedDocument ? record.revision : record.revision + 1
            let updated = try makeRecord(document: candidate, revision: revision, raw: raw)
            try atomicWriteIntegrity(updated)
            return SensitiveCatalogSnapshot(document: candidate, revision: revision, integrity: .verified)
        }
        return SensitiveCatalogSnapshot(document: candidate, revision: record.revision, integrity: .verified)
    }

    private func externalCandidateUnlocked() throws -> CatalogExternalChange? {
        guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try assertSafeFile(url)
        let raw = try Data(contentsOf: url)
        guard SensitiveCatalogDocumentCodec.format(raw) == .managedV3 else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        let record = try readIntegrityRecord()
        try verify(record)
        let candidate = try decodeV3(raw)
        let diff = CatalogSemanticDiff.between(old: record.acceptedDocument, new: candidate)
        guard !diff.isEmpty else { return nil }
        return CatalogExternalChange(rawSHA256: sha256Hex(raw), acceptedRevision: record.revision, candidateDocument: candidate, semanticDiff: diff)
    }

    private enum CatalogMergePath: Hashable {
        case indexOrder
        case entryOrder
        case fieldOrder(String)
        case index(String, String)
        case entry(String, String)
        case field(String, String, String)
    }

    private func writeUnlocked(
        _ document: SecretCatalogDocument,
        previous: UInt64,
        basedOn baseDocument: SecretCatalogDocument
    ) throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try document.validate()
        var targetDocument = document
        var sourceDocument = baseDocument

        for _ in 0..<3 {
            if fileManager.fileExists(atPath: url.path) {
                try assertSafeFile(url)
                let before = try Data(contentsOf: url)
                let currentDocument = try decodeV3(before)
                if currentDocument != sourceDocument {
                    guard let rebased = try safelyRebase(
                        base: sourceDocument,
                        local: targetDocument,
                        external: currentDocument
                    ) else {
                        throw SensitiveCatalogDocumentStoreError.revisionConflict
                    }
                    targetDocument = rebased
                    sourceDocument = currentDocument
                }

                let raw = try SensitiveCatalogDocumentCodec.minimalPatch(
                    before,
                    from: currentDocument,
                    to: targetDocument
                )
                let justBeforeWrite = try Data(contentsOf: url)
                guard sha256Hex(before) == sha256Hex(justBeforeWrite) else {
                    // The external writer won this read/patch window. Keep
                    // the desired semantic change and rebase it on the fresh
                    // source during the next pass instead of overwriting it.
                    sourceDocument = currentDocument
                    continue
                }
                guard try decodeV3(raw) == targetDocument else {
                    throw SensitiveCatalogDocumentStoreError.malformedDocument
                }
                try atomicWrite(raw, to: url)
                let revision = previous + 1
                let record = try makeRecord(document: targetDocument, revision: revision, raw: raw)
                try atomicWriteIntegrity(record)
                return SensitiveCatalogSnapshot(document: targetDocument, revision: revision, integrity: .verified)
            } else {
                guard sourceDocument == SecretCatalogDocument() else {
                    throw SensitiveCatalogDocumentStoreError.revisionConflict
                }
                let raw = try SensitiveCatalogDocumentCodec.canonicalData(targetDocument)
                guard !fileManager.fileExists(atPath: url.path) else { continue }
                try atomicWrite(raw, to: url)
                let revision = previous + 1
                let record = try makeRecord(document: targetDocument, revision: revision, raw: raw)
                try atomicWriteIntegrity(record)
                return SensitiveCatalogSnapshot(document: targetDocument, revision: revision, integrity: .verified)
            }
        }

        throw SensitiveCatalogDocumentStoreError.revisionConflict
    }

    private func safelyRebase(
        base: SecretCatalogDocument,
        local: SecretCatalogDocument,
        external: SecretCatalogDocument
    ) throws -> SecretCatalogDocument? {
        let externalDiff = CatalogSemanticDiff.between(old: base, new: external)
        guard !externalDiff.requiresApproval else {
            throw SensitiveCatalogDocumentStoreError.pendingExternalChange
        }

        let baseValues = mergeValues(for: base)
        let localValues = mergeValues(for: local)
        let externalValues = mergeValues(for: external)
        let paths = Set(baseValues.keys)
            .union(localValues.keys)
            .union(externalValues.keys)
        var mergedValues: [CatalogMergePath: Data] = [:]

        for path in paths {
            let baseValue = baseValues[path]
            let localValue = localValues[path]
            let externalValue = externalValues[path]
            let localChanged = localValue != baseValue
            let externalChanged = externalValue != baseValue

            if localChanged && externalChanged && localValue != externalValue {
                return nil
            }
            if localChanged {
                if let localValue { mergedValues[path] = localValue }
            } else if let externalValue {
                mergedValues[path] = externalValue
            }
        }

        return try materializeMergeValues(
            mergedValues,
            base: base,
            local: local,
            external: external
        )
    }

    private func mergeValues(for document: SecretCatalogDocument) -> [CatalogMergePath: Data] {
        var values: [CatalogMergePath: Data] = [
            .indexOrder: mergeEncoded(document.indexes.map(\.id)),
            .entryOrder: mergeEncoded(document.entries.map(\.id))
        ]
        for index in document.indexes {
            values[.index(index.id, "exists")] = mergeEncoded(true)
            values[.index(index.id, "title")] = mergeEncoded(index.title)
            values[.index(index.id, "aliases")] = mergeEncoded(index.aliases)
            values[.index(index.id, "tags")] = mergeEncoded(index.tags)
        }
        for entry in document.entries {
            values[.entry(entry.id, "exists")] = mergeEncoded(true)
            values[.entry(entry.id, "indexId")] = mergeEncoded(entry.indexId)
            values[.entry(entry.id, "title")] = mergeEncoded(entry.title)
            values[.entry(entry.id, "type")] = mergeEncoded(entry.type)
            values[.entry(entry.id, "aliases")] = mergeEncoded(entry.aliases)
            values[.entry(entry.id, "endpoints")] = mergeEncoded(entry.endpoints)
            values[.entry(entry.id, "notes")] = mergeEncoded(entry.notes)
            values[.entry(entry.id, "tags")] = mergeEncoded(entry.tags)
            values[.fieldOrder(entry.id)] = mergeEncoded(entry.fields.map(\.key))
            for field in entry.fields {
                values[.field(entry.id, field.key, "exists")] = mergeEncoded(true)
                values[.field(entry.id, field.key, "label")] = mergeEncoded(field.label)
                values[.field(entry.id, field.key, "type")] = mergeEncoded(field.type)
                values[.field(entry.id, field.key, "agentVisible")] = mergeEncoded(field.agentVisible)
                values[.field(entry.id, field.key, "searchable")] = mergeEncoded(field.searchable)
                values[.field(entry.id, field.key, "value")] = mergeEncoded(field.value)
                values[.field(entry.id, field.key, "secretRef")] = mergeEncoded(field.secretRef)
            }
        }
        return values
    }

    private func materializeMergeValues(
        _ values: [CatalogMergePath: Data],
        base: SecretCatalogDocument,
        local: SecretCatalogDocument,
        external: SecretCatalogDocument
    ) throws -> SecretCatalogDocument? {
        let allIndexIDs = Set(
            base.indexes.map(\.id) + local.indexes.map(\.id) + external.indexes.map(\.id)
        )
        let indexOrder = try mergeOrder(
            values[.indexOrder],
            allIDs: allIndexIDs
        )
        var indexes: [SecretCatalogIndex] = []
        for id in indexOrder where try mergeBool(values[.index(id, "exists")]) {
            indexes.append(SecretCatalogIndex(
                id: id,
                title: try mergeValue(values, path: .index(id, "title"), as: String.self),
                aliases: try mergeValue(values, path: .index(id, "aliases"), as: [String].self),
                tags: try mergeValue(values, path: .index(id, "tags"), as: [String].self)
            ))
        }

        let indexIDSet = Set(indexes.map(\.id))
        let allEntryIDs = Set(
            base.entries.map(\.id) + local.entries.map(\.id) + external.entries.map(\.id)
        )
        let entryOrder = try mergeOrder(values[.entryOrder], allIDs: allEntryIDs)
        var entries: [SecretCatalogEntry] = []
        for id in entryOrder where try mergeBool(values[.entry(id, "exists")]) {
            let indexID = try mergeValue(values, path: .entry(id, "indexId"), as: String.self)
            guard indexIDSet.contains(indexID) else { return nil }
            let allFieldKeys = Set(
                (base.entries + local.entries + external.entries)
                    .filter { $0.id == id }
                    .flatMap { $0.fields.map(\.key) }
            )
            let fieldOrder = try mergeOrder(values[.fieldOrder(id)], allIDs: allFieldKeys)
            var fields: [SecretCatalogFieldValue] = []
            for key in fieldOrder where try mergeBool(values[.field(id, key, "exists")]) {
                fields.append(SecretCatalogFieldValue(
                    key: key,
                    label: try mergeValue(values, path: .field(id, key, "label"), as: String.self),
                    type: try mergeValue(values, path: .field(id, key, "type"), as: SecretCatalogFieldType.self),
                    agentVisible: try mergeValue(values, path: .field(id, key, "agentVisible"), as: Bool.self),
                    searchable: try mergeValue(values, path: .field(id, key, "searchable"), as: Bool.self),
                    value: try mergeValue(values, path: .field(id, key, "value"), as: SecretCatalogValue?.self),
                    secretRef: try mergeValue(values, path: .field(id, key, "secretRef"), as: String?.self)
                ))
            }
            entries.append(SecretCatalogEntry(
                id: id,
                indexId: indexID,
                title: try mergeValue(values, path: .entry(id, "title"), as: String.self),
                type: try mergeValue(values, path: .entry(id, "type"), as: String.self),
                aliases: try mergeValue(values, path: .entry(id, "aliases"), as: [String].self),
                endpoints: try mergeValue(values, path: .entry(id, "endpoints"), as: [CatalogEndpoint].self),
                fields: fields,
                notes: try mergeValue(values, path: .entry(id, "notes"), as: String?.self),
                tags: try mergeValue(values, path: .entry(id, "tags"), as: [String].self)
            ))
        }

        let merged = SecretCatalogDocument(indexes: indexes, entries: entries)
        guard (try? merged.validate()) != nil else { return nil }
        return merged
    }

    private func mergeOrder(_ data: Data?, allIDs: Set<String>) throws -> [String] {
        guard let data else { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        let order = try mergeDecode([String].self, from: data)
        var result: [String] = []
        for id in order where allIDs.contains(id) && !result.contains(id) {
            result.append(id)
        }
        for id in allIDs.subtracting(result).sorted() {
            result.append(id)
        }
        return result
    }

    private func mergeBool(_ data: Data?) throws -> Bool {
        guard let data else { return false }
        return try mergeDecode(Bool.self, from: data)
    }

    private func mergeValue<T: Decodable>(
        _ values: [CatalogMergePath: Data],
        path: CatalogMergePath,
        as type: T.Type
    ) throws -> T {
        guard let data = values[path] else { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        return try mergeDecode(type, from: data)
    }

    private func mergeDecode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw SensitiveCatalogDocumentStoreError.revisionConflict }
    }

    private func mergeEncoded<T: Encodable>(_ value: T) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? encoder.encode(value)) ?? Data()
    }

    private func decodeV3(_ data: Data) throws -> SecretCatalogDocument {
        do { return try SensitiveCatalogDocumentCodec.decode(data) }
        catch { throw SensitiveCatalogDocumentStoreError.malformedDocument }
    }

    private func decodeV2(_ data: Data) throws -> SecretCatalogDocument {
        do { return try SensitiveCatalogDocumentCodec.decode(data) }
        catch { throw SensitiveCatalogDocumentStoreError.malformedDocument }
    }

    private func readDocumentData() throws -> Data {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try assertSafeFile(url)
        return try Data(contentsOf: url)
    }

    private func makeRecord(document: SecretCatalogDocument, revision: UInt64, raw: Data) throws -> CatalogIntegrityRecord {
        let state = CatalogAcceptedState(
            revision: revision,
            semanticSHA256: semanticDigest(document),
            acceptedDocument: document,
            rawSHA256: sha256Hex(raw),
            updatedAt: iso8601String(Date())
        )
        let key: Data
        do { key = try keyStore.loadOrCreateKey() } catch { throw SensitiveCatalogDocumentStoreError.writeFailed }
        let mac = HMAC<SHA256>.authenticationCode(for: integrityPayload(state), using: SymmetricKey(data: key))
        return CatalogIntegrityRecord(acceptedState: state, hmac: Data(mac).base64EncodedString())
    }

    private func verify(_ record: CatalogIntegrityRecord) throws {
        guard record.schemaVersion == SecretCatalogDocument.currentSchemaVersion, record.revision > 0, let expected = Data(base64Encoded: record.hmac) else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
        do { try record.acceptedDocument.validate() } catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        guard semanticDigest(record.acceptedDocument) == record.semanticSHA256 else { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let key: Data
        do { key = try keyStore.loadOrCreateKey() } catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let computed = Data(HMAC<SHA256>.authenticationCode(for: integrityPayload(record.acceptedState), using: SymmetricKey(data: key)))
        guard constantTimeEqual(computed, expected) else { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
    }

    private func integrityPayload(_ state: CatalogAcceptedState) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let document = (try? encoder.encode(state.acceptedDocument)).map { String(data: $0, encoding: .utf8) ?? "{}" } ?? "{}"
        return Data("SVLT-CATALOG-ACCEPTED-V3\n\(state.revision)\n\(state.semanticSHA256)\n\(document)".utf8)
    }

    private func semanticDigest(_ document: SecretCatalogDocument) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(document)) ?? Data()
        return sha256Hex(data)
    }

    private func referenceSet(_ document: SecretCatalogDocument) -> Set<String> {
        Set(document.entries.flatMap { $0.fields.compactMap(\.secretRef) })
    }

    private func readIntegrityRecord() throws -> CatalogIntegrityRecord {
        let url = try integrityURL()
        guard fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.integrityMissing }
        try assertSafeFile(url)
        do { return try JSONDecoder().decode(CatalogIntegrityRecord.self, from: Data(contentsOf: url)) }
        catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
    }

    private func atomicWriteIntegrity(_ record: CatalogIntegrityRecord) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do { try atomicWrite(encoder.encode(record), to: try integrityURL()) }
        catch let error as SensitiveCatalogDocumentStoreError { throw error }
        catch { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func backupCurrentDocumentUnlocked() throws -> URL? {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        try assertSafeFile(url)
        let backup = url.deletingLastPathComponent().appendingPathComponent("\(url.lastPathComponent).bak-\(backupTimestampString(Date()))-\(UUID().uuidString.lowercased())")
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

    private func integrityURL() throws -> URL {
        if let suppliedIntegrityURL { return suppliedIntegrityURL }
        let appSupport = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = appSupport.appendingPathComponent("AgentSecretVault", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return directory.appendingPathComponent("catalog-integrity.json")
    }

    private func withCatalogLock<T>(exclusive: Bool, _ operation: () throws -> T) throws -> T {
        let lockURL = try integrityURL().appendingPathExtension("lock")
        let parent = lockURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if fileManager.fileExists(atPath: lockURL.path) { try assertSafeFile(lockURL) }
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, mode_t(0o600))
        guard descriptor >= 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        defer { close(descriptor) }
        guard flock(descriptor, exclusive ? LOCK_EX : LOCK_SH) == 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try operation()
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
        guard values.isDirectory == true else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        guard values.isSymbolicLink != true else { throw SensitiveCatalogDocumentStoreError.symlinkRejected }
    }

    private func assertSafeFile(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        guard values.isSymbolicLink != true else { throw SensitiveCatalogDocumentStoreError.symlinkRejected }
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
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }

    private func iso8601String(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private func backupTimestampString(_ date: Date) -> String {
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }
}

private func replacingFields(_ entry: SecretCatalogEntry, _ fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(id: entry.id, indexId: entry.indexId, title: entry.title, type: entry.type, aliases: entry.aliases, endpoints: entry.endpoints, fields: fields, notes: entry.notes, tags: entry.tags, schema: entry.schema)
}
