import Foundation

/// A semantic change in the managed catalog. The source file, editor and
/// transport are deliberately absent from this type: policy is evaluated from
/// what changed, not from who happened to write the Markdown.
public enum CatalogSemanticChangeKind: String, Codable, CaseIterable, Sendable {
    case createIndex
    case updateIndexMetadata
    case deleteIndex
    case deleteSecretBearingIndex
    case createEntry
    case updateEntryMetadata
    case moveEntry
    case deleteEntry
    case deleteSecretBearingEntry
    case addMetadataField
    case updateMetadataField
    case removeMetadataField
    case createSecretPlaceholder
    case bindExistingSecret
    case replaceSecret
    case deleteSecret
    case changeSecretType
    case changeSecretTarget
}

public struct CatalogSemanticChange: Codable, Equatable, Sendable {
    public let kind: CatalogSemanticChangeKind
    public let indexID: String?
    public let entryID: String?
    public let fieldKey: String?
    public let oldSecretRef: String?
    public let newSecretRef: String?

    public init(
        kind: CatalogSemanticChangeKind,
        indexID: String? = nil,
        entryID: String? = nil,
        fieldKey: String? = nil,
        oldSecretRef: String? = nil,
        newSecretRef: String? = nil
    ) {
        self.kind = kind
        self.indexID = indexID
        self.entryID = entryID
        self.fieldKey = fieldKey
        self.oldSecretRef = oldSecretRef
        self.newSecretRef = newSecretRef
    }
}

public struct CatalogSemanticDiff: Codable, Equatable, Sendable {
    public let changes: [CatalogSemanticChange]
    /// Complete opaque reference set involved in the before/after documents.
    /// Change records keep one representative reference for concise UI
    /// messages, while approval must inspect every field reference.
    public let secretRefs: [String]

    public init(changes: [CatalogSemanticChange] = [], secretRefs: [String] = []) {
        self.changes = changes
        self.secretRefs = secretRefs
    }

    public var isEmpty: Bool { changes.isEmpty }

    public var touchesExistingSecret: Bool {
        changes.contains { change in
            change.oldSecretRef != nil
                || change.kind == .deleteSecretBearingEntry
                || change.kind == .deleteSecretBearingIndex
        }
    }

    public var changesSecretTarget: Bool {
        changes.contains { $0.kind == .changeSecretTarget }
    }

    public var requiresApproval: Bool {
        changes.contains { change in
            switch change.kind {
            case .deleteSecretBearingIndex, .deleteSecretBearingEntry,
                 .bindExistingSecret, .replaceSecret, .deleteSecret,
                 .changeSecretType, .changeSecretTarget:
                return true
            case .createIndex, .updateIndexMetadata, .deleteIndex,
                 .createEntry, .updateEntryMetadata, .moveEntry,
                 .deleteEntry, .addMetadataField, .updateMetadataField,
                 .removeMetadataField, .createSecretPlaceholder:
                return false
            }
        }
    }

    public var referencedSecretRefs: [String] {
        var references = Set<String>()
        references.formUnion(secretRefs)
        for change in changes {
            if let oldSecretRef = change.oldSecretRef { references.insert(oldSecretRef) }
            if let newSecretRef = change.newSecretRef { references.insert(newSecretRef) }
        }
        return references.sorted()
    }

    public static func between(
        old: SecretCatalogDocument,
        new: SecretCatalogDocument
    ) -> Self {
        var changes: [CatalogSemanticChange] = []
        let oldIndexes = Dictionary(uniqueKeysWithValues: old.indexes.map { ($0.id, $0) })
        let newIndexes = Dictionary(uniqueKeysWithValues: new.indexes.map { ($0.id, $0) })
        let oldEntries = Dictionary(uniqueKeysWithValues: old.entries.map { ($0.id, $0) })
        let newEntries = Dictionary(uniqueKeysWithValues: new.entries.map { ($0.id, $0) })

        for index in old.indexes where newIndexes[index.id] == nil {
            let hasSecret = old.entries
                .filter { $0.indexId == index.id }
                .contains { $0.fields.contains { $0.secretRef != nil } }
            changes.append(CatalogSemanticChange(
                kind: hasSecret ? .deleteSecretBearingIndex : .deleteIndex,
                indexID: index.id
            ))
        }
        for index in new.indexes where oldIndexes[index.id] == nil {
            let hasSecret = new.entries
                .filter { $0.indexId == index.id }
                .contains { $0.fields.contains { $0.secretRef != nil } }
            changes.append(CatalogSemanticChange(
                kind: .createIndex,
                indexID: index.id,
                newSecretRef: hasSecret ? new.entries
                    .filter { $0.indexId == index.id }
                    .flatMap { $0.fields.compactMap(\.secretRef) }
                    .first : nil
            ))
        }
        for indexID in Set(oldIndexes.keys).intersection(newIndexes.keys) {
            guard let oldIndex = oldIndexes[indexID], let newIndex = newIndexes[indexID] else { continue }
            if oldIndex.title != newIndex.title
                || oldIndex.aliases != newIndex.aliases
                || oldIndex.tags != newIndex.tags {
                changes.append(CatalogSemanticChange(kind: .updateIndexMetadata, indexID: indexID))
            }
        }

        for entry in old.entries where newEntries[entry.id] == nil {
            let references = entry.fields.compactMap(\.secretRef)
            changes.append(CatalogSemanticChange(
                kind: references.isEmpty ? .deleteEntry : .deleteSecretBearingEntry,
                indexID: entry.indexId,
                entryID: entry.id,
                oldSecretRef: references.first
            ))
        }
        for entry in new.entries where oldEntries[entry.id] == nil {
            let references = entry.fields.compactMap(\.secretRef)
            changes.append(CatalogSemanticChange(
                kind: references.isEmpty ? .createEntry : .bindExistingSecret,
                indexID: entry.indexId,
                entryID: entry.id,
                newSecretRef: references.first
            ))
        }

        for entryID in Set(oldEntries.keys).intersection(newEntries.keys) {
            guard let oldEntry = oldEntries[entryID], let newEntry = newEntries[entryID] else { continue }
            let oldReferences = oldEntry.fields.compactMap(\.secretRef)
            let newReferences = newEntry.fields.compactMap(\.secretRef)

            if oldEntry.indexId != newEntry.indexId {
                changes.append(CatalogSemanticChange(
                    kind: oldReferences.isEmpty ? .moveEntry : .changeSecretTarget,
                    indexID: newEntry.indexId,
                    entryID: entryID,
                    oldSecretRef: oldReferences.first,
                    newSecretRef: newReferences.first
                ))
            }

            let oldMetadata = SecretCatalogEntryMetadata(entry: oldEntry)
            let newMetadata = SecretCatalogEntryMetadata(entry: newEntry)
            // A group move already has its own semantic change. Do not emit a
            // second metadata change merely because indexId is different.
            if oldEntry.indexId == newEntry.indexId && oldMetadata != newMetadata {
                let hasReferences = !oldReferences.isEmpty || !newReferences.isEmpty
                let endpointsChanged = oldEntry.endpoints != newEntry.endpoints
                changes.append(CatalogSemanticChange(
                    kind: hasReferences && endpointsChanged ? .changeSecretTarget : .updateEntryMetadata,
                    indexID: newEntry.indexId,
                    entryID: entryID,
                    oldSecretRef: oldReferences.first,
                    newSecretRef: newReferences.first
                ))
            }

            let oldFields = Dictionary(uniqueKeysWithValues: oldEntry.fields.map { ($0.key, $0) })
            let newFields = Dictionary(uniqueKeysWithValues: newEntry.fields.map { ($0.key, $0) })
            for key in Set(oldFields.keys).union(newFields.keys).sorted() {
                let oldField = oldFields[key]
                let newField = newFields[key]
                switch (oldField, newField) {
                case (nil, let newField?):
                    let kind: CatalogSemanticChangeKind
                    if newField.secretRef != nil {
                        kind = .bindExistingSecret
                    } else if newField.type.isSecret {
                        kind = .createSecretPlaceholder
                    } else {
                        kind = .addMetadataField
                    }
                    changes.append(CatalogSemanticChange(
                        kind: kind,
                        indexID: newEntry.indexId,
                        entryID: entryID,
                        fieldKey: key,
                        newSecretRef: newField.secretRef
                    ))
                case (let oldField?, nil):
                    changes.append(CatalogSemanticChange(
                        kind: oldField.secretRef == nil ? .removeMetadataField : .deleteSecret,
                        indexID: oldEntry.indexId,
                        entryID: entryID,
                        fieldKey: key,
                        oldSecretRef: oldField.secretRef
                    ))
                case (let oldField?, let newField?):
                    let oldRef = oldField.secretRef
                    let newRef = newField.secretRef
                    if oldRef != newRef {
                        let kind: CatalogSemanticChangeKind
                        switch (oldRef, newRef) {
                        case (nil, .some): kind = .bindExistingSecret
                        case (.some, nil): kind = .deleteSecret
                        case (.some, .some): kind = .replaceSecret
                        case (nil, nil): kind = .updateMetadataField
                        }
                        changes.append(CatalogSemanticChange(
                            kind: kind,
                            indexID: newEntry.indexId,
                            entryID: entryID,
                            fieldKey: key,
                            oldSecretRef: oldRef,
                            newSecretRef: newRef
                        ))
                    } else if oldField.type != newField.type {
                        let kind = newField.type.isSecret && newRef == nil
                            ? CatalogSemanticChangeKind.createSecretPlaceholder
                            : .changeSecretType
                        changes.append(CatalogSemanticChange(
                            kind: kind,
                            indexID: newEntry.indexId,
                            entryID: entryID,
                            fieldKey: key,
                            oldSecretRef: oldRef,
                            newSecretRef: newRef
                        ))
                    } else if oldField != newField {
                        changes.append(CatalogSemanticChange(
                            kind: .updateMetadataField,
                            indexID: newEntry.indexId,
                            entryID: entryID,
                            fieldKey: key,
                            oldSecretRef: oldRef,
                            newSecretRef: newRef
                        ))
                    }
                case (nil, nil):
                    break
                }
            }
        }

        let references = Set(
            old.entries.flatMap { $0.fields.compactMap(\.secretRef) }
                + new.entries.flatMap { $0.fields.compactMap(\.secretRef) }
        ).sorted()
        return Self(changes: changes, secretRefs: references)
    }
}

private struct SecretCatalogEntryMetadata: Equatable {
    let title: String
    let type: String
    let aliases: [String]
    let endpoints: [CatalogEndpoint]
    let notes: String?
    let tags: [String]

    init(entry: SecretCatalogEntry) {
        title = entry.title
        type = entry.type
        aliases = entry.aliases
        endpoints = entry.endpoints
        notes = entry.notes
        tags = entry.tags
    }
}

public enum CatalogBatchOperation: Codable, Equatable, Sendable {
    case createIndex(SecretCatalogIndex)
    case updateIndex(SecretCatalogIndex)
    case deleteIndex(id: String)
    case createEntry(SecretCatalogEntry)
    case updateEntry(SecretCatalogEntry)
    case moveEntry(id: String, toIndexID: String)
    case deleteEntry(id: String)
    case addField(entryID: String, field: SecretCatalogFieldValue)
    case updateField(entryID: String, field: SecretCatalogFieldValue)
    case removeField(entryID: String, key: String)

    private enum CodingKeys: String, CodingKey { case type, index, entry, id, toIndexID, entryID, field, key }
    private enum OperationType: String, Codable {
        case createIndex, updateIndex, deleteIndex, createEntry, updateEntry, moveEntry, deleteEntry
        case addField, updateField, removeField
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(OperationType.self, forKey: .type) {
        case .createIndex: self = .createIndex(try container.decode(SecretCatalogIndex.self, forKey: .index))
        case .updateIndex: self = .updateIndex(try container.decode(SecretCatalogIndex.self, forKey: .index))
        case .deleteIndex: self = .deleteIndex(id: try container.decode(String.self, forKey: .id))
        case .createEntry: self = .createEntry(try container.decode(SecretCatalogEntry.self, forKey: .entry))
        case .updateEntry: self = .updateEntry(try container.decode(SecretCatalogEntry.self, forKey: .entry))
        case .moveEntry:
            self = .moveEntry(
                id: try container.decode(String.self, forKey: .id),
                toIndexID: try container.decode(String.self, forKey: .toIndexID)
            )
        case .deleteEntry: self = .deleteEntry(id: try container.decode(String.self, forKey: .id))
        case .addField:
            self = .addField(
                entryID: try container.decode(String.self, forKey: .entryID),
                field: try container.decode(SecretCatalogFieldValue.self, forKey: .field)
            )
        case .updateField:
            self = .updateField(
                entryID: try container.decode(String.self, forKey: .entryID),
                field: try container.decode(SecretCatalogFieldValue.self, forKey: .field)
            )
        case .removeField:
            self = .removeField(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key)
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .createIndex(index): try container.encode(OperationType.createIndex, forKey: .type); try container.encode(index, forKey: .index)
        case let .updateIndex(index): try container.encode(OperationType.updateIndex, forKey: .type); try container.encode(index, forKey: .index)
        case let .deleteIndex(id): try container.encode(OperationType.deleteIndex, forKey: .type); try container.encode(id, forKey: .id)
        case let .createEntry(entry): try container.encode(OperationType.createEntry, forKey: .type); try container.encode(entry, forKey: .entry)
        case let .updateEntry(entry): try container.encode(OperationType.updateEntry, forKey: .type); try container.encode(entry, forKey: .entry)
        case let .moveEntry(id, toIndexID):
            try container.encode(OperationType.moveEntry, forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(toIndexID, forKey: .toIndexID)
        case let .deleteEntry(id): try container.encode(OperationType.deleteEntry, forKey: .type); try container.encode(id, forKey: .id)
        case let .addField(entryID, field):
            try container.encode(OperationType.addField, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(field, forKey: .field)
        case let .updateField(entryID, field):
            try container.encode(OperationType.updateField, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(field, forKey: .field)
        case let .removeField(entryID, key):
            try container.encode(OperationType.removeField, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
        }
    }
}

public struct CatalogBatchMutation: Codable, Equatable, Sendable {
    public let operations: [CatalogBatchOperation]

    public init(operations: [CatalogBatchOperation]) {
        self.operations = operations
    }

    public func semanticDiff(from document: SecretCatalogDocument) throws -> CatalogSemanticDiff {
        CatalogSemanticDiff.between(old: document, new: try applying(to: document))
    }

    public func applying(to document: SecretCatalogDocument) throws -> SecretCatalogDocument {
        var indexes = document.indexes
        var entries = document.entries

        for operation in operations {
            switch operation {
            case let .createIndex(index):
                guard !indexes.contains(where: { $0.id == index.id }) else { throw SecretCatalogValidationError.duplicateIndexID }
                indexes.append(index)
            case let .updateIndex(index):
                guard let offset = indexes.firstIndex(where: { $0.id == index.id }) else { throw SecretCatalogValidationError.invalidID }
                indexes[offset] = index
            case let .deleteIndex(id):
                guard indexes.contains(where: { $0.id == id }) else { throw SecretCatalogValidationError.invalidID }
                indexes.removeAll { $0.id == id }
                entries.removeAll { $0.indexId == id }
            case let .createEntry(entry):
                let current = SecretCatalogDocument(indexes: indexes, entries: entries)
                let updated = try current.insertingEntryInSourceOrder(entry)
                entries = updated.entries
            case let .updateEntry(entry):
                guard let offset = entries.firstIndex(where: { $0.id == entry.id }), indexes.contains(where: { $0.id == entry.indexId }) else {
                    throw SecretCatalogValidationError.invalidID
                }
                entries[offset] = entry
            case let .moveEntry(id, toIndexID):
                let current = SecretCatalogDocument(indexes: indexes, entries: entries)
                let updated = try current.movingEntryInSourceOrder(id: id, toIndexID: toIndexID)
                entries = updated.entries
            case let .deleteEntry(id):
                guard entries.contains(where: { $0.id == id }) else { throw SecretCatalogValidationError.invalidID }
                entries.removeAll { $0.id == id }
            case let .addField(entryID, field):
                guard let offset = entries.firstIndex(where: { $0.id == entryID }) else { throw SecretCatalogValidationError.invalidID }
                let old = entries[offset]
                guard !old.fields.contains(where: { $0.key == field.key }) else { throw SecretCatalogValidationError.duplicateFieldKey }
                entries[offset] = Self.replacingFields(in: old, with: old.fields + [field])
            case let .updateField(entryID, field):
                guard let entryOffset = entries.firstIndex(where: { $0.id == entryID }) else { throw SecretCatalogValidationError.invalidID }
                let old = entries[entryOffset]
                guard let fieldOffset = old.fields.firstIndex(where: { $0.key == field.key }) else { throw SecretCatalogValidationError.invalidID }
                var fields = old.fields
                fields[fieldOffset] = field
                entries[entryOffset] = Self.replacingFields(in: old, with: fields)
            case let .removeField(entryID, key):
                guard let entryOffset = entries.firstIndex(where: { $0.id == entryID }) else { throw SecretCatalogValidationError.invalidID }
                let old = entries[entryOffset]
                guard old.fields.contains(where: { $0.key == key }) else { throw SecretCatalogValidationError.invalidID }
                entries[entryOffset] = Self.replacingFields(in: old, with: old.fields.filter { $0.key != key })
            }
        }

        let result = SecretCatalogDocument(indexes: indexes, entries: entries)
        try result.validate()
        return result
    }

    private static func replacingFields(
        in entry: SecretCatalogEntry,
        with fields: [SecretCatalogFieldValue]
    ) -> SecretCatalogEntry {
        SecretCatalogEntry(
            id: entry.id, indexId: entry.indexId, title: entry.title, type: entry.type,
            aliases: entry.aliases, endpoints: entry.endpoints, fields: fields,
            notes: entry.notes, tags: entry.tags, schema: entry.schema
        )
    }
}
