import Foundation

/// Obsidian-native, lossless Markdown codec for Catalog v3.
///
/// Headings and field bodies remain ordinary Markdown. SVLT markers delimit
/// managed ranges, allowing a writer to patch one object without reformatting
/// the rest of the file.
public enum SensitiveCatalogDocumentCodec {
    public static let marker = "<!-- SVLT-CATALOG schema=\"3\" -->"
    public static let v3Marker = marker
    public static let v2Marker = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->"
    public static let rootTitle = "敏感信息"

    public enum DocumentFormat: String, Codable, Equatable, Sendable {
        case unmanaged
        case legacy
        case managedV2
        case managedV3
    }

    public static func format(_ data: Data) -> DocumentFormat {
        guard let text = String(data: data, encoding: .utf8) else { return .unmanaged }
        return format(text)
    }

    public static func format(_ text: String) -> DocumentFormat {
        let normalized = normalizeNewlines(text)
        if normalized.hasPrefix(v3Marker + "\n") || normalized == v3Marker { return .managedV3 }
        if normalized.hasPrefix(v2Marker + "\n") || normalized == v2Marker { return .managedV2 }
        if text.contains("agent-secret-vault-sensitive-information: 1") { return .legacy }
        return .unmanaged
    }

    public static func decode(_ data: Data) throws -> SecretCatalogDocument {
        guard let text = String(data: data, encoding: .utf8) else {
            throw SecretCatalogValidationError.unmanagedContent
        }
        return try decode(text)
    }

    public static func decode(_ text: String) throws -> SecretCatalogDocument {
        switch format(text) {
        case .managedV3: return try parseV3(text).document
        case .managedV2: return try decodeV2(text)
        case .legacy: throw SecretCatalogValidationError.legacyDocument
        case .unmanaged: throw SecretCatalogValidationError.invalidMarker
        }
    }

    public static func encode(_ document: SecretCatalogDocument) throws -> String {
        try document.validate()
        var lines = [v3Marker, "# \(rootTitle)", ""]
        lines.append(contentsOf: SVLTAgentCatalogPolicy.documentPolicyBlock.components(separatedBy: "\n"))
        lines.append("")
        for (offset, index) in document.indexes.enumerated() {
            if offset > 0 { lines.append("") }
            lines.append(contentsOf: renderIndex(index, entries: document.entries.filter { $0.indexId == index.id }))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func canonicalData(_ document: SecretCatalogDocument) throws -> Data {
        Data(try encode(document).utf8)
    }

    /// v2 is input-only and exists for the explicit App migration flow.
    public static func encodeV2(_ document: SecretCatalogDocument) throws -> String {
        try document.validate()
        let indexes = document.indexes.map {
            SecretCatalogIndex(id: $0.id, title: $0.title, aliases: $0.aliases, tags: $0.tags, schema: SecretCatalogIndex.legacySchemaName)
        }
        let entries = document.entries.map {
            SecretCatalogEntry(id: $0.id, indexId: $0.indexId, title: $0.title, type: $0.type, aliases: $0.aliases, endpoints: $0.endpoints, fields: $0.fields, notes: $0.notes, tags: $0.tags, schema: SecretCatalogEntry.legacySchemaName)
        }
        let fence = String(repeating: String(UnicodeScalar(96)!), count: 3)
        var lines = [v2Marker, "# \(rootTitle)", "", "> 本文件由 SVLT 管理。请勿直接修改结构化数据。", "> Agent 必须使用 SVLT MCP Catalog 工具修改。", ""]
        for (offset, index) in indexes.enumerated() {
            if offset > 0 { lines.append(contentsOf: ["", ""]) }
            lines += ["## \(index.title)", "", fence + "json", try canonicalJSON(index), fence]
            for entry in entries where entry.indexId == index.id {
                lines += ["", "", "### \(entry.title)", "", fence + "json", try canonicalJSON(entry), fence]
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func isManagedV2(_ data: Data) -> Bool { format(data) == .managedV2 }
    public static func isManagedV2(_ text: String) -> Bool { format(text) == .managedV2 }
    public static func isManagedV3(_ data: Data) -> Bool { format(data) == .managedV3 }
    public static func isManagedV3(_ text: String) -> Bool { format(text) == .managedV3 }

    /// Apply only the source ranges needed to turn old into new.
    public static func minimalPatch(_ data: Data, from old: SecretCatalogDocument, to new: SecretCatalogDocument) throws -> Data {
        guard format(data) == .managedV3 else { return try canonicalData(new) }
        try old.validate()
        try new.validate()
        let parsed = try parseV3(try utf8(data))
        guard parsed.document == old else { throw SecretCatalogValidationError.referenceSetChanged }

        let oldIndexes = Dictionary(uniqueKeysWithValues: old.indexes.map { ($0.id, $0) })
        let newIndexes = Dictionary(uniqueKeysWithValues: new.indexes.map { ($0.id, $0) })
        let oldEntries = Dictionary(uniqueKeysWithValues: old.entries.map { ($0.id, $0) })
        let newEntries = Dictionary(uniqueKeysWithValues: new.entries.map { ($0.id, $0) })
        var patches: [Patch] = []
        var deletedIndexes = Set<String>()
        var deletedEntries = Set<String>()
        var newIndexesOnDisk = Set<String>()

        for index in old.indexes where newIndexes[index.id] == nil {
            guard let source = parsed.source.indexes[index.id] else { throw SecretCatalogValidationError.missingIndexBlock }
            patch(&patches, source.blockRange, Data())
            deletedIndexes.insert(index.id)
        }
        for index in new.indexes where oldIndexes[index.id] == nil {
            newIndexesOnDisk.insert(index.id)
            let at = indexInsertOffset(index.id, new.indexes, parsed.source, data.count)
            let rendered = renderIndex(index, entries: new.entries.filter { $0.indexId == index.id }).joined(separator: "\n") + "\n"
            patch(&patches, at..<at, Data(rendered.utf8), order: new.indexes.firstIndex { $0.id == index.id } ?? 0)
        }
        for id in Set(oldIndexes.keys).intersection(newIndexes.keys) {
            guard !deletedIndexes.contains(id), let oldIndex = oldIndexes[id], let newIndex = newIndexes[id], let source = parsed.source.indexes[id] else { continue }
            if oldIndex.aliases != newIndex.aliases || oldIndex.tags != newIndex.tags {
                patch(&patches, source.markerRange, Data(renderIndexMarker(newIndex).utf8))
            }
            if oldIndex.title != newIndex.title {
                patch(&patches, source.headingRange, Data("## \(newIndex.title)".utf8))
            }
        }

        for entry in old.entries where newEntries[entry.id] == nil {
            if deletedIndexes.contains(entry.indexId) { continue }
            guard let source = parsed.source.entries[entry.id] else { throw SecretCatalogValidationError.missingEntryBlock }
            patch(&patches, source.blockRange, Data())
            deletedEntries.insert(entry.id)
        }
        for entry in new.entries where oldEntries[entry.id] == nil {
            if newIndexesOnDisk.contains(entry.indexId) { continue }
            guard let indexSource = parsed.source.indexes[entry.indexId] else { throw SecretCatalogValidationError.entryReferencesMissingIndex }
            let at = entryInsertOffset(entry.id, entry.indexId, new.entries, parsed.source, indexSource.closeStart)
            patch(&patches, at..<at, Data((renderEntry(entry).joined(separator: "\n") + "\n").utf8), order: new.entries.firstIndex { $0.id == entry.id } ?? 0)
        }

        for id in Set(oldEntries.keys).intersection(newEntries.keys) {
            guard !deletedEntries.contains(id), let oldEntry = oldEntries[id], let newEntry = newEntries[id] else { continue }
            // Deleting an index removes its complete source block. Avoid an
            // overlapping entry patch when an entry is moved out of that
            // index in the same mutation.
            if deletedIndexes.contains(oldEntry.indexId) { continue }
            guard let source = parsed.source.entries[id] else { continue }
            if oldEntry.indexId != newEntry.indexId {
                patch(&patches, source.blockRange, Data())
                // A newly inserted index already renders all of its final
                // entries in one block, so the moved entry must not also be
                // inserted into a source range that did not exist before.
                if newIndexesOnDisk.contains(newEntry.indexId) { continue }
                guard let destination = parsed.source.indexes[newEntry.indexId] else { throw SecretCatalogValidationError.entryReferencesMissingIndex }
                let at = entryInsertOffset(id, newEntry.indexId, new.entries, parsed.source, destination.closeStart)
                patch(&patches, at..<at, Data((renderEntry(newEntry).joined(separator: "\n") + "\n").utf8), order: new.entries.firstIndex { $0.id == id } ?? 0)
                continue
            }
            if oldEntry.type != newEntry.type || oldEntry.aliases != newEntry.aliases || oldEntry.endpoints != newEntry.endpoints || oldEntry.tags != newEntry.tags {
                patch(&patches, source.markerRange, Data(renderEntryMarker(newEntry).utf8))
            }
            if oldEntry.title != newEntry.title {
                patch(&patches, source.headingRange, Data("### \(newEntry.title)".utf8))
            }
            if oldEntry.notes != newEntry.notes {
                patch(&patches, source.notesRange, Data(renderNotes(newEntry.notes).utf8))
            }

            let oldFields = Dictionary(uniqueKeysWithValues: oldEntry.fields.map { ($0.key, $0) })
            let newFields = Dictionary(uniqueKeysWithValues: newEntry.fields.map { ($0.key, $0) })
            for field in oldEntry.fields where newFields[field.key] == nil {
                guard let source = parsed.source.fields[FieldKey(id: id, key: field.key)] else { throw SecretCatalogValidationError.duplicateFieldKey }
                patch(&patches, source.blockRange, Data())
            }
            for field in newEntry.fields where oldFields[field.key] == nil {
                let at = fieldInsertOffset(field.key, id, newEntry.fields, parsed.source, source.closeStart)
                patch(&patches, at..<at, Data(renderField(field).joined(separator: "\n").utf8), order: newEntry.fields.firstIndex { $0.key == field.key } ?? 0)
            }
            for key in Set(oldFields.keys).intersection(newFields.keys) {
                guard let oldField = oldFields[key], let newField = newFields[key], let source = parsed.source.fields[FieldKey(id: id, key: key)] else { continue }
                if oldField.label != newField.label || oldField.type != newField.type || oldField.agentVisible != newField.agentVisible || oldField.searchable != newField.searchable {
                    patch(&patches, source.markerRange, Data(renderFieldMarker(newField).utf8))
                }
                if oldField.value != newField.value || oldField.secretRef != newField.secretRef || oldField.label != newField.label {
                    patch(&patches, source.bodyRange, Data((renderFieldBody(newField) + "\n").utf8))
                }
            }
        }

        let result = apply(data, patches)
        guard try parseV3(try utf8(result)).document == new else { throw SecretCatalogValidationError.referenceSetChanged }
        return result
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct Line {
        let text: String
        let start: Int
        let contentEnd: Int
        let end: Int
    }
    struct IndexSource { let markerRange: Range<Int>; let headingRange: Range<Int>; let blockRange: Range<Int>; let closeStart: Int }
    struct EntrySource { let markerRange: Range<Int>; let headingRange: Range<Int>; let notesRange: Range<Int>; let blockRange: Range<Int>; let closeStart: Int }
    struct FieldKey: Hashable { let id: String; let key: String }
    struct FieldSource { let markerRange: Range<Int>; let bodyRange: Range<Int>; let blockRange: Range<Int> }
    struct Source { var indexes: [String: IndexSource] = [:]; var entries: [String: EntrySource] = [:]; var fields: [FieldKey: FieldSource] = [:] }
    struct Parsed { let document: SecretCatalogDocument; let source: Source }
    struct Patch { let start: Int; let end: Int; let data: Data; let order: Int }
    struct IndexState {
        let id: String; let aliases: [String]; let tags: [String]; let markerRange: Range<Int>
        var title: String?; var headingRange: Range<Int>?; var entries: [SecretCatalogEntry] = []; var entryIDs = Set<String>()
    }
    struct EntryState {
        let id: String; let type: String; let aliases: [String]; let endpoints: [CatalogEndpoint]; let tags: [String]; let indexID: String; let markerRange: Range<Int>
        var title: String?; var headingRange: Range<Int>?; var bodyStart: Int?; var notesEnd: Int?; var fields: [SecretCatalogFieldValue] = []; var fieldKeys = Set<String>()
    }
    struct FieldState {
        let id: String; let key: String; let label: String; let type: SecretCatalogFieldType; let agentVisible: Bool; let searchable: Bool; let markerRange: Range<Int>; let lineEnd: Int
    }

    static func parseV3(_ text: String) throws -> Parsed {
        try validatePolicyBlock(text)
        let data = Data(text.utf8)
        let lines = splitLines(data)
        guard lines.first?.text == marker else { throw SecretCatalogValidationError.invalidMarker }
        var source = Source()
        var indexes: [SecretCatalogIndex] = []
        var allEntries: [SecretCatalogEntry] = []
        var index: IndexState?
        var entry: EntryState?
        var field: FieldState?
        var policy = false
        var root = false

        for line in lines.dropFirst() {
            let trimmed = line.text.trimmingCharacters(in: .whitespaces)
            if trimmed == SVLTAgentCatalogPolicy.documentPolicyBeginMarker {
                guard !policy, index == nil, entry == nil, field == nil else { throw SecretCatalogValidationError.invalidHeading }
                policy = true
                continue
            }
            if policy {
                if trimmed == "<!-- SVLT-POLICY-END -->" { policy = false }
                continue
            }
            if let current = field {
                if trimmed == "<!-- /SVLT-FIELD -->" {
                    let bodyRange = current.lineEnd..<line.start
                    let parsed = try parseField(body: sliceText(data, range: bodyRange), state: current)
                    guard var currentEntry = entry, currentEntry.fieldKeys.insert(current.key).inserted else { throw SecretCatalogValidationError.duplicateFieldKey }
                    currentEntry.fields.append(parsed)
                    entry = currentEntry
                    source.fields[FieldKey(id: current.id, key: current.key)] = FieldSource(markerRange: current.markerRange, bodyRange: bodyRange, blockRange: current.markerRange.lowerBound..<line.end)
                    field = nil
                }
                continue
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-FIELD ", line: line) {
                guard var currentEntry = entry, currentEntry.title != nil else { throw SecretCatalogValidationError.missingEntryBlock }
                if currentEntry.notesEnd == nil { currentEntry.notesEnd = line.start }
                entry = currentEntry
                let value = try fieldMarker(raw.json)
                field = FieldState(id: currentEntry.id, key: value.key, label: value.label, type: value.type, agentVisible: value.agentVisible, searchable: value.searchable, markerRange: raw.range, lineEnd: line.end)
                continue
            }
            if trimmed == "<!-- /SVLT-ENTRY -->" {
                guard let current = entry, let title = current.title, let heading = current.headingRange, var currentIndex = index else { throw SecretCatalogValidationError.missingEntryBlock }
                let noteRange = (current.bodyStart ?? line.start)..<(current.notesEnd ?? line.start)
                let value = SecretCatalogEntry(id: current.id, indexId: current.indexID, title: title, type: current.type, aliases: current.aliases, endpoints: current.endpoints, fields: current.fields, notes: parseNotes(sliceText(data, range: noteRange)), tags: current.tags)
                try value.validateStandalone()
                guard currentIndex.entryIDs.contains(value.id) else { throw SecretCatalogValidationError.duplicateEntryID }
                currentIndex.entries.append(value)
                index = currentIndex
                source.entries[value.id] = EntrySource(markerRange: current.markerRange, headingRange: heading, notesRange: noteRange, blockRange: current.markerRange.lowerBound..<line.end, closeStart: line.start)
                entry = nil
                continue
            }
            if trimmed == "<!-- /SVLT-INDEX -->" {
                guard entry == nil, let current = index, let title = current.title, let heading = current.headingRange else { throw SecretCatalogValidationError.missingIndexBlock }
                let value = SecretCatalogIndex(id: current.id, title: title, aliases: current.aliases, tags: current.tags)
                try value.validateStandalone()
                indexes.append(value)
                allEntries.append(contentsOf: current.entries)
                source.indexes[value.id] = IndexSource(markerRange: current.markerRange, headingRange: heading, blockRange: current.markerRange.lowerBound..<line.end, closeStart: line.start)
                index = nil
                continue
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-INDEX ", line: line) {
                guard index == nil, entry == nil else { throw SecretCatalogValidationError.invalidHeading }
                let value = try indexMarker(raw.json)
                index = IndexState(id: value.id, aliases: value.aliases, tags: value.tags, markerRange: raw.range)
                continue
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-ENTRY ", line: line) {
                guard var currentIndex = index, entry == nil, currentIndex.title != nil else { throw SecretCatalogValidationError.missingIndexBlock }
                let value = try entryMarker(raw.json)
                guard currentIndex.entryIDs.insert(value.id).inserted else { throw SecretCatalogValidationError.duplicateEntryID }
                index = currentIndex
                entry = EntryState(id: value.id, type: value.type, aliases: value.aliases, endpoints: value.endpoints, tags: value.tags, indexID: currentIndex.id, markerRange: raw.range)
                continue
            }
            if let heading = heading(trimmed) {
                switch heading.level {
                case 1:
                    guard !root, index == nil, entry == nil, heading.title == rootTitle else { throw SecretCatalogValidationError.invalidHeading }
                    root = true
                case 2:
                    guard root else { throw SecretCatalogValidationError.invalidHeading }
                    guard var currentIndex = index, entry == nil else { continue }
                    // Once a group heading has been consumed, later ##
                    // headings are ordinary user Markdown inside that
                    // marker-bounded group and remain part of its source map.
                    guard currentIndex.title == nil else { continue }
                    currentIndex.title = heading.title
                    currentIndex.headingRange = line.start..<line.contentEnd
                    index = currentIndex
                case 3:
                    guard root else { throw SecretCatalogValidationError.invalidHeading }
                    guard var currentEntry = entry else { continue }
                    // A real entry heading is required immediately after its
                    // SVLT-ENTRY marker. After that point ### is user prose.
                    guard currentEntry.title == nil else { continue }
                    currentEntry.title = heading.title
                    currentEntry.headingRange = line.start..<line.contentEnd
                    currentEntry.bodyStart = line.end
                    entry = currentEntry
                default:
                    continue
                }
                continue
            }
            if entry == nil && index == nil && !root && !trimmed.isEmpty { throw SecretCatalogValidationError.invalidHeading }
        }
        guard root, !policy, field == nil, entry == nil, index == nil else { throw SecretCatalogValidationError.invalidHeading }
        let document = SecretCatalogDocument(indexes: indexes, entries: allEntries)
        try document.validate()
        return Parsed(document: document, source: source)
    }

    static func validatePolicyBlock(_ text: String) throws {
        let lines = normalizeNewlines(text).components(separatedBy: "\n")
        let beginLines = lines.enumerated().compactMap { offset, line in
            line.trimmingCharacters(in: .whitespaces) == SVLTAgentCatalogPolicy.documentPolicyBeginMarker
                ? offset
                : nil
        }
        let endLines = lines.enumerated().compactMap { offset, line in
            line.trimmingCharacters(in: .whitespaces) == SVLTAgentCatalogPolicy.documentPolicyEndMarker
                ? offset
                : nil
        }
        guard beginLines.count == 1, endLines.count == 1,
              let begin = beginLines.first, let end = endLines.first, begin < end
        else {
            throw SecretCatalogValidationError.invalidPolicyBlock
        }

        let block = lines[begin...end].joined(separator: "\n")
        guard block == SVLTAgentCatalogPolicy.documentPolicyBlock else {
            throw SecretCatalogValidationError.invalidPolicyBlock
        }
    }

    static func parseField(body: String, state: FieldState) throws -> SecretCatalogFieldValue {
        let normalized = normalizeNewlines(body).trimmingCharacters(in: CharacterSet.newlines)
        let parts = normalized.components(separatedBy: "\n")
        var label = state.label.isEmpty ? state.key : state.label
        var content = normalized
        if let first = parts.first, let separator = first.range(of: "：") ?? first.range(of: ":") {
            let prefix = first[..<separator.lowerBound]
            if prefix.hasPrefix("- ") {
                label = String(prefix.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                content = ([String(first[separator.upperBound...])] + parts.dropFirst()).joined(separator: "\n")
            }
        }
        content = content.trimmingCharacters(in: CharacterSet.newlines)
        let tick = String(UnicodeScalar(96)!)
        let valueText = content.hasPrefix(tick) && content.hasSuffix(tick) && content.count >= 2 ? String(content.dropFirst().dropLast()) : content
        let value: SecretCatalogValue?
        var secretRef: String?
        if state.type.isSecret {
            guard valueText.isEmpty || (try? SecretReference(valueText)) != nil else { throw SecretCatalogValidationError.secretFieldContainsValue }
            secretRef = valueText.isEmpty ? nil : valueText
            value = nil
        } else {
            secretRef = nil
            if valueText.isEmpty {
                value = nil
            } else {
                switch state.type {
                case .text, .multiline, .url, .host, .date: value = .string(valueText)
                case .number, .port:
                    guard let number = Double(valueText), number.isFinite else { throw SecretCatalogValidationError.invalidFieldValue }
                    value = .number(number)
                case .boolean:
                    guard let boolean = Bool(valueText) else { throw SecretCatalogValidationError.invalidFieldValue }
                    value = .boolean(boolean)
                case .list:
                    if let data = valueText.data(using: .utf8), let list = try? JSONDecoder().decode([String].self, from: data) { value = .list(list) }
                    else { value = .list(valueText.components(separatedBy: "\n")) }
                case .secret: value = nil
                }
            }
        }
        let field = SecretCatalogFieldValue(key: state.key, label: label, type: state.type, agentVisible: state.agentVisible, searchable: state.searchable, value: value, secretRef: secretRef)
        try CatalogValidationProxy.validate(field)
        return field
    }

    static func parseNotes(_ body: String) -> String? {
        let value = normalizeNewlines(body).trimmingCharacters(in: CharacterSet.newlines)
        guard !value.isEmpty else { return nil }
        let lines = value.components(separatedBy: "\n")
        if lines.first?.trimmingCharacters(in: .whitespaces) == "<!-- SVLT-NOTES-BEGIN -->", lines.last?.trimmingCharacters(in: .whitespaces) == "<!-- SVLT-NOTES-END -->" {
            let notes = Array(lines.dropFirst().dropLast()).joined(separator: "\n").trimmingCharacters(in: CharacterSet.newlines)
            return notes.isEmpty ? nil : notes
        }
        return value
    }

    static func marker(_ value: String, prefix: String, line: Line) -> (json: String, range: Range<Int>)? {
        guard value.hasPrefix(prefix), value.hasSuffix(" -->") else { return nil }
        let start = value.index(value.startIndex, offsetBy: prefix.count)
        let end = value.index(value.endIndex, offsetBy: -4)
        return (String(value[start..<end]), line.start..<line.contentEnd)
    }

    static func indexMarker(_ json: String) throws -> (id: String, aliases: [String], tags: [String]) {
        let object = try object(json, allowed: ["id", "aliases", "tags"], required: ["id"])
        guard let id = object["id"] as? String else { throw SecretCatalogValidationError.malformedJSON }
        return (id, (object["aliases"] as? [Any])?.compactMap { $0 as? String } ?? [], (object["tags"] as? [Any])?.compactMap { $0 as? String } ?? [])
    }

    static func entryMarker(_ json: String) throws -> (id: String, type: String, aliases: [String], endpoints: [CatalogEndpoint], tags: [String]) {
        let object = try object(json, allowed: ["id", "type", "aliases", "endpoints", "tags"], required: ["id", "type"])
        guard let id = object["id"] as? String, let type = object["type"] as? String else { throw SecretCatalogValidationError.malformedJSON }
        let endpoints: [CatalogEndpoint]
        if let raw = object["endpoints"] {
            endpoints = try JSONDecoder().decode([CatalogEndpoint].self, from: JSONSerialization.data(withJSONObject: raw))
        } else { endpoints = [] }
        return (id, type, (object["aliases"] as? [Any])?.compactMap { $0 as? String } ?? [], endpoints, (object["tags"] as? [Any])?.compactMap { $0 as? String } ?? [])
    }

    static func fieldMarker(_ json: String) throws -> (key: String, label: String, type: SecretCatalogFieldType, agentVisible: Bool, searchable: Bool) {
        let object = try object(json, allowed: ["key", "label", "type", "agentVisible", "searchable"], required: ["key", "type"])
        guard let key = object["key"] as? String, let rawType = object["type"] as? String, let type = SecretCatalogFieldType(rawValue: rawType) else { throw SecretCatalogValidationError.malformedJSON }
        return (key, object["label"] as? String ?? key, type, object["agentVisible"] as? Bool ?? true, object["searchable"] as? Bool ?? true)
    }

    static func object(_ json: String, allowed: Set<String>, required: Set<String>) throws -> [String: Any] {
        guard let data = json.data(using: .utf8), let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys).isSubset(of: allowed), required.isSubset(of: Set(value.keys)) else { throw SecretCatalogValidationError.malformedJSON }
        return value
    }

    static func splitLines(_ data: Data) -> [Line] {
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { return [] }
        var result: [Line] = []
        var start = 0
        for index in 0...bytes.count where index == bytes.count || bytes[index] == 0x0A {
            let end = index > start && bytes[index - 1] == 0x0D ? index - 1 : index
            result.append(Line(text: String(decoding: bytes[start..<end], as: UTF8.self), start: start, contentEnd: end, end: min(index + 1, bytes.count)))
            start = index + 1
        }
        return result
    }

    static func sliceText(_ data: Data, range: Range<Int>) -> String {
        guard !range.isEmpty else { return "" }
        return String(decoding: [UInt8](data)[range], as: UTF8.self)
    }

    static func heading(_ line: String) -> (level: Int, title: String)? {
        let level = line.prefix(while: { $0 == "#" }).count
        guard (1...3).contains(level) else { return nil }
        let remainder = line.dropFirst(level)
        guard remainder.first == " " || remainder.first == "\t" else { return nil }
        let title = String(remainder).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty, !title.contains("\0") else { return nil }
        return (level, title)
    }

    static func normalizeNewlines(_ value: String) -> String {
        value.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
    }

    static func utf8(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else { throw SecretCatalogValidationError.unmanagedContent }
        return value
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct IndexMarkerValue: Codable { let id: String; let aliases: [String]; let tags: [String] }
    struct EntryMarkerValue: Codable { let id: String; let type: String; let aliases: [String]; let endpoints: [CatalogEndpoint]; let tags: [String] }
    struct FieldMarkerValue: Codable { let key: String; let label: String; let type: String; let agentVisible: Bool; let searchable: Bool }

    static func compact<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? String(data: encoder.encode(value), encoding: .utf8)) ?? "{}"
    }

    static func canonicalJSON<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let text = String(data: try encoder.encode(value), encoding: .utf8), !text.contains("\r") else {
            throw SecretCatalogValidationError.malformedJSON
        }
        return text
    }

    static func renderIndexMarker(_ index: SecretCatalogIndex) -> String {
        "<!-- SVLT-INDEX \(compact(IndexMarkerValue(id: index.id, aliases: index.aliases, tags: index.tags))) -->"
    }
    static func renderEntryMarker(_ entry: SecretCatalogEntry) -> String {
        "<!-- SVLT-ENTRY \(compact(EntryMarkerValue(id: entry.id, type: entry.type, aliases: entry.aliases, endpoints: entry.endpoints, tags: entry.tags))) -->"
    }
    static func renderFieldMarker(_ field: SecretCatalogFieldValue) -> String {
        "<!-- SVLT-FIELD \(compact(FieldMarkerValue(key: field.key, label: field.label, type: field.type.rawValue, agentVisible: field.agentVisible, searchable: field.searchable))) -->"
    }
    static func renderIndex(_ index: SecretCatalogIndex, entries: [SecretCatalogEntry]) -> [String] {
        var result = [renderIndexMarker(index), "## \(index.title)", ""]
        for entry in entries { result.append(contentsOf: renderEntry(entry)) }
        result.append("<!-- /SVLT-INDEX -->")
        return result
    }
    static func renderEntry(_ entry: SecretCatalogEntry) -> [String] {
        var result = [renderEntryMarker(entry), "### \(entry.title)", ""]
        if let notes = entry.notes {
            result += ["<!-- SVLT-NOTES-BEGIN -->"] + notes.components(separatedBy: "\n") + ["<!-- SVLT-NOTES-END -->", ""]
        }
        for field in entry.fields { result.append(contentsOf: renderField(field)) }
        result.append("<!-- /SVLT-ENTRY -->")
        return result
    }
    static func renderField(_ field: SecretCatalogFieldValue) -> [String] {
        [renderFieldMarker(field)] + renderFieldBody(field).components(separatedBy: "\n") + ["<!-- /SVLT-FIELD -->", ""]
    }
    static func renderFieldBody(_ field: SecretCatalogFieldValue) -> String {
        let prefix = "- \(field.label)："
        if let secretRef = field.secretRef {
            let tick = String(UnicodeScalar(96)!)
            return prefix + tick + secretRef + tick
        }
        guard let value = field.value else { return prefix }
        switch value {
        case .string(let value): return prefix + value
        case .number(let value): return prefix + String(value)
        case .boolean(let value): return prefix + String(value)
        case .list(let value):
            let data = try? JSONEncoder().encode(value)
            return prefix + (data.flatMap { String(data: $0, encoding: .utf8) } ?? "[]")
        }
    }
    static func renderNotes(_ notes: String?) -> String {
        guard let notes else { return "" }
        return "\n<!-- SVLT-NOTES-BEGIN -->\n\(notes)\n<!-- SVLT-NOTES-END -->\n"
    }
    static func patch(_ patches: inout [Patch], _ range: Range<Int>, _ data: Data, order: Int = 0) {
        if range.isEmpty, let i = patches.firstIndex(where: { $0.start == range.lowerBound && $0.end == range.upperBound }) {
            let old = patches[i]
            patches[i] = order < old.order
                ? Patch(start: old.start, end: old.end, data: data + old.data, order: order)
                : Patch(start: old.start, end: old.end, data: old.data + data, order: old.order)
        } else {
            patches.append(Patch(start: range.lowerBound, end: range.upperBound, data: data, order: order))
        }
    }
    static func apply(_ source: Data, _ patches: [Patch]) -> Data {
        var bytes = [UInt8](source)
        for item in patches.sorted(by: { $0.start == $1.start ? $0.end > $1.end : $0.start > $1.start }) {
            bytes.replaceSubrange(item.start..<item.end, with: item.data)
        }
        return Data(bytes)
    }
    static func indexInsertOffset(_ id: String, _ indexes: [SecretCatalogIndex], _ source: Source, _ end: Int) -> Int {
        guard let position = indexes.firstIndex(where: { $0.id == id }) else { return end }
        for next in indexes.dropFirst(position + 1) { if let source = source.indexes[next.id] { return source.blockRange.lowerBound } }
        return end
    }
    static func entryInsertOffset(_ id: String, _ indexID: String, _ entries: [SecretCatalogEntry], _ source: Source, _ fallback: Int) -> Int {
        guard let position = entries.firstIndex(where: { $0.id == id }) else { return fallback }
        for next in entries.dropFirst(position + 1) where next.indexId == indexID { if let source = source.entries[next.id] { return source.blockRange.lowerBound } }
        return fallback
    }
    static func fieldInsertOffset(_ key: String, _ entryID: String, _ fields: [SecretCatalogFieldValue], _ source: Source, _ fallback: Int) -> Int {
        guard let position = fields.firstIndex(where: { $0.key == key }) else { return fallback }
        for next in fields.dropFirst(position + 1) { if let source = source.fields[FieldKey(id: entryID, key: next.key)] { return source.blockRange.lowerBound } }
        return fallback
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct Envelope: Decodable { let schema: String }
    static func decodeV2(_ text: String) throws -> SecretCatalogDocument {
        let lines = normalizeNewlines(text).components(separatedBy: "\n")
        guard lines.first == v2Marker else { throw SecretCatalogValidationError.invalidMarker }
        let fence = String(repeating: String(UnicodeScalar(96)!), count: 3)
        var root = false; var indexTitle: String?; var entryTitle: String?; var active: SecretCatalogIndex?
        var indexes: [SecretCatalogIndex] = []; var entries: [SecretCatalogEntry] = []
        var indexCount = 0; var entryCount = 0; var inFence = false; var json: [String] = []; var level = 0
        for line in lines.dropFirst() {
            if inFence {
                if line == fence {
                    inFence = false
                    try decodeV2Block(json.joined(separator: "\n"), level: level, indexTitle: indexTitle, entryTitle: entryTitle, active: active, indexes: &indexes, entries: &entries, indexCount: &indexCount, entryCount: &entryCount, current: &active)
                    json.removeAll(keepingCapacity: true)
                } else { json.append(line) }
                continue
            }
            if let value = heading(line) {
                switch value.level {
                case 1: guard !root, value.title == rootTitle else { throw SecretCatalogValidationError.invalidHeading }; root = true
                case 2: guard root else { throw SecretCatalogValidationError.invalidHeading }; try finish(entryTitle, entryCount); try finish(indexTitle, indexCount); indexTitle = value.title; entryTitle = nil; active = nil; indexCount = 0; entryCount = 0
                case 3: guard root, indexTitle != nil, active != nil else { throw SecretCatalogValidationError.invalidHeading }; try finish(entryTitle, entryCount); entryTitle = value.title; entryCount = 0
                default: throw SecretCatalogValidationError.invalidHeading
                }
                continue
            }
            if line == fence + "json" {
                guard root, indexTitle != nil else { throw SecretCatalogValidationError.invalidHeading }
                inFence = true; level = entryTitle == nil ? 2 : 3; json.removeAll(keepingCapacity: true); continue
            }
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty || trimmed == "> 本文件由 SVLT 管理。请勿直接修改结构化数据。" || trimmed == "> Agent 必须使用 SVLT MCP Catalog 工具修改。" else {
                throw SecretCatalogValidationError.unmanagedContent
            }
        }
        guard root, !inFence else { throw SecretCatalogValidationError.malformedJSON }
        try finish(entryTitle, entryCount); try finish(indexTitle, indexCount)
        let document = SecretCatalogDocument(indexes: indexes, entries: entries); try document.validate(); return document
    }
    static func decodeV2Block(_ json: String, level: Int, indexTitle: String?, entryTitle: String?, active: SecretCatalogIndex?, indexes: inout [SecretCatalogIndex], entries: inout [SecretCatalogEntry], indexCount: inout Int, entryCount: inout Int, current: inout SecretCatalogIndex?) throws {
        guard let data = json.data(using: .utf8), let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else { throw SecretCatalogValidationError.malformedJSON }
        switch (level, envelope.schema) {
        case (2, SecretCatalogIndex.legacySchemaName):
            guard indexCount == 0, let title = indexTitle else { throw SecretCatalogValidationError.missingIndexBlock }
            let old = try JSONDecoder().decode(SecretCatalogIndex.self, from: data); guard old.title == title else { throw SecretCatalogValidationError.headingDoesNotMatchBlock }
            let value = SecretCatalogIndex(id: old.id, title: old.title, aliases: old.aliases, tags: old.tags); try value.validateStandalone(); indexes.append(value); current = value; indexCount += 1
        case (3, SecretCatalogEntry.legacySchemaName):
            guard entryCount == 0, let title = entryTitle, let active else { throw SecretCatalogValidationError.missingEntryBlock }
            let old = try JSONDecoder().decode(SecretCatalogEntry.self, from: data); guard old.title == title, old.indexId == active.id else { throw SecretCatalogValidationError.headingDoesNotMatchBlock }
            entries.append(SecretCatalogEntry(id: old.id, indexId: old.indexId, title: old.title, type: old.type, aliases: old.aliases, endpoints: old.endpoints, fields: old.fields, notes: old.notes, tags: old.tags)); entryCount += 1
        default: throw SecretCatalogValidationError.unknownSchema
        }
    }
    static func finish(_ title: String?, _ count: Int) throws { guard title == nil || count == 1 else { throw SecretCatalogValidationError.missingEntryBlock } }
}

private extension SecretCatalogIndex {
    func validateStandalone() throws { try SecretCatalogOpaqueID.validate(id); guard !title.isEmpty, !title.contains("\n"), !title.contains("\r") else { throw SecretCatalogValidationError.invalidVisibleText } }
}

private extension SecretCatalogEntry {
    func validateStandalone() throws { try SecretCatalogOpaqueID.validate(id); guard !title.isEmpty, !title.contains("\n"), !title.contains("\r") else { throw SecretCatalogValidationError.invalidVisibleText } }
}

private enum CatalogValidationProxy {
    static func validate(_ field: SecretCatalogFieldValue) throws {
        let indexID = "0123456789ABCDEFGHJKMNPQRS"; let entryID = "0123456789ABCDEFGHJKMNPQRT"
        try SecretCatalogDocument(indexes: [SecretCatalogIndex(id: indexID, title: "校验")], entries: [SecretCatalogEntry(id: entryID, indexId: indexID, title: "校验", fields: [field])]).validate()
    }
}
