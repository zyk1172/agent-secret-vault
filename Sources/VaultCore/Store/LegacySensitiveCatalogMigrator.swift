import Foundation

public struct SecretCatalogMigrationAmbiguity: Codable, Equatable, Sendable {
    public let reference: String
    public let entryID: String
    public let suggestedKeys: [String]

    public init(reference: String, entryID: String, suggestedKeys: [String] = ["username", "password", "token", "other"]) {
        self.reference = reference
        self.entryID = entryID
        self.suggestedKeys = suggestedKeys
    }
}

public struct SecretCatalogMigrationPlaintextIssue: Codable, Equatable, Sendable {
    public let entryID: String
    public let fieldKey: String

    public init(entryID: String, fieldKey: String) {
        self.entryID = entryID
        self.fieldKey = fieldKey
    }
}

public struct SecretCatalogMigrationPreview: Codable, Equatable, Sendable {
    public let document: SecretCatalogDocument
    public let referencesBefore: [String]
    public let referencesAfter: [String]
    public let ambiguousReferences: [SecretCatalogMigrationAmbiguity]
    public let plaintextSensitiveFields: [SecretCatalogMigrationPlaintextIssue]

    public init(
        document: SecretCatalogDocument,
        referencesBefore: [String],
        referencesAfter: [String],
        ambiguousReferences: [SecretCatalogMigrationAmbiguity],
        plaintextSensitiveFields: [SecretCatalogMigrationPlaintextIssue]
    ) {
        self.document = document
        self.referencesBefore = referencesBefore
        self.referencesAfter = referencesAfter
        self.ambiguousReferences = ambiguousReferences
        self.plaintextSensitiveFields = plaintextSensitiveFields
    }

    public var referenceSetPreserved: Bool {
        Set(referencesBefore) == Set(referencesAfter)
    }

    public var requiresUserResolution: Bool {
        !ambiguousReferences.isEmpty || !plaintextSensitiveFields.isEmpty
    }
}

public enum LegacySensitiveCatalogMigratorError: Error, Equatable, Sendable {
    case managedDocumentAlreadyV2
    case referenceSetChanged
    case invalidGeneratedDocument
}

/// Converts legacy human-authored Markdown into a v2 preview.  This type is
/// intentionally not used by normal catalog search.  It never guesses the
/// role of an unlabelled `secret://` reference and never copies a plaintext
/// password/token into the preview.
public enum LegacySensitiveCatalogMigrator {
    private static let referencePattern = "secret://[0-9A-HJKMNP-TV-Z]{26}"
    private static let sensitiveKeys: Set<String> = [
        "password", "pass", "pwd", "token", "apikey", "api密钥", "cookie", "privatekey", "secret", "密码", "令牌", "密钥", "私钥"
    ]

    public static func preview(_ text: String) throws -> SecretCatalogMigrationPreview {
        guard !SensitiveCatalogDocumentCodec.isManagedV2(text) else {
            throw LegacySensitiveCatalogMigratorError.managedDocumentAlreadyV2
        }

        let referencesBefore = MarkdownReferenceScanner.references(in: text).sorted()
        let blocks = parseBlocks(text)
        var indexByTitle: [String: SecretCatalogIndex] = [:]
        var indexes: [SecretCatalogIndex] = []
        var entries: [SecretCatalogEntry] = []
        var ambiguities: [SecretCatalogMigrationAmbiguity] = []
        var plaintextIssues: [SecretCatalogMigrationPlaintextIssue] = []

        for block in blocks where !block.references.isEmpty || !block.metadata.isEmpty {
            let indexTitle = block.indexTitle
            let normalizedIndexTitle = normalize(indexTitle)
            let index: SecretCatalogIndex
            if let existing = indexByTitle[normalizedIndexTitle] {
                index = existing
            } else {
                index = try SecretCatalogIndex.generated(title: indexTitle)
                indexByTitle[normalizedIndexTitle] = index
                indexes.append(index)
            }

            let entry = try makeEntry(
                block,
                indexID: index.id,
                ambiguities: &ambiguities,
                plaintextIssues: &plaintextIssues
            )
            entries.append(entry)
        }

        if entries.isEmpty, !referencesBefore.isEmpty {
            let index = try SecretCatalogIndex.generated(title: "待确认迁移")
            let entryID = try SecretCatalogOpaqueID.generate()
            var fields: [SecretCatalogFieldValue] = []
            for (offset, reference) in referencesBefore.enumerated() {
                let key = "unclassified-secret-\(offset + 1)"
                fields.append(SecretCatalogFieldValue(
                    key: key,
                    label: "未识别秘密 \(offset + 1)",
                    type: .secret,
                    agentVisible: true,
                    searchable: true,
                    secretRef: reference
                ))
                ambiguities.append(SecretCatalogMigrationAmbiguity(reference: reference, entryID: entryID))
            }
            indexes = [index]
            entries = [SecretCatalogEntry(
                id: entryID,
                indexId: index.id,
                title: "待确认迁移",
                fields: fields
            )]
        }

        let document = SecretCatalogDocument(indexes: indexes, entries: entries)
        try document.validate()

        let referencesAfter = references(in: document).sorted()
        guard Set(referencesBefore) == Set(referencesAfter) else {
            throw LegacySensitiveCatalogMigratorError.referenceSetChanged
        }

        return SecretCatalogMigrationPreview(
            document: document,
            referencesBefore: referencesBefore,
            referencesAfter: referencesAfter,
            ambiguousReferences: ambiguities,
            plaintextSensitiveFields: plaintextIssues
        )
    }

    public static func canonicalData(for preview: SecretCatalogMigrationPreview) throws -> Data {
        guard preview.referenceSetPreserved else {
            throw LegacySensitiveCatalogMigratorError.referenceSetChanged
        }
        return try SensitiveCatalogDocumentCodec.canonicalData(preview.document)
    }

    private static func makeEntry(
        _ block: LegacyBlock,
        indexID: String,
        ambiguities: inout [SecretCatalogMigrationAmbiguity],
        plaintextIssues: inout [SecretCatalogMigrationPlaintextIssue]
    ) throws -> SecretCatalogEntry {
        let entryID = try SecretCatalogOpaqueID.generate()
        var fields: [SecretCatalogFieldValue] = []
        var endpoints: [CatalogEndpoint] = []
        var tags: [String] = block.headings
            .dropFirst()
            .map { sanitizeVisible($0) }
            .filter { !$0.isEmpty }

        for metadata in block.metadata {
            let key = canonicalKey(metadata.key)
            guard !key.isEmpty else { continue }
            let value = metadata.value
            if let role = SecretCatalogField.fromKey(metadata.key) {
                let roleKey = legacyFieldKey(role)
                let refs = MarkdownReferenceScanner.references(in: value)
                if !refs.isEmpty {
                    for (offset, reference) in refs.enumerated() {
                        let fieldKey = uniqueKey(roleKey, existing: fields, offset: offset)
                        fields.append(SecretCatalogFieldValue(
                            key: fieldKey,
                            label: role.displayName,
                            type: .secret,
                            agentVisible: true,
                            searchable: true,
                            secretRef: reference
                        ))
                    }
                } else if isSensitive(metadata.key) {
                    plaintextIssues.append(SecretCatalogMigrationPlaintextIssue(entryID: entryID, fieldKey: roleKey))
                    fields.append(SecretCatalogFieldValue(
                        key: uniqueKey(roleKey, existing: fields),
                        label: role.displayName,
                        type: .secret,
                        agentVisible: true,
                        searchable: true
                    ))
                } else {
                    fields.append(SecretCatalogFieldValue(
                        key: uniqueKey(roleKey, existing: fields),
                        label: role.displayName,
                        type: .text,
                        agentVisible: true,
                        searchable: true,
                        value: .string(sanitizeVisible(value))
                    ))
                }
                continue
            }

            let refs = MarkdownReferenceScanner.references(in: value)
            if !refs.isEmpty {
                for (offset, reference) in refs.enumerated() {
                    let fieldKey = uniqueKey("unclassified-secret", existing: fields, offset: offset)
                    fields.append(SecretCatalogFieldValue(
                        key: fieldKey,
                        label: "未识别秘密",
                        type: .secret,
                        agentVisible: true,
                        searchable: true,
                        secretRef: reference
                    ))
                    ambiguities.append(SecretCatalogMigrationAmbiguity(
                        reference: reference,
                        entryID: entryID
                    ))
                }
                continue
            }

            let safeValue = sanitizeVisible(value)
            guard !safeValue.isEmpty else { continue }
            let fieldType: SecretCatalogFieldType = key == "port" && Int(safeValue) != nil ? .port : (key == "url" ? .url : (key == "host" ? .host : .text))
            let fieldValue: SecretCatalogValue = fieldType == .port ? .number(Double(Int(safeValue) ?? 0)) : .string(safeValue)
            fields.append(SecretCatalogFieldValue(
                key: uniqueKey(key, existing: fields),
                label: safeLabel(metadata.key, fallback: key),
                type: fieldType,
                agentVisible: true,
                searchable: true,
                value: fieldValue
            ))

            if ["host", "url"].contains(key) {
                endpoints.append(contentsOf: endpointsFor(value: safeValue))
            }
            if key == "tag" {
                tags.append(safeValue)
            }
        }

        for (offset, reference) in block.unlabelledReferences.enumerated() {
            let fieldKey = uniqueKey("unclassified-secret", existing: fields, offset: offset)
            fields.append(SecretCatalogFieldValue(
                key: fieldKey,
                label: "未识别秘密",
                type: .secret,
                agentVisible: true,
                searchable: true,
                secretRef: reference
            ))
            ambiguities.append(SecretCatalogMigrationAmbiguity(
                reference: reference,
                entryID: entryID
            ))
        }

        let title = sanitizeVisible(block.entryTitle).isEmpty ? block.indexTitle : sanitizeVisible(block.entryTitle)
        return SecretCatalogEntry(
            id: entryID,
            indexId: indexID,
            title: title,
            aliases: [],
            endpoints: uniqueEndpoints(endpoints),
            fields: fields,
            notes: block.note.isEmpty ? nil : block.note,
            tags: Array(Set(tags)).sorted()
        )
    }

    private static func parseBlocks(_ text: String) -> [LegacyBlock] {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.components(separatedBy: "\n")
        var headings: [String] = []
        var current = LegacyBlockBuilder(headings: [])
        var blocks: [LegacyBlock] = []

        func finish() {
            if !current.metadata.isEmpty || !current.references.isEmpty || !current.note.isEmpty {
                blocks.append(current.build())
            }
            current = LegacyBlockBuilder(headings: headings)
        }

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if let heading = parseHeading(trimmed) {
                if heading.level <= (headings.count == 0 ? 1 : headings.count) && (!current.metadata.isEmpty || !current.references.isEmpty) {
                    finish()
                }
                if headings.count >= heading.level {
                    headings = Array(headings.prefix(heading.level - 1))
                }
                headings.append(heading.title)
                current = LegacyBlockBuilder(headings: headings)
                continue
            }

            if let pair = parseKeyValue(trimmed) {
                current.metadata.append(pair)
                current.references.append(contentsOf: MarkdownReferenceScanner.references(in: pair.value))
                let normalizedKey = normalize(pair.key)
                if ["备注", "note", "notes", "说明"].contains(normalizedKey) {
                    current.note = sanitizeVisible(pair.value)
                }
                continue
            }

            let refs = MarkdownReferenceScanner.references(in: line)
            if !refs.isEmpty {
                current.references.append(contentsOf: refs)
                current.unlabelledReferences.append(contentsOf: refs)
            }
        }
        finish()
        return blocks
    }

    private static func references(in document: SecretCatalogDocument) -> [String] {
        document.entries.flatMap { entry in
            entry.fields.compactMap(\.secretRef)
        }
    }

    private static func parseHeading(_ line: String) -> (level: Int, title: String)? {
        let level = line.prefix(while: { $0 == "#" }).count
        guard (1...6).contains(level) else { return nil }
        let remainder = line.dropFirst(level)
        guard remainder.first == " " || remainder.first == "\t" else { return nil }
        let title = sanitizeVisible(String(remainder).trimmingCharacters(in: .whitespacesAndNewlines))
        return title.isEmpty ? nil : (level, title)
    }

    private static func parseKeyValue(_ line: String) -> (key: String, value: String)? {
        guard !line.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("secret://") else {
            return nil
        }
        guard let separator = [line.firstIndex(of: ":"), line.firstIndex(of: "：")]
            .compactMap({ $0 })
            .min(by: { $0 < $1 })
        else { return nil }
        let key = String(line[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines)
        let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty, !value.isEmpty else { return nil }
        return (key, value)
    }

    private static func canonicalKey(_ raw: String) -> String {
        let normalized = normalize(raw)
        switch normalized {
        case "服务", "service", "servicename": return "service"
        case "设备", "device": return "device"
        case "地址", "主机", "host", "hostname", "ip", "destination": return "host"
        case "url", "网址", "链接": return "url"
        case "端口", "port": return "port"
        case "用途", "purpose", "用途描述", "description": return "purpose"
        case "备注", "note", "notes", "说明": return "note"
        case "标签", "tag", "tags": return "tag"
        default: return normalized
        }
    }

    private static func legacyFieldKey(_ field: SecretCatalogField) -> String {
        switch field {
        case .username: return "username"
        case .password: return "password"
        case .token: return "token"
        case .apiKey: return "apiKey"
        case .cookie: return "cookie"
        case .privateKey: return "privateKey"
        case .other: return "other"
        }
    }

    private static func isSensitive(_ key: String) -> Bool {
        sensitiveKeys.contains(normalize(key))
    }

    private static func normalize(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "-", with: "")
    }

    private static func sanitizeVisible(_ value: String) -> String {
        var result = value
            .replacingOccurrences(of: "\0", with: "")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let regex = try? NSRegularExpression(pattern: referencePattern) {
            let range = NSRange(location: 0, length: (result as NSString).length)
            result = regex.stringByReplacingMatches(in: result, range: range, withTemplate: "[secret-reference]")
        }
        return String(result.prefix(2_000))
    }

    private static func safeLabel(_ raw: String, fallback: String) -> String {
        let value = sanitizeVisible(raw)
        return value.isEmpty ? fallback : value
    }

    private static func uniqueKey(_ key: String, existing: [SecretCatalogFieldValue], offset: Int = 0) -> String {
        let base = offset == 0 ? key : "\(key)-\(offset + 1)"
        guard existing.contains(where: { $0.key == base }) else { return base }
        var number = 2
        while existing.contains(where: { $0.key == "\(key)-\(number)" }) {
            number += 1
        }
        return "\(key)-\(number)"
    }

    private static func endpointsFor(value: String) -> [CatalogEndpoint] {
        if let url = URL(string: value), let host = url.host {
            return [CatalogEndpoint(type: url.scheme ?? "https", host: host, port: url.port)]
        }
        return [CatalogEndpoint(type: "host", host: value)]
    }

    private static func uniqueEndpoints(_ endpoints: [CatalogEndpoint]) -> [CatalogEndpoint] {
        var seen = Set<String>()
        return endpoints.filter { endpoint in
            let key = "\(endpoint.type)|\(endpoint.host)|\(endpoint.port.map(String.init) ?? "")"
            return seen.insert(key).inserted
        }
    }

    private struct LegacyBlockBuilder {
        let headings: [String]
        var metadata: [(key: String, value: String)] = []
        var references: [String] = []
        var unlabelledReferences: [String] = []
        var note = ""

        func build() -> LegacyBlock {
            let nonRootHeadings = headings.dropFirst()
            let indexTitle = nonRootHeadings.first ?? headings.last ?? "待确认迁移"
            let entryTitle = nonRootHeadings.last ?? indexTitle
            return LegacyBlock(
                headings: headings,
                indexTitle: indexTitle,
                entryTitle: entryTitle,
                metadata: metadata,
                references: Array(Set(references)).sorted(),
                unlabelledReferences: Array(Set(unlabelledReferences)).sorted(),
                note: note
            )
        }
    }

    private struct LegacyBlock {
        let headings: [String]
        let indexTitle: String
        let entryTitle: String
        let metadata: [(key: String, value: String)]
        let references: [String]
        let unlabelledReferences: [String]
        let note: String
    }
}
