import Foundation

/// The managed-document codec.  Markdown headings are a human-readable view;
/// the JSON blocks are the only source of machine data.
public enum SensitiveCatalogDocumentCodec {
    public static let marker = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->"
    public static let rootTitle = "敏感信息"

    private static let introLines = [
        "> 本文件由 SVLT 管理。请勿直接修改结构化数据。",
        "> Agent 必须使用 SVLT MCP Catalog 工具修改。"
    ]

    public static func decode(_ data: Data) throws -> SecretCatalogDocument {
        guard let text = String(data: data, encoding: .utf8) else {
            throw SecretCatalogValidationError.unmanagedContent
        }
        return try decode(text)
    }

    public static func decode(_ text: String) throws -> SecretCatalogDocument {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.components(separatedBy: "\n")

        guard lines.first == marker else {
            if text.contains("agent-secret-vault-sensitive-information: 1") {
                throw SecretCatalogValidationError.legacyDocument
            }
            throw SecretCatalogValidationError.invalidMarker
        }

        var sawRoot = false
        var currentIndexTitle: String?
        var currentEntryTitle: String?
        var currentIndex: SecretCatalogIndex?
        var indexes: [SecretCatalogIndex] = []
        var entries: [SecretCatalogEntry] = []
        var indexBlockCount = 0
        var entryBlockCount = 0
        var inJSONFence = false
        var jsonLines: [String] = []
        var jsonLevel = 0

        for line in lines.dropFirst() {
            if inJSONFence {
                if line == "```" {
                    inJSONFence = false
                    let json = jsonLines.joined(separator: "\n")
                    try decodeBlock(
                        json,
                        level: jsonLevel,
                        indexTitle: currentIndexTitle,
                        entryTitle: currentEntryTitle,
                        activeIndex: currentIndex,
                        indexes: &indexes,
                        entries: &entries,
                        indexBlockCount: &indexBlockCount,
                        entryBlockCount: &entryBlockCount,
                        currentIndex: &currentIndex
                    )
                    jsonLines.removeAll(keepingCapacity: true)
                    continue
                }
                jsonLines.append(line)
                continue
            }

            if let heading = parseHeading(line) {
                switch heading.level {
                case 1:
                    guard !sawRoot, heading.title == rootTitle else {
                        throw SecretCatalogValidationError.invalidHeading
                    }
                    sawRoot = true
                    guard currentIndexTitle == nil else {
                        throw SecretCatalogValidationError.invalidHeading
                    }
                case 2:
                    guard sawRoot else { throw SecretCatalogValidationError.invalidHeading }
                    try finishCurrentEntry(
                        currentEntryTitle,
                        entryBlockCount: entryBlockCount
                    )
                    try finishCurrentIndex(
                        currentIndexTitle,
                        indexBlockCount: indexBlockCount
                    )
                    currentIndexTitle = heading.title
                    currentEntryTitle = nil
                    currentIndex = nil
                    indexBlockCount = 0
                    entryBlockCount = 0
                case 3:
                    guard sawRoot, currentIndexTitle != nil, currentIndex != nil else {
                        throw SecretCatalogValidationError.invalidHeading
                    }
                    try finishCurrentEntry(
                        currentEntryTitle,
                        entryBlockCount: entryBlockCount
                    )
                    currentEntryTitle = heading.title
                    entryBlockCount = 0
                default:
                    throw SecretCatalogValidationError.invalidHeading
                }
                continue
            }

            if line == "```json" {
                guard sawRoot, currentIndexTitle != nil
                else {
                    throw SecretCatalogValidationError.invalidHeading
                }
                inJSONFence = true
                jsonLevel = currentEntryTitle == nil ? 2 : 3
                jsonLines.removeAll(keepingCapacity: true)
                continue
            }

            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || introLines.contains(line) {
                continue
            }

            throw SecretCatalogValidationError.unmanagedContent
        }

        guard !inJSONFence else { throw SecretCatalogValidationError.malformedJSON }
        try finishCurrentEntry(currentEntryTitle, entryBlockCount: entryBlockCount)
        try finishCurrentIndex(currentIndexTitle, indexBlockCount: indexBlockCount)
        guard sawRoot else { throw SecretCatalogValidationError.invalidHeading }

        let document = SecretCatalogDocument(indexes: indexes, entries: entries)
        try document.validate()
        return document
    }

    public static func encode(_ document: SecretCatalogDocument) throws -> String {
        try document.validate()

        var lines = [marker, "# \(rootTitle)", ""]
        lines.append(contentsOf: introLines)
        lines.append("")

        for (indexOffset, index) in document.indexes.enumerated() {
            if indexOffset > 0 {
                lines.append("")
                lines.append("")
            }
            lines.append("## \(index.title)")
            lines.append("")
            lines.append("```json")
            lines.append(try canonicalJSON(index))
            lines.append("```")

            let indexEntries = document.entries.filter { $0.indexId == index.id }
            for entry in indexEntries {
                lines.append("")
                lines.append("")
                lines.append("### \(entry.title)")
                lines.append("")
                lines.append("```json")
                lines.append(try canonicalJSON(entry))
                lines.append("```")
            }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    public static func canonicalData(_ document: SecretCatalogDocument) throws -> Data {
        Data(try encode(document).utf8)
    }

    public static func isManagedV2(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return false }
        return isManagedV2(text)
    }

    public static func isManagedV2(_ text: String) -> Bool {
        text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .hasPrefix(marker + "\n")
    }

    private static func decodeBlock(
        _ json: String,
        level: Int,
        indexTitle: String?,
        entryTitle: String?,
        activeIndex: SecretCatalogIndex?,
        indexes: inout [SecretCatalogIndex],
        entries: inout [SecretCatalogEntry],
        indexBlockCount: inout Int,
        entryBlockCount: inout Int,
        currentIndex: inout SecretCatalogIndex?
    ) throws {
        let data = Data(json.utf8)
        let envelope: SchemaEnvelope
        do {
            envelope = try JSONDecoder().decode(SchemaEnvelope.self, from: data)
        } catch {
            throw SecretCatalogValidationError.malformedJSON
        }

        switch (level, envelope.schema) {
        case (2, SecretCatalogIndex.schemaName):
            guard indexBlockCount == 0, let indexTitle else {
                throw SecretCatalogValidationError.missingIndexBlock
            }
            let index: SecretCatalogIndex
            do {
                index = try JSONDecoder().decode(SecretCatalogIndex.self, from: data)
            } catch {
                throw SecretCatalogValidationError.malformedJSON
            }
            guard index.title == indexTitle else {
                throw SecretCatalogValidationError.headingDoesNotMatchBlock
            }
            try index.validateStandalone()
            indexes.append(index)
            currentIndex = index
            indexBlockCount += 1
        case (3, SecretCatalogEntry.schemaName):
            guard entryBlockCount == 0,
                  let entryTitle,
                  let currentIndex = activeIndex
            else {
                throw SecretCatalogValidationError.missingEntryBlock
            }
            let entry: SecretCatalogEntry
            do {
                entry = try JSONDecoder().decode(SecretCatalogEntry.self, from: data)
            } catch {
                throw SecretCatalogValidationError.malformedJSON
            }
            guard entry.title == entryTitle,
                  entry.indexId == currentIndex.id
            else {
                throw SecretCatalogValidationError.headingDoesNotMatchBlock
            }
            entries.append(entry)
            entryBlockCount += 1
        default:
            throw SecretCatalogValidationError.unknownSchema
        }
    }

    private static func finishCurrentEntry(
        _ title: String?,
        entryBlockCount: Int
    ) throws {
        guard title == nil || entryBlockCount == 1 else {
            throw SecretCatalogValidationError.missingEntryBlock
        }
    }

    private static func finishCurrentIndex(
        _ title: String?,
        indexBlockCount: Int
    ) throws {
        guard title == nil || indexBlockCount == 1 else {
            throw SecretCatalogValidationError.missingIndexBlock
        }
    }

    private static func parseHeading(_ line: String) -> (level: Int, title: String)? {
        let level = line.prefix(while: { $0 == "#" }).count
        guard (1...3).contains(level) else { return nil }
        let remainder = line.dropFirst(level)
        guard remainder.first == " " || remainder.first == "\t" else { return nil }
        let title = String(remainder).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty, !title.contains("\0") else { return nil }
        return (level, title)
    }

    private static func canonicalJSON<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let result = String(data: try encoder.encode(value), encoding: .utf8) else {
            throw SecretCatalogValidationError.malformedJSON
        }
        guard !result.contains("\r") else {
            throw SecretCatalogValidationError.malformedJSON
        }
        return result
    }

    private struct SchemaEnvelope: Decodable {
        let schema: String
    }
}

private extension SecretCatalogIndex {
    func validateStandalone() throws {
        try SecretCatalogOpaqueID.validate(id)
        guard schema == Self.schemaName else {
            throw SecretCatalogValidationError.unknownSchema
        }
        guard !title.isEmpty, !title.contains("\n"), !title.contains("\r") else {
            throw SecretCatalogValidationError.invalidVisibleText
        }
    }
}
