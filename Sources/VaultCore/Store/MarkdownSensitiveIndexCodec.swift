import Foundation

public enum MarkdownSensitiveIndexError: Error, Equatable, Sendable {
    case invalidHeader
    case malformedEntry
    case invalidDisplayID(String)
    case invalidMetadata
    case invalidReference
    case invalidSource
    case invalidDate
    case invalidEnvelope
    case referenceDoesNotMatchRecord
    case policyDoesNotMatchRecord
    case duplicateDisplayID(String)
    case duplicateReference(String)
}

public enum MarkdownSensitiveIndexCodec {
    private static let header = "<!-- agent-secret-vault-index: 1 -->\n# Sensitive Information Index"
    private static let displayIDPrefix = "S-"

    public static func encode(_ entries: [IndexedEncryptedRecord]) throws -> String {
        var displayIDs = Set<String>()
        var references = Set<String>()
        let sortedEntries = try entries.sorted(by: compare)
        let renderedEntries = try sortedEntries.map { entry -> String in
            try validate(entry)
            guard displayIDs.insert(entry.displayID).inserted else {
                throw MarkdownSensitiveIndexError.duplicateDisplayID(entry.displayID)
            }

            let reference = "secret://\(entry.record.id)"
            guard references.insert(reference).inserted else {
                throw MarkdownSensitiveIndexError.duplicateReference(reference)
            }

            return try render(entry)
        }

        return ([header] + renderedEntries).joined(separator: "\n\n") + "\n"
    }

    public static func decode(_ text: String) throws -> [IndexedEncryptedRecord] {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .trimmingCharacters(in: .newlines)
        guard normalized == header || normalized.hasPrefix(header + "\n\n") else {
            throw MarkdownSensitiveIndexError.invalidHeader
        }

        guard normalized != header else {
            return []
        }

        let bodyStart = normalized.index(normalized.startIndex, offsetBy: header.count + 2)
        let body = String(normalized[bodyStart...])
        let sections = body
            .components(separatedBy: "\n\n## ")
            .enumerated()
            .map { index, section in index == 0 ? section : "## \(section)" }

        var entries: [IndexedEncryptedRecord] = []
        var displayIDs = Set<String>()
        var references = Set<String>()

        for section in sections {
            guard !section.isEmpty else {
                throw MarkdownSensitiveIndexError.malformedEntry
            }
            let entry = try parse(section.trimmingCharacters(in: .newlines))
            guard displayIDs.insert(entry.displayID).inserted else {
                throw MarkdownSensitiveIndexError.duplicateDisplayID(entry.displayID)
            }

            let reference = "secret://\(entry.record.id)"
            guard references.insert(reference).inserted else {
                throw MarkdownSensitiveIndexError.duplicateReference(reference)
            }
            entries.append(entry)
        }

        return try entries.sorted(by: compare)
    }

    private static func render(_ entry: IndexedEncryptedRecord) throws -> String {
        let reference = "secret://\(entry.record.id)"
        let source = entry.source.map { "\($0.filePath):\($0.line)" } ?? "-"
        let payload = try encodedEnvelope(entry.record)

        return [
            "## \(entry.displayID) - \(entry.title)",
            "- Category: \(entry.category)",
            "- Policy: \(entry.record.policy.rawValue)",
            "- Source: \(source)",
            "- Reference: `\(reference)`",
            "- Created: \(formatDate(entry.record.createdAt))",
            "- Updated: \(formatDate(entry.record.updatedAt))",
            "",
            "```asv-record",
            payload,
            "```"
        ].joined(separator: "\n")
    }

    private static func parse(_ section: String) throws -> IndexedEncryptedRecord {
        let lines = section.components(separatedBy: "\n")
        guard lines.count == 11,
              lines[7].isEmpty,
              lines[8] == "```asv-record",
              lines[10] == "```"
        else {
            throw MarkdownSensitiveIndexError.malformedEntry
        }

        let headingPrefix = "## "
        guard lines[0].hasPrefix(headingPrefix),
              let separator = lines[0].dropFirst(headingPrefix.count).range(of: " - ")
        else {
            throw MarkdownSensitiveIndexError.malformedEntry
        }

        let heading = lines[0].dropFirst(headingPrefix.count)
        let displayID = String(heading[..<separator.lowerBound])
        let title = String(heading[separator.upperBound...])
        let category = try field(lines[1], prefix: "- Category: ")
        let policyText = try field(lines[2], prefix: "- Policy: ")
        let sourceText = try field(lines[3], prefix: "- Source: ")
        let referenceText = try field(lines[4], prefix: "- Reference: `", suffix: "`")
        _ = try validateDate(field(lines[5], prefix: "- Created: "))
        _ = try validateDate(field(lines[6], prefix: "- Updated: "))

        guard let policy = SecretPolicy(rawValue: policyText) else {
            throw MarkdownSensitiveIndexError.invalidMetadata
        }
        let source = try parseSource(sourceText)
        let reference: SecretReference
        do {
            reference = try SecretReference(referenceText)
        } catch {
            throw MarkdownSensitiveIndexError.invalidReference
        }

        let record = try decodedEnvelope(lines[9])
        guard record.id == reference.id else {
            throw MarkdownSensitiveIndexError.referenceDoesNotMatchRecord
        }
        guard record.policy == policy else {
            throw MarkdownSensitiveIndexError.policyDoesNotMatchRecord
        }

        let entry = IndexedEncryptedRecord(
            displayID: displayID,
            category: category,
            title: title,
            source: source,
            record: record
        )
        try validate(entry)
        return entry
    }

    private static func validate(_ entry: IndexedEncryptedRecord) throws {
        guard isValidDisplayID(entry.displayID) else {
            throw MarkdownSensitiveIndexError.invalidDisplayID(entry.displayID)
        }
        guard isValidVisibleText(entry.category), isValidVisibleText(entry.title) else {
            throw MarkdownSensitiveIndexError.invalidMetadata
        }
        if let source = entry.source {
            guard isValidVisibleText(source.filePath), source.line > 0 else {
                throw MarkdownSensitiveIndexError.invalidSource
            }
        }
        do {
            _ = try SecretReference("secret://\(entry.record.id)")
        } catch {
            throw MarkdownSensitiveIndexError.invalidReference
        }
    }

    private static func parseSource(_ text: String) throws -> SensitiveSourceLocation? {
        guard text != "-" else {
            return nil
        }
        guard let separator = text.lastIndex(of: ":"),
              let line = Int(text[text.index(after: separator)...]),
              line > 0
        else {
            throw MarkdownSensitiveIndexError.invalidSource
        }

        let path = String(text[..<separator])
        guard isValidVisibleText(path) else {
            throw MarkdownSensitiveIndexError.invalidSource
        }
        return SensitiveSourceLocation(filePath: path, line: line)
    }

    private static func field(_ line: String, prefix: String, suffix: String = "") throws -> String {
        guard line.hasPrefix(prefix), line.hasSuffix(suffix) else {
            throw MarkdownSensitiveIndexError.malformedEntry
        }
        let start = line.index(line.startIndex, offsetBy: prefix.count)
        let end = suffix.isEmpty ? line.endIndex : line.index(line.endIndex, offsetBy: -suffix.count)
        return String(line[start..<end])
    }

    private static func validateDate(_ value: String) throws -> String {
        guard makeDateFormatter().date(from: value) != nil else {
            throw MarkdownSensitiveIndexError.invalidDate
        }
        return value
    }

    private static func encodedEnvelope(_ record: EncryptedRecord) throws -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(record).base64EncodedString()
    }

    private static func decodedEnvelope(_ payload: String) throws -> EncryptedRecord {
        guard let data = Data(base64Encoded: payload) else {
            throw MarkdownSensitiveIndexError.invalidEnvelope
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        do {
            return try decoder.decode(EncryptedRecord.self, from: data)
        } catch {
            throw MarkdownSensitiveIndexError.invalidEnvelope
        }
    }

    private static func isValidDisplayID(_ value: String) -> Bool {
        guard value.hasPrefix(displayIDPrefix) else {
            return false
        }
        let digits = value.dropFirst(displayIDPrefix.count)
        return digits.count >= 3 && digits.allSatisfy(\.isNumber)
    }

    private static func isValidVisibleText(_ value: String) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !value.contains("\n")
            && !value.contains("\r")
    }

    private static func compare(_ left: IndexedEncryptedRecord, _ right: IndexedEncryptedRecord) throws -> Bool {
        let leftNumber = try displayIDNumber(left.displayID)
        let rightNumber = try displayIDNumber(right.displayID)
        return leftNumber == rightNumber ? left.displayID < right.displayID : leftNumber < rightNumber
    }

    private static func displayIDNumber(_ value: String) throws -> Int {
        guard isValidDisplayID(value), let number = Int(value.dropFirst(displayIDPrefix.count)) else {
            throw MarkdownSensitiveIndexError.invalidDisplayID(value)
        }
        return number
    }

    private static func formatDate(_ date: Date) -> String {
        makeDateFormatter().string(from: date)
    }

    private static func makeDateFormatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }
}
