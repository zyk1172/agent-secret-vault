import Foundation

/// Parses only safe, human-authored context around opaque references.  It does
/// not attempt to interpret or retain values that are not explicitly marked as
/// catalog metadata.
public enum SecretCatalogMarkdownParser {
    private static let referencePattern = "secret://[0-9A-HJKMNP-TV-Z]{26}"
    private static let genericHeadings: Set<String> = [
        "敏感信息",
        "敏感信息索引",
        "格式模板",
        "服务api",
        "账号密码",
        "token",
        "api",
        "api key",
        "密码",
        "用户名",
        "账号"
    ]

    public static func parse(_ text: String) -> [SecretCatalogEntry] {
        guard let referenceRegex = try? NSRegularExpression(pattern: referencePattern) else {
            return []
        }

        var headingPath: [String] = []
        var context = ParseContext(headings: headingPath)
        var parsed: [SecretCatalogEntry] = []

        for line in normalizedLines(text) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                context.resetParagraphState()
                continue
            }

            if let heading = parseHeading(trimmed) {
                let level = heading.level
                if headingPath.count >= level {
                    headingPath = Array(headingPath.prefix(level - 1))
                }
                headingPath.append(heading.title)
                context = ParseContext(headings: headingPath)
                continue
            }

            let keyValue = parseKeyValue(trimmed)
            if let keyValue {
                context.update(key: keyValue.key, value: keyValue.value)
            }

            let range = NSRange(location: 0, length: (line as NSString).length)
            let matches = referenceRegex.matches(in: line, range: range)
            guard !matches.isEmpty else {
                continue
            }

            let lineField = keyValue.flatMap { SecretCatalogField.fromKey($0.key) }
            for match in matches {
                let reference = (line as NSString).substring(with: match.range)
                guard (try? SecretReference(reference)) != nil else {
                    continue
                }
                parsed.append(context.entry(reference: reference, lineField: lineField))
            }
        }

        return mergeDuplicateReferences(parsed)
    }

    private static func normalizedLines(_ text: String) -> [String] {
        text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .components(separatedBy: "\n")
    }

    private static func parseHeading(_ line: String) -> (level: Int, title: String)? {
        let hashes = line.prefix(while: { $0 == "#" }).count
        guard (1...6).contains(hashes) else {
            return nil
        }
        let remainder = line.dropFirst(hashes)
        guard remainder.first == " " || remainder.first == "\t" else {
            return nil
        }
        let title = sanitizeMetadata(String(remainder).trimmingCharacters(in: .whitespacesAndNewlines))
        guard !title.isEmpty else {
            return nil
        }
        return (hashes, title)
    }

    private static func parseKeyValue(_ line: String) -> (key: String, value: String)? {
        var content = line.trimmingCharacters(in: .whitespacesAndNewlines)
        while content.hasPrefix(">") || content.hasPrefix("-") || content.hasPrefix("*") {
            content.removeFirst()
            content = content.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let colonCandidates = [content.firstIndex(of: ":"), content.firstIndex(of: "：")].compactMap { $0 }
        guard let colon = colonCandidates.min(by: { $0 < $1 }) else {
            return nil
        }

        let key = String(content[..<colon]).trimmingCharacters(in: .whitespacesAndNewlines)
        let value = String(content[content.index(after: colon)...]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty, !value.isEmpty else {
            return nil
        }
        return (key, value)
    }

    private static func sanitizeMetadata(_ value: String) -> String {
        var sanitized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        sanitized = sanitized.replacingOccurrences(of: "`", with: "")
        sanitized = sanitized.replacingOccurrences(of: "[", with: "")
        sanitized = sanitized.replacingOccurrences(of: "]", with: "")
        sanitized = sanitized.replacingOccurrences(of: "<", with: "")
        sanitized = sanitized.replacingOccurrences(of: ">", with: "")
        if let regex = try? NSRegularExpression(pattern: referencePattern) {
            let range = NSRange(location: 0, length: (sanitized as NSString).length)
            sanitized = regex.stringByReplacingMatches(
                in: sanitized,
                range: range,
                withTemplate: "[secret-reference]"
            )
        }
        sanitized = sanitized.replacingOccurrences(of: "\n", with: " ")
        sanitized = sanitized.replacingOccurrences(of: "\r", with: " ")
        return String(sanitized.prefix(160)).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func parseDestinations(_ value: String) -> [String] {
        sanitizeMetadata(value)
            .split(whereSeparator: { ",，;；|".contains($0) })
            .map { part in
                part.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "。")))
            }
            .filter { !$0.isEmpty && !$0.contains("[secret-reference]") }
            .map { String($0) }
    }

    private static func mergeDuplicateReferences(_ entries: [SecretCatalogEntry]) -> [SecretCatalogEntry] {
        var indexByReference: [String: Int] = [:]
        var merged: [SecretCatalogEntry] = []
        merged.reserveCapacity(entries.count)

        for entry in entries {
            guard let existingIndex = indexByReference[entry.reference] else {
                indexByReference[entry.reference] = merged.count
                merged.append(entry)
                continue
            }

            let existing = merged[existingIndex]
            let field = existing.field == .other ? entry.field : existing.field
            let service = existing.service ?? entry.service
            let label = existing.label ?? entry.label
            let purpose = existing.purpose ?? entry.purpose
            let destinations = Array(Set(existing.destinations + entry.destinations)).sorted()
            let contextTerms = Array(Set(existing.contextTerms + entry.contextTerms)).sorted()
            merged[existingIndex] = SecretCatalogEntry(
                reference: existing.reference,
                service: service,
                field: field,
                label: label,
                destinations: destinations,
                purpose: purpose,
                groupID: existing.groupID ?? entry.groupID,
                contextTerms: contextTerms
            )
        }
        return merged
    }

    private struct Heading {
        let level: Int
        let title: String
    }

    private struct ParseContext {
        let headings: [String]
        var service: String?
        var device: String?
        var destinations: [String] = []
        var purpose: String?
        var explicitLabel: String?
        var field: SecretCatalogField?
        var contextTerms: [String]

        init(headings: [String]) {
            self.headings = headings
            self.contextTerms = headings
        }

        mutating func resetParagraphState() {
            field = nil
            purpose = nil
            explicitLabel = nil
        }

        mutating func update(key: String, value: String) {
            let safeValue = SecretCatalogMarkdownParser.sanitizeMetadata(value)
            guard !safeValue.isEmpty else {
                return
            }
            let normalizedKey = key
                .lowercased()
                .replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: "_", with: "")
                .replacingOccurrences(of: "-", with: "")

            switch normalizedKey {
            case "服务", "service", "servicename":
                service = safeValue
                contextTerms.append(safeValue)
            case "设备", "device":
                device = safeValue
                contextTerms.append(safeValue)
            case "地址", "主机", "host", "hostname", "destination", "destinations", "url":
                let values = SecretCatalogMarkdownParser.parseDestinations(value)
                destinations.append(contentsOf: values)
                contextTerms.append(contentsOf: values)
            case "用途", "purpose", "用途描述", "description":
                purpose = safeValue
                contextTerms.append(safeValue)
            case "标签", "名称", "显示名称", "标题", "label", "name", "title":
                explicitLabel = safeValue
                contextTerms.append(safeValue)
            default:
                if let parsedField = SecretCatalogField.fromKey(key) {
                    field = parsedField
                    // The field name is safe context.  The value on a field
                    // line is deliberately never retained.
                    contextTerms.append(parsedField.displayName)
                }
            }
        }

        func entry(reference: String, lineField: SecretCatalogField?) -> SecretCatalogEntry {
            let service = service ?? inferredService() ?? device
            let field = lineField ?? self.field ?? .other
            let destinations = Array(Set(destinations)).sorted()
            let label = explicitLabel ?? synthesizedLabel(service: service, field: field)
            let terms = Array(Set(contextTerms + headings + [service, device, label].compactMap { $0 }))
                .filter { !$0.isEmpty }
                .sorted()

            return SecretCatalogEntry(
                reference: reference,
                service: service,
                field: field,
                label: label,
                destinations: destinations,
                purpose: purpose,
                groupID: SecretCatalogEntry.stableGroupID(
                    service: service,
                    destinations: destinations,
                    headingPath: headings
                ),
                contextTerms: terms
            )
        }

        private func inferredService() -> String? {
            headings.reversed().first { heading in
                let normalized = SecretCatalogEntry.normalizeForSearch(heading)
                return !normalized.isEmpty
                    && !SecretCatalogMarkdownParser.genericHeadings.contains(normalized)
                    && SecretCatalogField.fromKey(heading) == nil
            }
        }

        private func synthesizedLabel(service: String?, field: SecretCatalogField) -> String? {
            if let service, field != .other {
                return "\(service) \(field.displayName)"
            }
            if field != .other {
                return field.displayName
            }
            return service
        }
    }
}
