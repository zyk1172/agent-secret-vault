import Foundation
import VaultCore

public enum SensitiveCandidateRisk: String, Equatable, Sendable {
    case high
    case medium
}

public struct LocalSensitiveInformationCandidate: Identifiable, Equatable, Sendable {
    public let id: String
    public let fileURL: URL
    public let source: SensitiveSourceLocation
    public let paragraph: String
    public let matchedValue: String
    public let valueStartUTF16: Int
    public let valueEndUTF16: Int
    public let contentFingerprint: String
    public let rule: String
    public let risk: SensitiveCandidateRisk
    public let title: String
    public let category: String

    public init(
        id: String,
        fileURL: URL,
        source: SensitiveSourceLocation,
        paragraph: String,
        matchedValue: String,
        valueStartUTF16: Int,
        valueEndUTF16: Int,
        contentFingerprint: String,
        rule: String,
        risk: SensitiveCandidateRisk,
        title: String,
        category: String
    ) {
        self.id = id
        self.fileURL = fileURL
        self.source = source
        self.paragraph = paragraph
        self.matchedValue = matchedValue
        self.valueStartUTF16 = valueStartUTF16
        self.valueEndUTF16 = valueEndUTF16
        self.contentFingerprint = contentFingerprint
        self.rule = rule
        self.risk = risk
        self.title = title
        self.category = category
    }
}

public struct LocalSensitiveInformationScanner: Sendable {
    public init() {}

    public func scan(directory: URL, excluding excludedURL: URL? = nil) throws -> [LocalSensitiveInformationCandidate] {
        let root = directory.standardizedFileURL
        let excludedPath = excludedURL?.standardizedFileURL.path
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey]
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: Array(keys),
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            return []
        }

        var candidates: [LocalSensitiveInformationCandidate] = []
        for case let url as URL in enumerator {
            guard url.pathExtension.lowercased() == "md",
                  url.standardizedFileURL.path != excludedPath
            else {
                continue
            }
            let values = try url.resourceValues(forKeys: keys)
            guard values.isRegularFile == true, values.isSymbolicLink != true else {
                continue
            }
            let text = try String(contentsOf: url, encoding: .utf8)
            let displayPath = url.path.replacingOccurrences(of: root.path + "/", with: "")
            candidates.append(contentsOf: try scan(fileURL: url, filePath: displayPath, text: text))
        }
        return candidates.sorted { left, right in
            left.risk == right.risk
                ? left.source.filePath == right.source.filePath
                    ? left.valueStartUTF16 < right.valueStartUTF16
                    : left.source.filePath < right.source.filePath
                : left.risk == .high
        }
    }

    public func scan(filePath: String, text: String) throws -> [LocalSensitiveInformationCandidate] {
        try scan(fileURL: URL(fileURLWithPath: filePath), filePath: filePath, text: text)
    }

    public func scan(fileURL: URL, filePath: String, text: String) throws -> [LocalSensitiveInformationCandidate] {
        let fullRange = NSRange(location: 0, length: (text as NSString).length)
        let fingerprint = Self.fingerprint(text)
        var matches: [Match] = []

        for rule in Self.rules() {
            for result in rule.expression.matches(in: text, range: fullRange) {
                let valueRange = rule.captureIndexes
                    .map { result.range(at: $0) }
                    .first(where: { $0.location != NSNotFound && $0.length > 0 }) ?? result.range
                matches.append(Match(rule: rule, range: valueRange))
            }
        }

        let sortedMatches = matches.sorted { left, right in
            left.rule.risk == right.rule.risk
                ? left.range.length == right.range.length
                    ? left.range.location < right.range.location
                    : left.range.length > right.range.length
                : left.rule.risk == .high
        }
        var acceptedRanges: [NSRange] = []
        var candidates: [LocalSensitiveInformationCandidate] = []

        for match in sortedMatches {
            guard !acceptedRanges.contains(where: { NSIntersectionRange($0, match.range).length > 0 }) else {
                continue
            }
            let paragraphRange = Self.paragraphRange(in: text, containingUTF16Offset: match.range.location)
            let paragraph = (text as NSString).substring(with: paragraphRange)
            guard !paragraph.contains("secret://") else {
                continue
            }

            acceptedRanges.append(match.range)
            let value = (text as NSString).substring(with: match.range)
            let line = Self.lineNumber(in: text, atUTF16Offset: match.range.location)
            let title = Self.title(in: text, atUTF16Offset: match.range.location, fallback: match.rule.title)
            candidates.append(
                LocalSensitiveInformationCandidate(
                    id: "\(fileURL.path):\(match.range.location):\(match.range.length)",
                    fileURL: fileURL,
                    source: SensitiveSourceLocation(filePath: filePath, line: line),
                    paragraph: paragraph,
                    matchedValue: value,
                    valueStartUTF16: match.range.location,
                    valueEndUTF16: match.range.location + match.range.length,
                    contentFingerprint: fingerprint,
                    rule: match.rule.name,
                    risk: match.rule.risk,
                    title: title,
                    category: match.rule.category
                )
            )
        }
        return candidates.sorted { $0.valueStartUTF16 < $1.valueStartUTF16 }
    }

    private struct Rule {
        let name: String
        let title: String
        let category: String
        let risk: SensitiveCandidateRisk
        let expression: NSRegularExpression
        let captureIndexes: [Int]
    }

    private struct Match {
        let rule: Rule
        let range: NSRange
    }

    private static func rules() -> [Rule] {
        [
            rule("OpenAI API Key", "OpenAI API Key", "API Key", .high, "\\bsk-[A-Za-z0-9_-]{16,}\\b"),
            rule("GitHub Token", "GitHub Token", "Token", .high, "\\bgh[pousr]_[A-Za-z0-9_]{20,}\\b"),
            rule("Private Key", "Private Key", "Private Key", .high, "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
            rule("Bearer Token", "Bearer Token", "Token", .high, "\\bBearer\\s+([A-Za-z0-9._~+/=-]{10,})", captures: [1]),
            rule("Password Assignment", "Password", "Credential", .medium, "(?i)(?:password|passwd|pwd|api[_ -]?key|access[_ -]?key|token|secret|密码|口令|令牌|密钥)\\s*[:=：]\\s*(?:\\\"([^\\\"\\r\\n]+)\\\"|'([^'\\r\\n]+)'|([^\\s'\\\"`，。；;]+))", captures: [1, 2, 3])
        ]
    }

    private static func rule(
        _ name: String,
        _ title: String,
        _ category: String,
        _ risk: SensitiveCandidateRisk,
        _ pattern: String,
        captures: [Int] = []
    ) -> Rule {
        Rule(
            name: name,
            title: title,
            category: category,
            risk: risk,
            expression: try! NSRegularExpression(pattern: pattern),
            captureIndexes: captures
        )
    }

    private static func paragraphRange(in text: String, containingUTF16Offset offset: Int) -> NSRange {
        let nsText = text as NSString
        var start = offset
        while start > 0 {
            let priorNewline = nsText.range(of: "\n", options: .backwards, range: NSRange(location: 0, length: start))
            if priorNewline.location == NSNotFound {
                start = 0
                break
            }
            let lineStart = priorNewline.location + 1
            let line = nsText.substring(with: NSRange(location: lineStart, length: start - lineStart))
            if line.trimmingCharacters(in: .whitespaces).isEmpty {
                start = lineStart
                break
            }
            start = priorNewline.location
        }

        var end = offset
        while end < nsText.length {
            let newline = nsText.range(of: "\n", options: [], range: NSRange(location: end, length: nsText.length - end))
            if newline.location == NSNotFound {
                end = nsText.length
                break
            }
            let nextLineStart = newline.location + 1
            let nextNewline = nsText.range(of: "\n", options: [], range: NSRange(location: nextLineStart, length: nsText.length - nextLineStart))
            let nextLineEnd = nextNewline.location == NSNotFound ? nsText.length : nextNewline.location
            let nextLine = nsText.substring(with: NSRange(location: nextLineStart, length: nextLineEnd - nextLineStart))
            if nextLine.trimmingCharacters(in: .whitespaces).isEmpty {
                end = newline.location
                break
            }
            end = nextLineStart
        }
        return NSRange(location: start, length: max(0, end - start))
    }

    private static func lineNumber(in text: String, atUTF16Offset offset: Int) -> Int {
        let prefix = (text as NSString).substring(to: offset)
        return prefix.reduce(into: 1) { count, character in
            if character == "\n" { count += 1 }
        }
    }

    private static func title(in text: String, atUTF16Offset offset: Int, fallback: String) -> String {
        let nsText = text as NSString
        let lineStart = nsText.range(of: "\n", options: .backwards, range: NSRange(location: 0, length: offset)).location
        let start = lineStart == NSNotFound ? 0 : lineStart + 1
        let prefix = nsText.substring(with: NSRange(location: start, length: offset - start))
            .replacingOccurrences(of: "：", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "=", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return prefix.isEmpty ? fallback : String(prefix.suffix(48))
    }

    static func fingerprint(_ text: String) -> String {
        var value: UInt64 = 1_469_598_103_934_665_603
        for byte in text.utf8 {
            value ^= UInt64(byte)
            value &*= 1_099_511_628_211
        }
        return String(value, radix: 16)
    }
}

public enum LocalSensitiveInformationWriteError: Error, Equatable, Sendable {
    case changedSinceScan
    case symlinkRejected
    case invalidSource
}

public enum LocalSensitiveInformationWriter {
    public static func replace(
        _ candidate: LocalSensitiveInformationCandidate,
        displayID: String,
        reference: String
    ) throws {
        let values = try candidate.fileURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw LocalSensitiveInformationWriteError.invalidSource
        }
        if values.isSymbolicLink == true {
            throw LocalSensitiveInformationWriteError.symlinkRejected
        }

        let text = try String(contentsOf: candidate.fileURL, encoding: .utf8)
        guard LocalSensitiveInformationScanner.fingerprint(text) == candidate.contentFingerprint else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }
        let nsText = text as NSString
        guard candidate.valueStartUTF16 >= 0,
              candidate.valueEndUTF16 >= candidate.valueStartUTF16,
              candidate.valueEndUTF16 <= nsText.length
        else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }
        let range = NSRange(
            location: candidate.valueStartUTF16,
            length: candidate.valueEndUTF16 - candidate.valueStartUTF16
        )
        guard nsText.substring(with: range) == candidate.matchedValue else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }

        let title = candidate.title.replacingOccurrences(of: "[", with: " ")
            .replacingOccurrences(of: "]", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let visibleTitle = title.isEmpty ? "敏感信息" : title
        let replacement = "[\(displayID) \(visibleTitle)](\(reference))"
        let updated = nsText.replacingCharacters(in: range, with: replacement)
        try updated.write(to: candidate.fileURL, atomically: true, encoding: .utf8)
    }
}
