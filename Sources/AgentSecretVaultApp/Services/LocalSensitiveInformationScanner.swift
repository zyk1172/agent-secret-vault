import Foundation
import VaultCore

public enum SensitiveCandidateRisk: String, Codable, Equatable, Sendable, CaseIterable {
    case high
    case medium
}

public struct SensitiveScanRuleDefinition: Identifiable, Codable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var labels: [String]
    public var category: String
    public var risk: SensitiveCandidateRisk
    public var enabled: Bool

    public init(
        id: String = UUID().uuidString,
        name: String,
        labels: [String],
        category: String,
        risk: SensitiveCandidateRisk,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.labels = labels
        self.category = category
        self.risk = risk
        self.enabled = enabled
    }

    public static let defaults: [SensitiveScanRuleDefinition] = [
        .init(id: "credential", name: "密码与口令", labels: ["密码", "密碼", "口令", "登录密码", "登入密碼", "password", "passwd", "pwd", "passcode"], category: "Credential", risk: .high),
        .init(id: "api-key", name: "API Key 与访问密钥", labels: ["api", "api key", "apikey", "api-key", "接口密钥", "接口密鑰", "密钥", "密鑰", "access key", "access-key", "secret key", "secret-key", "client secret"], category: "API Key", risk: .high),
        .init(id: "token", name: "Token 与令牌", labels: ["token", "access token", "access-token", "refresh token", "refresh-token", "bearer token", "令牌", "访问令牌", "刷新令牌"], category: "Token", risk: .high),
        .init(id: "cookie", name: "Cookie 与会话", labels: ["cookie", "session", "session id", "sessionid", "会话", "会话令牌"], category: "Cookie", risk: .high),
        .init(id: "private-key", name: "私钥与证书", labels: ["private key", "private-key", "ssh key", "ssh-key", "私钥", "私鑰", "证书", "憑證", "certificate"], category: "Private Key", risk: .high),
        .init(id: "account", name: "账号与用户标识", labels: ["账号", "帳號", "用户名", "使用者", "username", "user", "account", "email", "邮箱", "郵箱"], category: "Identity", risk: .medium),
        .init(id: "database", name: "数据库连接", labels: ["database url", "database-url", "db url", "db-url", "connection string", "连接字符串", "連線字串", "dsn"], category: "Database", risk: .high),
        .init(id: "wifi", name: "网络凭据", labels: ["wifi 密码", "wifi password", "wireless password", "网络密码", "網路密碼"], category: "Credential", risk: .high)
    ]
}

@MainActor
public enum SensitiveScanRulePreferences {
    private static let customRulesKey = "customSensitiveScanRules"
    private static let ignoredCandidatesKey = "ignoredSensitiveScanCandidates"

    public static func customRules(defaults: UserDefaults = .standard) -> [SensitiveScanRuleDefinition] {
        guard let data = defaults.data(forKey: customRulesKey),
              let decoded = try? JSONDecoder().decode([SensitiveScanRuleDefinition].self, from: data)
        else {
            return []
        }
        return decoded
    }

    public static func saveCustomRules(_ rules: [SensitiveScanRuleDefinition], defaults: UserDefaults = .standard) {
        defaults.set(try? JSONEncoder().encode(rules), forKey: customRulesKey)
    }

    public static func ignoredCandidateIDs(defaults: UserDefaults = .standard) -> Set<String> {
        Set(defaults.stringArray(forKey: ignoredCandidatesKey) ?? [])
    }

    public static func ignore(_ ids: Set<String>, defaults: UserDefaults = .standard) {
        let updated = ignoredCandidateIDs(defaults: defaults).union(ids)
        defaults.set(Array(updated).sorted(), forKey: ignoredCandidatesKey)
    }
}

public struct LocalSensitiveInformationCandidate: Identifiable, Equatable, Sendable {
    public let id: String
    public let fileURL: URL
    public let source: SensitiveSourceLocation
    public let paragraph: String
    public let matchedValue: String
    public let valueStartUTF16: Int
    public let valueEndUTF16: Int
    public let paragraphStartUTF16: Int
    public let paragraphEndUTF16: Int
    public let valueStartInParagraphUTF16: Int
    public let valueEndInParagraphUTF16: Int
    public let replacementText: String
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
        paragraphStartUTF16: Int,
        paragraphEndUTF16: Int,
        valueStartInParagraphUTF16: Int,
        valueEndInParagraphUTF16: Int,
        replacementText: String? = nil,
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
        self.paragraphStartUTF16 = paragraphStartUTF16
        self.paragraphEndUTF16 = paragraphEndUTF16
        self.valueStartInParagraphUTF16 = valueStartInParagraphUTF16
        self.valueEndInParagraphUTF16 = valueEndInParagraphUTF16
        self.replacementText = replacementText ?? matchedValue
        self.contentFingerprint = contentFingerprint
        self.rule = rule
        self.risk = risk
        self.title = title
        self.category = category
    }

    public func replacingValue(in text: String, reference: String) -> String {
        let nsText = text as NSString
        guard valueStartInParagraphUTF16 >= 0,
              valueEndInParagraphUTF16 >= valueStartInParagraphUTF16,
              valueEndInParagraphUTF16 <= nsText.length
        else {
            return text
        }
        let range = NSRange(
            location: valueStartInParagraphUTF16,
            length: valueEndInParagraphUTF16 - valueStartInParagraphUTF16
        )
        guard nsText.substring(with: range) == replacementText else {
            return text
        }
        return nsText.replacingCharacters(in: range, with: " \(reference)")
    }
}

public struct LocalSensitiveInformationScanner: Sendable {
    private let rules: [SensitiveScanRuleDefinition]

    public init(rules: [SensitiveScanRuleDefinition] = SensitiveScanRuleDefinition.defaults) {
        self.rules = rules.filter { $0.enabled && !$0.labels.isEmpty }
    }

    public func scan(target: URL, excluding excludedURL: URL? = nil) throws -> [LocalSensitiveInformationCandidate] {
        let values = try target.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            return []
        }
        if values.isRegularFile == true {
            guard target.pathExtension.lowercased() == "md",
                  target.standardizedFileURL.path != excludedURL?.standardizedFileURL.path
            else {
                return []
            }
            let text = try String(contentsOf: target, encoding: .utf8)
            return try scan(fileURL: target, filePath: target.lastPathComponent, text: text)
        }
        guard values.isDirectory == true else {
            return []
        }
        return try scan(directory: target, excluding: excludedURL)
    }

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
        return Self.sorted(candidates)
    }

    public func scan(filePath: String, text: String) throws -> [LocalSensitiveInformationCandidate] {
        try scan(fileURL: URL(fileURLWithPath: filePath), filePath: filePath, text: text)
    }

    public func scan(fileURL: URL, filePath: String, text: String) throws -> [LocalSensitiveInformationCandidate] {
        let nsText = text as NSString
        let fingerprint = Self.fingerprint(text)
        var matches: [AssignmentMatch] = []

        for rule in rules {
            let expression = try assignmentExpression(for: rule.labels)
            for result in expression.matches(in: text, range: NSRange(location: 0, length: nsText.length)) {
                let separatorRange = result.range(at: 2)
                guard separatorRange.location != NSNotFound,
                      let value = Self.assignmentValue(in: nsText, after: separatorRange.location + separatorRange.length)
                else {
                    continue
                }
                let label = nsText.substring(with: result.range(at: 1))
                matches.append(AssignmentMatch(rule: rule, label: label, value: value))
            }
        }

        let sortedMatches = matches.sorted { left, right in
            left.rule.risk == right.rule.risk
                ? left.value.range.location < right.value.range.location
                : left.rule.risk == .high
        }
        var acceptedRanges: [NSRange] = []
        var candidates: [LocalSensitiveInformationCandidate] = []

        for match in sortedMatches {
            guard !acceptedRanges.contains(where: { NSIntersectionRange($0, match.value.range).length > 0 }) else {
                continue
            }
            let paragraphRange = Self.paragraphRange(in: text, containingUTF16Offset: match.value.range.location)
            let paragraph = nsText.substring(with: paragraphRange)
            if (try? SecretReference(match.value.plaintext)) != nil {
                continue
            }

            acceptedRanges.append(match.value.range)
            let line = Self.lineNumber(in: text, atUTF16Offset: match.value.range.location)
            let title = match.label.trimmingCharacters(in: .whitespacesAndNewlines)
            candidates.append(
                LocalSensitiveInformationCandidate(
                    id: "\(fileURL.path):\(match.value.range.location):\(match.value.range.length):\(fingerprint)",
                    fileURL: fileURL,
                    source: SensitiveSourceLocation(filePath: filePath, line: line),
                    paragraph: paragraph,
                    matchedValue: match.value.plaintext,
                    valueStartUTF16: match.value.range.location,
                    valueEndUTF16: match.value.range.location + match.value.range.length,
                    paragraphStartUTF16: paragraphRange.location,
                    paragraphEndUTF16: paragraphRange.location + paragraphRange.length,
                    valueStartInParagraphUTF16: match.value.range.location - paragraphRange.location,
                    valueEndInParagraphUTF16: match.value.range.location + match.value.range.length - paragraphRange.location,
                    replacementText: nsText.substring(with: match.value.range),
                    contentFingerprint: fingerprint,
                    rule: match.rule.name,
                    risk: match.rule.risk,
                    title: title.isEmpty ? match.rule.name : title,
                    category: match.rule.category
                )
            )
        }
        return Self.sorted(candidates)
    }

    private struct AssignmentMatch {
        let rule: SensitiveScanRuleDefinition
        let label: String
        let value: ParsedValue
    }

    private struct ParsedValue {
        let plaintext: String
        let range: NSRange
    }

    private func assignmentExpression(for labels: [String]) throws -> NSRegularExpression {
        let alternatives = labels
            .sorted { $0.count > $1.count }
            .map(NSRegularExpression.escapedPattern(for:))
            .joined(separator: "|")
        return try NSRegularExpression(pattern: "(?i)(?<![A-Za-z0-9_])(\(alternatives))(?![A-Za-z0-9_])\\s*([:：=＝])")
    }

    private static func assignmentValue(in text: NSString, after separatorEnd: Int) -> ParsedValue? {
        let lineEndRange = text.range(of: "\n", options: [], range: NSRange(location: separatorEnd, length: text.length - separatorEnd))
        let lineEnd = lineEndRange.location == NSNotFound ? text.length : lineEndRange.location
        var cursor = separatorEnd
        while cursor < lineEnd, isWhitespace(text, at: cursor) {
            cursor += 1
        }
        guard cursor < lineEnd else {
            return nil
        }

        let openingPairs: [(String, String)] = [("**", "**"), ("__", "__"), ("\"", "\""), ("'", "'"), ("`", "`"), ("“", "”"), ("‘", "’"), ("「", "」"), ("『", "』"), ("【", "】"), ("[", "]"), ("(", ")"), ("（", "）")]
        let remainder = text.substring(with: NSRange(location: cursor, length: lineEnd - cursor))
        for (opening, closing) in openingPairs where remainder.hasPrefix(opening) {
            let contentStart = cursor + (opening as NSString).length
            let searchable = text.substring(with: NSRange(location: contentStart, length: lineEnd - contentStart))
            guard searchable.range(of: closing) != nil else {
                continue
            }
            let closingOffset = (searchable as NSString).range(of: closing).location
            let raw = (text.substring(with: NSRange(location: contentStart, length: closingOffset)))
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !raw.isEmpty else {
                return nil
            }
            let end = contentStart + closingOffset + (closing as NSString).length
            return ParsedValue(plaintext: raw, range: NSRange(location: separatorEnd, length: end - separatorEnd))
        }

        var end = cursor
        while end < lineEnd {
            let character = text.substring(with: NSRange(location: end, length: 1))
            if isWhitespace(text, at: end) || [",", "，", ";", "；"].contains(character) {
                break
            }
            end += 1
        }
        let raw = text.substring(with: NSRange(location: cursor, length: end - cursor))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else {
            return nil
        }
        return ParsedValue(plaintext: raw, range: NSRange(location: separatorEnd, length: end - separatorEnd))
    }

    private static func sorted(_ candidates: [LocalSensitiveInformationCandidate]) -> [LocalSensitiveInformationCandidate] {
        candidates.sorted { left, right in
            left.risk == right.risk
                ? left.source.filePath == right.source.filePath
                    ? left.valueStartUTF16 < right.valueStartUTF16
                    : left.source.filePath < right.source.filePath
                : left.risk == .high
        }
    }

    private static func isWhitespace(_ text: NSString, at offset: Int) -> Bool {
        text.substring(with: NSRange(location: offset, length: 1))
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .isEmpty
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
    public static func replace(_ candidate: LocalSensitiveInformationCandidate, reference: String) throws {
        try replace([candidate], references: [reference])
    }

    public static func remove(_ candidate: LocalSensitiveInformationCandidate) throws {
        try replace([candidate], references: [""])
    }

    public static func replacingValues(
        in text: String,
        candidates: [LocalSensitiveInformationCandidate],
        references: [String]
    ) -> String {
        guard candidates.count == references.count, !candidates.isEmpty else {
            return text
        }
        let mutable = NSMutableString(string: text)
        let ordered = zip(candidates, references).sorted { lhs, rhs in
            lhs.0.valueStartInParagraphUTF16 > rhs.0.valueStartInParagraphUTF16
        }
        for (candidate, reference) in ordered {
            let nsText = mutable as NSString
            guard candidate.valueStartInParagraphUTF16 >= 0,
                  candidate.valueEndInParagraphUTF16 >= candidate.valueStartInParagraphUTF16,
                  candidate.valueEndInParagraphUTF16 <= nsText.length
            else {
                return text
            }
            let range = NSRange(
                location: candidate.valueStartInParagraphUTF16,
                length: candidate.valueEndInParagraphUTF16 - candidate.valueStartInParagraphUTF16
            )
            guard nsText.substring(with: range) == candidate.replacementText else {
                return text
            }
            mutable.replaceCharacters(in: range, with: " \(reference)")
        }
        return mutable as String
    }

    public static func validate(_ candidates: [LocalSensitiveInformationCandidate]) throws {
        guard let first = candidates.first else {
            return
        }
        try validateSameSource(candidates, against: first)
        let text = try readSource(at: first.fileURL)
        guard LocalSensitiveInformationScanner.fingerprint(text) == first.contentFingerprint else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }
        let nsText = text as NSString
        for candidate in candidates {
            try validate(candidate, in: nsText)
        }
    }

    public static func replace(
        _ candidates: [LocalSensitiveInformationCandidate],
        references: [String]
    ) throws {
        guard candidates.count == references.count else {
            throw LocalSensitiveInformationWriteError.invalidSource
        }
        guard let first = candidates.first else {
            return
        }
        try validateSameSource(candidates, against: first)
        let text = try readSource(at: first.fileURL)
        guard LocalSensitiveInformationScanner.fingerprint(text) == first.contentFingerprint else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }

        let mutable = NSMutableString(string: text)
        let ordered = zip(candidates, references).sorted { lhs, rhs in
            lhs.0.valueStartUTF16 > rhs.0.valueStartUTF16
        }
        for (candidate, reference) in ordered {
            let nsText = mutable as NSString
            try validate(candidate, in: nsText)
            let range = NSRange(
                location: candidate.valueStartUTF16,
                length: candidate.valueEndUTF16 - candidate.valueStartUTF16
            )
            let replacement = reference.isEmpty ? "" : " \(reference)"
            mutable.replaceCharacters(in: range, with: replacement)
        }

        let values = try first.fileURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw LocalSensitiveInformationWriteError.invalidSource
        }
        if values.isSymbolicLink == true {
            throw LocalSensitiveInformationWriteError.symlinkRejected
        }
        try (mutable as String).write(to: first.fileURL, atomically: true, encoding: .utf8)
    }

    private static func validateSameSource(
        _ candidates: [LocalSensitiveInformationCandidate],
        against first: LocalSensitiveInformationCandidate
    ) throws {
        for candidate in candidates {
            guard candidate.fileURL.standardizedFileURL == first.fileURL.standardizedFileURL,
                  candidate.contentFingerprint == first.contentFingerprint
            else {
                throw LocalSensitiveInformationWriteError.changedSinceScan
            }
        }
    }

    private static func readSource(at url: URL) throws -> String {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw LocalSensitiveInformationWriteError.invalidSource
        }
        if values.isSymbolicLink == true {
            throw LocalSensitiveInformationWriteError.symlinkRejected
        }
        return try String(contentsOf: url, encoding: .utf8)
    }

    private static func validate(_ candidate: LocalSensitiveInformationCandidate, in nsText: NSString) throws {
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
        guard nsText.substring(with: range) == candidate.replacementText else {
            throw LocalSensitiveInformationWriteError.changedSinceScan
        }
    }
}
