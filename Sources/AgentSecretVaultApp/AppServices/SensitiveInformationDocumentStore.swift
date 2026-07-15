import Foundation
import VaultCore

public struct SensitiveInformationDocumentReference: Identifiable, Equatable, Sendable {
    public let id: String
    public let reference: String
    public let title: String
    public let source: SensitiveSourceLocation

    public init(reference: String, title: String, source: SensitiveSourceLocation) {
        self.id = "\(reference):\(source.line)"
        self.reference = reference
        self.title = title
        self.source = source
    }
}

public enum SensitiveInformationDocumentStoreError: Error, Equatable, Sendable {
    case noSelectedDocument
    case malformedDocument
    case symlinkRejected
    case invalidReference
    case verificationFailed
}

/// The Markdown document is the human-maintained catalog. Encrypted envelopes stay in the local vault.
public actor SensitiveInformationDocumentStore {
    private static let marker = "<!-- agent-secret-vault-sensitive-information: 1 -->"
    private static let referencePattern = "secret://[0-9A-HJKMNP-TV-Z]{26}"
    private var documentURL: URL?

    public init(documentURL: URL? = nil) {
        self.documentURL = documentURL
    }

    public func selectDocument(at url: URL?) throws {
        if let url {
            try assertSafeFile(url)
        }
        documentURL = url
    }

    public func selectedDocumentURL() -> URL? {
        documentURL
    }

    @discardableResult
    public func prepareSelectedDocument() throws -> Bool {
        let url = try requiredURL()
        if FileManager.default.fileExists(atPath: url.path) {
            try assertSafeFile(url)
            let original = try String(contentsOf: url, encoding: .utf8)
            let normalized = Self.normalizedDocument(original)
            guard normalized != original else {
                return false
            }
            try write(normalized, to: url)
            return true
        }

        try write(Self.template, to: url)
        return true
    }

    public func references() throws -> [SensitiveInformationDocumentReference] {
        let url = try requiredURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }
        try assertSafeFile(url)
        return Self.references(in: try String(contentsOf: url, encoding: .utf8), filePath: url.path)
    }

    public func appendParagraph(_ paragraph: String, title: String, reference: String) throws {
        _ = try SecretReference(reference)
        let url = try requiredURL()
        _ = try prepareSelectedDocument()
        let text = try String(contentsOf: url, encoding: .utf8)
        if text.contains(reference) {
            return
        }

        let safeTitle = title
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let heading = safeTitle.isEmpty ? "敏感信息" : safeTitle
        let normalizedParagraph = Self.normalizedReferencePresentation(paragraph)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let updated = text.trimmingCharacters(in: .newlines)
            + "\n\n## \(heading)\n\n"
            + normalizedParagraph
            + "\n"
        try write(updated, to: url)
    }

    public static func defaultDocumentURL(scanTargetURL: URL?) -> URL? {
        guard let scanTargetURL else {
            return nil
        }
        let candidate: URL
        if scanTargetURL.pathExtension.lowercased() == "md" {
            candidate = scanTargetURL.lastPathComponent == "敏感信息.md"
                ? scanTargetURL
                : scanTargetURL.deletingLastPathComponent().appendingPathComponent("敏感信息.md")
        } else {
            candidate = scanTargetURL.appendingPathComponent("敏感信息.md")
        }
        return FileManager.default.fileExists(atPath: candidate.path) ? candidate : nil
    }

    public static func normalizedDocument(_ text: String) -> String {
        let withHeader: String
        if text.contains(marker) {
            withHeader = text
        } else {
            let existing = text.trimmingCharacters(in: .newlines)
            withHeader = existing.isEmpty ? template : template + "\n\n" + existing + "\n"
        }
        return normalizedReferencePresentation(withHeader)
    }

    public static func normalizedReferencePresentation(_ text: String) -> String {
        let linkPattern = "\\[[^\\]\\r\\n]*\\]\\((\(referencePattern))\\)"
        let codePattern = "`\\s*(\(referencePattern))\\s*`"
        let unspacedPattern = "(?<!\\s)(\(referencePattern))"
        let multipleSpacesPattern = "[ \\t]+(\(referencePattern))"
        let linkRegex = try! NSRegularExpression(pattern: linkPattern)
        let codeRegex = try! NSRegularExpression(pattern: codePattern)
        let unspacedRegex = try! NSRegularExpression(pattern: unspacedPattern)
        let fullRange = NSRange(location: 0, length: (text as NSString).length)
        let withoutLinks = linkRegex.stringByReplacingMatches(in: text, range: fullRange, withTemplate: " $1")
        let codeRange = NSRange(location: 0, length: (withoutLinks as NSString).length)
        let withoutCode = codeRegex.stringByReplacingMatches(in: withoutLinks, range: codeRange, withTemplate: " $1")
        let referenceRange = NSRange(location: 0, length: (withoutCode as NSString).length)
        let withRequiredSpace = unspacedRegex.stringByReplacingMatches(in: withoutCode, range: referenceRange, withTemplate: " $1")
        let spaceRange = NSRange(location: 0, length: (withRequiredSpace as NSString).length)
        let spacesRegex = try! NSRegularExpression(pattern: multipleSpacesPattern)
        return spacesRegex.stringByReplacingMatches(in: withRequiredSpace, range: spaceRange, withTemplate: " $1")
    }

    private static func references(in text: String, filePath: String) -> [SensitiveInformationDocumentReference] {
        let regex = try! NSRegularExpression(pattern: referencePattern)
        let nsText = text as NSString
        let matches = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
        return matches.map { match in
            let reference = nsText.substring(with: match.range)
            let line = lineNumber(in: text, offset: match.range.location)
            let title = title(in: text, match: match.range, fallback: "敏感信息")
            return SensitiveInformationDocumentReference(
                reference: reference,
                title: title,
                source: SensitiveSourceLocation(filePath: filePath, line: line)
            )
        }
    }

    private static func title(in text: String, match: NSRange, fallback: String) -> String {
        let nsText = text as NSString
        let lineStartRange = nsText.range(of: "\n", options: .backwards, range: NSRange(location: 0, length: match.location))
        let lineStart = lineStartRange.location == NSNotFound ? 0 : lineStartRange.location + 1
        let prefix = nsText.substring(with: NSRange(location: lineStart, length: match.location - lineStart))
            .replacingOccurrences(of: "#", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "：", with: "")
            .replacingOccurrences(of: ":", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if !prefix.isEmpty {
            return String(prefix.suffix(64))
        }

        let preceding = String(text[..<String.Index(utf16Offset: match.location, in: text)])
        if let heading = preceding.split(separator: "\n").reversed().first(where: { $0.hasPrefix("#") }) {
            let value = heading.trimmingCharacters(in: CharacterSet(charactersIn: "# "))
            if !value.isEmpty {
                return String(value.suffix(64))
            }
        }
        return fallback
    }

    private static func lineNumber(in text: String, offset: Int) -> Int {
        let prefix = (text as NSString).substring(to: offset)
        return prefix.reduce(into: 1) { count, character in
            if character == "\n" { count += 1 }
        }
    }

    private func requiredURL() throws -> URL {
        guard let documentURL else {
            throw SensitiveInformationDocumentStoreError.noSelectedDocument
        }
        return documentURL
    }

    private func write(_ text: String, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        let values = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else {
            throw SensitiveInformationDocumentStoreError.malformedDocument
        }
        if values.isSymbolicLink == true {
            throw SensitiveInformationDocumentStoreError.symlinkRejected
        }
        try text.write(to: url, atomically: true, encoding: .utf8)
        guard try String(contentsOf: url, encoding: .utf8) == text else {
            throw SensitiveInformationDocumentStoreError.verificationFailed
        }
    }

    private func assertSafeFile(_ url: URL) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw SensitiveInformationDocumentStoreError.malformedDocument
        }
        if values.isSymbolicLink == true {
            throw SensitiveInformationDocumentStoreError.symlinkRejected
        }
    }

    private static let template = """
    <!-- agent-secret-vault-sensitive-information: 1 -->
    # 敏感信息

    > **必读：格式与使用**
    > 1. 此文件集中维护敏感信息的用途、上下文与 `secret://` 引用；加密记录只可由 SVLT 解密。
    > 2. 每组信息使用一个独立段落。保留服务、地址、账号等非敏感上下文；敏感值写为一个英文空格后紧跟 `secret://引用 ID`，不得使用反引号、链接、方括号或其他符号包裹。
    > 3. Agent 必须通过 SVLT MCP 查询和使用引用；不得直接读取、修改、猜测或导出敏感明文。
    > 4. 新增敏感值请用 App 或 Obsidian 插件加密；需要删除时先在 App 中确认，再自行清理不再需要的上下文。

    ## 格式模板

    ### 服务 API
    服务: <服务名称>
    地址: <https://example.local/v1>
    API: secret://<REFERENCE_ID>

    ### 账号密码
    服务: <服务名称>
    账号: <账号名称>
    密码: secret://<REFERENCE_ID>

    ### Token
    服务: <服务名称>
    用途: <用途说明>
    Token: secret://<REFERENCE_ID>
    """
}
