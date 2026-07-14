import Foundation

public struct SensitiveSourceLocation: Codable, Equatable, Sendable {
    public let filePath: String
    public let line: Int

    public init(filePath: String, line: Int) {
        self.filePath = filePath
        self.line = line
    }
}

public struct IndexedEncryptedRecord: Equatable, Sendable {
    public let displayID: String
    public let category: String
    public let title: String
    public let source: SensitiveSourceLocation?
    public let record: EncryptedRecord

    public init(
        displayID: String,
        category: String,
        title: String,
        source: SensitiveSourceLocation?,
        record: EncryptedRecord
    ) {
        self.displayID = displayID
        self.category = category
        self.title = title
        self.source = source
        self.record = record
    }
}
