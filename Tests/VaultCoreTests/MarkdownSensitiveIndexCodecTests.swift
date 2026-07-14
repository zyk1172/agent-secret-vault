import Foundation
import Testing
@testable import VaultCore

@Test func markdownIndexRoundTripsVisibleMetadataAndEncryptedEnvelope() throws {
    let entry = IndexedEncryptedRecord(
        displayID: "S-001",
        category: "API Key",
        title: "OpenAI API Key",
        source: SensitiveSourceLocation(filePath: "AI/Tools.md", line: 23),
        record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    )

    let text = try MarkdownSensitiveIndexCodec.encode([entry])

    #expect(text.contains("# Sensitive Information Index"))
    #expect(text.contains("## S-001 - OpenAI API Key"))
    #expect(text.contains("secret://0123456789ABCDEFGHJKMNPQRS"))
    #expect(text.contains("```asv-record"))
    #expect(try MarkdownSensitiveIndexCodec.decode(text) == [entry])
}

@Test func markdownIndexRejectsDuplicateDisplayIDs() throws {
    let first = IndexedEncryptedRecord(
        displayID: "S-001",
        category: "API Key",
        title: "First",
        source: nil,
        record: fixtureRecord(id: "ABCDEFGHJKMNPQRSTVWXYZ0123")
    )
    let second = IndexedEncryptedRecord(
        displayID: "S-002",
        category: "Token",
        title: "Second",
        source: nil,
        record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    )
    let firstText = try MarkdownSensitiveIndexCodec.encode([first])
    let secondEntry = try MarkdownSensitiveIndexCodec.encode([second])
        .components(separatedBy: "\n\n")
        .dropFirst()
        .joined(separator: "\n\n")
    let duplicate = firstText + "\n\n" + secondEntry.replacingOccurrences(of: "## S-002", with: "## S-001")

    #expect(throws: MarkdownSensitiveIndexError.duplicateDisplayID("S-001")) {
        _ = try MarkdownSensitiveIndexCodec.decode(duplicate)
    }
}

@Test func markdownIndexRejectsDuplicateReferences() throws {
    let first = IndexedEncryptedRecord(
        displayID: "S-001",
        category: "API Key",
        title: "First",
        source: nil,
        record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    )
    let second = IndexedEncryptedRecord(
        displayID: "S-002",
        category: "Token",
        title: "Second",
        source: nil,
        record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    )
    let firstText = try MarkdownSensitiveIndexCodec.encode([first])
    let secondEntry = try MarkdownSensitiveIndexCodec.encode([second])
        .components(separatedBy: "\n\n")
        .dropFirst()
        .joined(separator: "\n\n")
    let duplicate = firstText + "\n\n" + secondEntry

    #expect(throws: MarkdownSensitiveIndexError.duplicateReference("secret://0123456789ABCDEFGHJKMNPQRS")) {
        _ = try MarkdownSensitiveIndexCodec.decode(duplicate)
    }
}

private func fixtureRecord(id: String) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: 1,
        id: id,
        recordVersion: 1,
        ciphertext: Data([1, 2, 3]),
        nonce: Data([4, 5, 6]),
        tag: Data([7, 8, 9]),
        wrappedDataKey: Data([10, 11, 12]),
        wrappedDataKeyNonce: Data([13, 14, 15]),
        wrappedDataKeyTag: Data([16, 17, 18]),
        label: "OpenAI API Key",
        policy: .credential,
        createdAt: .distantPast,
        updatedAt: .distantPast
    )
}
