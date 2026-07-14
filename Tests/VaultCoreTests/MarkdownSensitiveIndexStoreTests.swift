import Foundation
import Testing
@testable import VaultCore

@Test func markdownIndexStoreRequiresSelectedFile() async throws {
    let store = MarkdownSensitiveIndexStore()

    await #expect(throws: MarkdownSensitiveIndexStoreError.noSelectedIndex) {
        _ = try await store.recordIDs()
    }
}

@Test func markdownIndexStorePersistsRecordsInSelectedMarkdownFile() async throws {
    let directory = try makeMarkdownIndexTemporaryDirectory()
    let indexURL = directory.appendingPathComponent("Sensitive Information.md")
    let store = MarkdownSensitiveIndexStore(indexURL: indexURL)
    let record = makeMarkdownIndexRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 1)

    try await store.save(
        record,
        metadata: SensitiveIndexMetadata(
            category: "API Key",
            title: "OpenAI API Key",
            source: SensitiveSourceLocation(filePath: "AI/Tools.md", line: 23)
        )
    )

    let text = try String(contentsOf: indexURL, encoding: .utf8)
    #expect(text.contains("## S-001 - OpenAI API Key"))
    #expect(text.contains("secret://0123456789ABCDEFGHJKMNPQRS"))
    #expect(try await store.recordIDs() == ["0123456789ABCDEFGHJKMNPQRS"])
    #expect(try await store.latest(id: record.id) == record)
    #expect(try await store.versions(id: record.id) == [1])
}

@Test func markdownIndexStorePreservesExistingMetadataWhenReplacingARecord() async throws {
    let directory = try makeMarkdownIndexTemporaryDirectory()
    let indexURL = directory.appendingPathComponent("Sensitive Information.md")
    let store = MarkdownSensitiveIndexStore(indexURL: indexURL)
    let first = makeMarkdownIndexRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 1)
    let second = makeMarkdownIndexRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 2)
    let metadata = SensitiveIndexMetadata(category: "API Key", title: "OpenAI API Key", source: nil)

    try await store.save(first, metadata: metadata)
    try await store.save(second, metadata: SensitiveIndexMetadata(category: "Other", title: "Ignored", source: nil))

    let entries = try await store.entries()
    #expect(entries.count == 1)
    #expect(entries[0].category == metadata.category)
    #expect(entries[0].title == metadata.title)
    #expect(entries[0].record == second)
}

@Test func markdownIndexStoreLeavesExistingFileUntouchedWhenIndexIsMalformed() async throws {
    let directory = try makeMarkdownIndexTemporaryDirectory()
    let indexURL = directory.appendingPathComponent("Sensitive Information.md")
    let malformed = "not an index\n"
    try Data(malformed.utf8).write(to: indexURL)
    let store = MarkdownSensitiveIndexStore(indexURL: indexURL)

    await #expect(throws: MarkdownSensitiveIndexStoreError.malformedIndex) {
        try await store.save(makeMarkdownIndexRecord(id: "0123456789ABCDEFGHJKMNPQRS", version: 1))
    }

    #expect(try String(contentsOf: indexURL, encoding: .utf8) == malformed)
}

@Test func markdownIndexStoreRejectsSymbolicLinkIndex() async throws {
    let directory = try makeMarkdownIndexTemporaryDirectory()
    let targetURL = directory.appendingPathComponent("target.md")
    try Data("placeholder".utf8).write(to: targetURL)
    let indexURL = directory.appendingPathComponent("Sensitive Information.md")
    try FileManager.default.createSymbolicLink(at: indexURL, withDestinationURL: targetURL)
    let store = MarkdownSensitiveIndexStore(indexURL: indexURL)

    await #expect(throws: MarkdownSensitiveIndexStoreError.symlinkRejected) {
        _ = try await store.recordIDs()
    }
}

private func makeMarkdownIndexTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("MarkdownSensitiveIndexStoreTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func makeMarkdownIndexRecord(id: String, version: Int) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: VaultFormat.current,
        id: id,
        recordVersion: version,
        ciphertext: Data([0x01, UInt8(version)]),
        nonce: Data([0x02, UInt8(version)]),
        tag: Data([0x03, UInt8(version)]),
        wrappedDataKey: Data([0x04, UInt8(version)]),
        wrappedDataKeyNonce: Data([0x05, UInt8(version)]),
        wrappedDataKeyTag: Data([0x06, UInt8(version)]),
        label: "OpenAI API Key",
        policy: .credential,
        createdAt: Date(timeIntervalSinceReferenceDate: 1_234_567.25),
        updatedAt: Date(timeIntervalSinceReferenceDate: 1_234_567.5 + Double(version))
    )
}
