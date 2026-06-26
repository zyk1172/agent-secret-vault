import Foundation
import Testing
@testable import VaultCore

private let referencedRecordID = "01J33333333333333333333333"
private let orphanRecordID = "01J44444444444444444444444"

@Test func orphanScannerFindsUnreferencedRecordsWithoutDeleting() async throws {
    let baseDirectory = try makeOrphanTemporaryDirectory()
    let markdownDirectory = baseDirectory.appendingPathComponent("notes", isDirectory: true)
    try FileManager.default.createDirectory(at: markdownDirectory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: baseDirectory)
    try await store.save(makeOrphanRecord(id: referencedRecordID, version: 1))
    try await store.save(makeOrphanRecord(id: orphanRecordID, version: 1))
    try await store.save(makeOrphanRecord(id: orphanRecordID, version: 2))

    try """
    This note references `secret://\(referencedRecordID)`.
    This embedded non-reference must not count: prefixsecret://\(orphanRecordID)
    This longer token must not count: secret://\(orphanRecordID)ABC
    """.write(
        to: markdownDirectory.appendingPathComponent("note.md"),
        atomically: true,
        encoding: .utf8
    )

    let scanner = OrphanScanner(
        baseDirectory: baseDirectory,
        markdownDirectories: [markdownDirectory]
    )

    let candidates = try await scanner.scan()

    #expect(candidates == [
        OrphanCandidate(
            id: orphanRecordID,
            versions: [1, 2],
            referencedBy: []
        )
    ])
    #expect(try await store.versions(id: referencedRecordID) == [1])
    #expect(try await store.versions(id: orphanRecordID) == [1, 2])
}

@Test func orphanScannerReturnsReferenceLocationsForReferencedRecords() async throws {
    let baseDirectory = try makeOrphanTemporaryDirectory()
    let markdownDirectory = baseDirectory.appendingPathComponent("notes", isDirectory: true)
    try FileManager.default.createDirectory(at: markdownDirectory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: baseDirectory)
    try await store.save(makeOrphanRecord(id: referencedRecordID, version: 1))
    let noteURL = markdownDirectory.appendingPathComponent("note.md")
    try "secret://\(referencedRecordID)".write(
        to: noteURL,
        atomically: true,
        encoding: .utf8
    )

    let scanner = OrphanScanner(
        baseDirectory: baseDirectory,
        markdownDirectories: [markdownDirectory]
    )

    let candidates = try await scanner.scan(includeReferenced: true)
    #expect(candidates == [
        OrphanCandidate(
            id: referencedRecordID,
            versions: [1],
            referencedBy: [noteURL.standardizedFileURL]
        )
    ], "Actual candidates: \(candidates)")
}

private func makeOrphanTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("OrphanScannerTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func makeOrphanRecord(id: String, version: Int) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: VaultFormat.current,
        id: id,
        recordVersion: version,
        ciphertext: Data([0x10, UInt8(version)]),
        nonce: Data([0x11, UInt8(version)]),
        tag: Data([0x12, UInt8(version)]),
        wrappedDataKey: Data([0x13, UInt8(version)]),
        wrappedDataKeyNonce: Data([0x14, UInt8(version)]),
        wrappedDataKeyTag: Data([0x15, UInt8(version)]),
        label: "record-\(version)",
        policy: .credential,
        createdAt: Date(timeIntervalSinceReferenceDate: 2_000_000),
        updatedAt: Date(timeIntervalSinceReferenceDate: 2_000_000 + Double(version))
    )
}
