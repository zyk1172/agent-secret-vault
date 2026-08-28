import CryptoKit
import Foundation
import Testing
@testable import VaultCore

@Test func auditEventEncodingUsesOnlyFixedAllowlistedFields() throws {
    let events = [
        AuditEvent(
            timestamp: Date(timeIntervalSince1970: 1_800_000_000),
            integration: "codex",
            referenceID: "0123456789ABCDEFGHJKMNPQRS",
            operation: .reveal,
            risk: 0,
            authorizationOutcome: .approved,
            declaredTarget: nil,
            status: .displayedToUser,
            exitCode: nil
        ),
        AuditEvent(
            timestamp: Date(timeIntervalSince1970: 1_800_000_001),
            integration: "mcp",
            referenceID: nil,
            operation: .secureExecute,
            risk: 1,
            authorizationOutcome: .approved,
            declaredTarget: "api.example.com/v1/send",
            status: .completed,
            exitCode: 0
        ),
        AuditEvent(
            timestamp: Date(timeIntervalSince1970: 1_800_000_002),
            integration: "codex",
            referenceID: "0123456789ABCDEFGHJKMNPQRS",
            operation: .create,
            risk: 2,
            authorizationOutcome: .denied,
            declaredTarget: nil,
            status: .failure,
            exitCode: nil
        )
    ]

    for event in events {
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
        #expect(Set(collectKeys(in: object)).isSubset(of: AuditEvent.allowedEncodedKeys))
        #expect(collectForbiddenKeys(in: object).isEmpty)
    }
}

@Test func encryptedAuditLogDoesNotPersistPlaintextEventFields() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-log-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xA1, count: 32))
    let event = AuditEvent(
        timestamp: Date(timeIntervalSince1970: 1_800_000_003),
        integration: "codex",
        referenceID: "0123456789ABCDEFGHJKMNPQRS",
        operation: .reveal,
        risk: 0,
        authorizationOutcome: .approved,
        declaredTarget: "api.example.com",
        status: .displayedToUser,
        exitCode: nil
    )

    try await log.append(event, masterKey: masterKey)

    let persisted = try allFileBytes(under: directory)
    #expect(!persisted.contains(Data("codex".utf8)))
    #expect(!persisted.contains(Data("0123456789ABCDEFGHJKMNPQRS".utf8)))
    #expect(!persisted.contains(Data("api.example.com".utf8)))
    #expect(try await log.export(masterKey: masterKey) == [event])
}

@Test func encryptedAuditLogRetentionRemovesRecordsOlderThanThirtyDays() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-retention-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let now = Date(timeIntervalSince1970: 1_900_000_000)
    let log = EncryptedAuditLog(directoryURL: directory, now: { now })
    let masterKey = SymmetricKey(data: Data(repeating: 0xB2, count: 32))
    let thirtyDaysOld = makeAuditEvent(timestamp: now.addingTimeInterval(-30 * 24 * 60 * 60))
    let thirtyOneDaysOld = makeAuditEvent(timestamp: now.addingTimeInterval(-31 * 24 * 60 * 60))

    try await log.append(thirtyDaysOld, masterKey: masterKey)
    try await log.append(thirtyOneDaysOld, masterKey: masterKey)
    try await log.prune(retentionDays: 30, masterKey: masterKey)

    #expect(try await log.export(masterKey: masterKey) == [thirtyDaysOld])
}

@Test func encryptedAuditLogRecentReturnsBoundedNewestFirstWindow() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xC3, count: 32))
    let first = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_100))
    let second = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_101))
    let third = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_102))

    try await log.append(first, masterKey: masterKey)
    try await log.append(second, masterKey: masterKey)
    try await log.append(third, masterKey: masterKey)

    #expect(try await log.recent(limit: 2, masterKey: masterKey) == [third, second])
    #expect((try await log.recent(limit: 0, masterKey: masterKey)).count == 1)
    #expect((try await log.recent(limit: 101, masterKey: masterKey)).count == 3)
}

@Test func encryptedAuditLogRecentCreatesMissingDirectoryAndReturnsEmpty() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-empty-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    #expect(!FileManager.default.fileExists(atPath: directory.path))

    let log = EncryptedAuditLog(
        directoryURL: directory,
        auditKeyProvider: { SymmetricKey(data: Data(repeating: 0xD3, count: 32)) }
    )
    let events = try await log.recent()

    #expect(events.isEmpty)
    #expect(FileManager.default.fileExists(atPath: directory.path))

    let result = try await log.recentWithDiagnostics()
    #expect(result.events.isEmpty)
    #expect(result.diagnostics == .none)
}

@Test func encryptedAuditLogRecentKeepsHealthyRecordsWhenOneRecordIsMalformed() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-malformed-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xD4, count: 32))
    let first = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_400))
    let second = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_401))

    try await log.append(first, masterKey: masterKey)
    try await log.append(second, masterKey: masterKey)
    try Data("{\"truncated\":".utf8).write(
        to: directory.appending(path: "broken.audit.json"),
        options: [.atomic]
    )

    let result = try await log.recentWithDiagnostics(limit: 100, masterKey: masterKey)

    #expect(result.events == [second, first])
    #expect(result.diagnostics.unreadableRecordCount == 1)
    #expect(result.diagnostics.integrityFailureCount == 0)
}

@Test func encryptedAuditLogRecentReportsTamperedRecordWithoutDroppingHealthyRecords() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-tamper-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xD4, count: 32))

    try await log.append(makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_200)), masterKey: masterKey)
    let healthy = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_201))
    try await log.append(healthy, masterKey: masterKey)
    let auditFile = try #require(
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first(where: { $0.pathExtension == "json" && $0.lastPathComponent != "audit-key.json" })
    )
    var object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: auditFile)) as? [String: Any]
    )
    object["createdAt"] = 0
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: auditFile, options: [.atomic])

    let result = try await log.recentWithDiagnostics(limit: 100, masterKey: masterKey)

    #expect(result.events.count == 1)
    #expect(result.diagnostics.unreadableRecordCount == 0)
    #expect(result.diagnostics.integrityFailureCount == 1)
}

@Test func encryptedAuditLogRecentAuthenticatesBeforeApplyingTopN() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-top-n-integrity-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let clock = AuditTestClock(start: 1_700_000_000)
    let log = EncryptedAuditLog(directoryURL: directory, now: { clock.now() })
    let masterKey = SymmetricKey(data: Data(repeating: 0xD5, count: 32))
    let first = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_500))
    let second = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_501))

    try await log.append(first, masterKey: masterKey)
    try await log.append(second, masterKey: masterKey)
    let auditFiles = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        .filter { $0.lastPathComponent.hasSuffix(".audit.json") }
    let newestOuterRecord = try #require(
        auditFiles
            .map { (url: $0, createdAt: try persistedCreatedAt($0)) }
            .max { $0.createdAt < $1.createdAt }?
            .url
    )
    var object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: newestOuterRecord)) as? [String: Any]
    )
    object["createdAt"] = 0
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        .write(to: newestOuterRecord, options: [.atomic])

    let result = try await log.recentWithDiagnostics(limit: 1, masterKey: masterKey)

    #expect(result.events == [first])
    #expect(result.diagnostics.integrityFailureCount == 1)
}

@Test func encryptedAuditLogRecentKeepsLegacyRecordsReadable() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-legacy-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let auditKey = SymmetricKey(data: Data(repeating: 0xE5, count: 32))
    let log = EncryptedAuditLog(
        directoryURL: directory,
        auditKeyProvider: { auditKey }
    )
    let event = makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_300))
    try await log.append(event)

    let auditFile = try #require(
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first(where: { $0.pathExtension == "json" && $0.lastPathComponent != "audit-key.json" })
    )
    let sealed = try AES.GCM.seal(
        JSONEncoder().encode(event),
        using: auditKey,
        authenticating: Data("AgentSecretVault.AuditEvent.v1".utf8)
    )
    let legacy = LegacyAuditEventRecord(
        id: "legacy-audit-record",
        createdAt: Date(timeIntervalSince1970: 1_900_000_300),
        ciphertext: sealed.ciphertext,
        nonce: Data(sealed.nonce),
        tag: sealed.tag
    )
    try JSONEncoder().encode(legacy).write(to: auditFile, options: [.atomic])

    #expect(try await log.recent(limit: 1) == [event])
}

private final class AuditTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var next: TimeInterval

    init(start: TimeInterval) {
        next = start
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        defer { next += 1 }
        return Date(timeIntervalSince1970: next)
    }
}

private func persistedCreatedAt(_ url: URL) throws -> Date {
    let object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
    )
    let value = try #require(object["createdAt"] as? NSNumber)
    return Date(timeIntervalSinceReferenceDate: value.doubleValue)
}

private func makeAuditEvent(timestamp: Date) -> AuditEvent {
    AuditEvent(
        timestamp: timestamp,
        integration: "codex",
        referenceID: "0123456789ABCDEFGHJKMNPQRS",
        operation: .secureExecute,
        risk: 1,
        authorizationOutcome: .approved,
        declaredTarget: "api.example.com",
        status: .completed,
        exitCode: 0
    )
}

private struct LegacyAuditEventRecord: Codable {
    let id: String
    let createdAt: Date
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}

private func allFileBytes(under directory: URL) throws -> Data {
    let urls = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil
    )
    return try urls.reduce(into: Data()) { partial, url in
        partial.append(try Data(contentsOf: url))
    }
}

private func collectKeys(in value: Any) -> [String] {
    if let dictionary = value as? [String: Any] {
        return dictionary.flatMap { key, nestedValue in
            [key] + collectKeys(in: nestedValue)
        }
    }
    if let array = value as? [Any] {
        return array.flatMap(collectKeys)
    }
    return []
}

private func collectForbiddenKeys(in value: Any) -> [String] {
    let forbidden = /plaintext|secretValue|resolvedArguments|masterKey|metadata/.ignoresCase()
    if let dictionary = value as? [String: Any] {
        return dictionary.flatMap { key, nestedValue in
            var matches: [String] = []
            if key.contains(forbidden) {
                matches.append(key)
            }
            matches.append(contentsOf: collectForbiddenKeys(in: nestedValue))
            return matches
        }
    }
    if let array = value as? [Any] {
        return array.flatMap(collectForbiddenKeys)
    }
    return []
}
