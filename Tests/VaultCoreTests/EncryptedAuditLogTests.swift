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

@Test func encryptedAuditLogRecentRejectsTamperedRoutingMetadata() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-recent-tamper-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: directory)
    }
    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0xD4, count: 32))

    try await log.append(makeAuditEvent(timestamp: Date(timeIntervalSince1970: 1_900_000_200)), masterKey: masterKey)
    let auditFile = try #require(
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first(where: { $0.pathExtension == "json" && $0.lastPathComponent != "audit-key.json" })
    )
    var object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: auditFile)) as? [String: Any]
    )
    object["createdAt"] = 0
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: auditFile, options: [.atomic])

    await #expect(throws: EncryptedAuditLogError.integrityFailed) {
        try await log.recent(limit: 1, masterKey: masterKey)
    }
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
