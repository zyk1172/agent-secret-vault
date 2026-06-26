import CryptoKit
import Foundation
import Security

public enum EncryptedAuditLogError: Error, Equatable, Sendable {
    case integrityFailed
    case randomGenerationFailed
}

public struct EncryptedAuditLog: Sendable {
    private let directoryURL: URL
    private let now: @Sendable () -> Date
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        directoryURL: URL,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.directoryURL = directoryURL
        self.now = now

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder
        decoder = JSONDecoder()
    }

    public func append(_ event: AuditEvent, masterKey: SymmetricKey) async throws {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        let eventData = try encoder.encode(event)
        let sealed = try AES.GCM.seal(
            eventData,
            using: auditKey,
            authenticating: Data("AgentSecretVault.AuditEvent.v1".utf8)
        )
        let record = EncryptedAuditEventRecord(
            id: UUID().uuidString,
            createdAt: now(),
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        let url = directoryURL.appending(path: "\(record.id).audit.json")
        try encoder.encode(record).write(to: url, options: [.atomic])
    }

    public func export(masterKey: SymmetricKey) async throws -> [AuditEvent] {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        let records = try eventRecords()
        let events = try records.map { _, record in
            try open(record, using: auditKey)
        }
        return events.sorted { $0.timestamp < $1.timestamp }
    }

    public func prune(retentionDays: Int, masterKey: SymmetricKey) async throws {
        try prepareDirectory()
        let cutoff = now().addingTimeInterval(-Double(retentionDays) * 24 * 60 * 60)
        let auditKey = try auditDataKey(masterKey: masterKey)

        for (url, record) in try eventRecords() {
            let event = try open(record, using: auditKey)
            if event.timestamp < cutoff {
                try FileManager.default.removeItem(at: url)
            }
        }
    }

    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
    }

    private func auditDataKey(masterKey: SymmetricKey) throws -> SymmetricKey {
        let keyURL = directoryURL.appending(path: "audit-key.json")
        if FileManager.default.fileExists(atPath: keyURL.path) {
            let record = try decoder.decode(
                WrappedAuditDataKey.self,
                from: Data(contentsOf: keyURL)
            )
            return SymmetricKey(data: try open(record, masterKey: masterKey))
        }

        let keyData = try randomBytes(count: 32)
        let sealed = try AES.GCM.seal(
            keyData,
            using: masterKey,
            authenticating: Data("AgentSecretVault.AuditDataKey.v1".utf8)
        )
        let record = WrappedAuditDataKey(
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        try encoder.encode(record).write(to: keyURL, options: [.atomic])
        return SymmetricKey(data: keyData)
    }

    private func eventRecords() throws -> [(URL, EncryptedAuditEventRecord)] {
        let urls = try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )
        return try urls
            .filter { $0.lastPathComponent.hasSuffix(".audit.json") }
            .map { url in
                (url, try decoder.decode(EncryptedAuditEventRecord.self, from: Data(contentsOf: url)))
            }
            .sorted { lhs, rhs in
                lhs.1.createdAt < rhs.1.createdAt
            }
    }

    private func open(_ record: EncryptedAuditEventRecord, using auditKey: SymmetricKey) throws -> AuditEvent {
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )
            let data = try AES.GCM.open(
                box,
                using: auditKey,
                authenticating: Data("AgentSecretVault.AuditEvent.v1".utf8)
            )
            return try decoder.decode(AuditEvent.self, from: data)
        } catch {
            throw EncryptedAuditLogError.integrityFailed
        }
    }

    private func open(_ record: WrappedAuditDataKey, masterKey: SymmetricKey) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )
            return try AES.GCM.open(
                box,
                using: masterKey,
                authenticating: Data("AgentSecretVault.AuditDataKey.v1".utf8)
            )
        } catch {
            throw EncryptedAuditLogError.integrityFailed
        }
    }

    private func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw EncryptedAuditLogError.randomGenerationFailed
        }
        return Data(bytes)
    }
}

private struct WrappedAuditDataKey: Codable, Sendable {
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}

private struct EncryptedAuditEventRecord: Codable, Sendable {
    let id: String
    let createdAt: Date
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
