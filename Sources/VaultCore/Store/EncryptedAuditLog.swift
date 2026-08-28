import CryptoKit
import Foundation
import Security

public enum EncryptedAuditLogError: Error, Equatable, Sendable {
    case integrityFailed
    case randomGenerationFailed
    case auditKeyUnavailable
}

public struct EncryptedAuditLog: Sendable {
    private static let legacyAuditEventAssociatedData = Data("AgentSecretVault.AuditEvent.v1".utf8)
    private static let authenticatedAuditEventMetadataVersion = 2

    private let directoryURL: URL
    private let auditKeyProvider: (@Sendable () async throws -> SymmetricKey)?
    private let now: @Sendable () -> Date
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        directoryURL: URL,
        auditKeyProvider: (@Sendable () async throws -> SymmetricKey)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.directoryURL = directoryURL
        self.auditKeyProvider = auditKeyProvider
        self.now = now

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder
        decoder = JSONDecoder()
    }

    /// Production path. The supplied key is independent from the vault
    /// master key and is loaded without `.userPresence`, so status requests
    /// cannot trigger a vault unlock.
    public func append(_ event: AuditEvent) async throws {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try await append(event, auditKey: auditKeyProvider())
    }

    /// Compatibility path for explicit audit export/migration callers that
    /// already hold a master key. VaultAppServices never calls this to record
    /// routine activity.
    public func append(_ event: AuditEvent, masterKey: SymmetricKey) async throws {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        try await append(event, auditKey: auditKey)
    }

    public func export() async throws -> [AuditEvent] {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        let key = try await auditKeyProvider()
        return try export(auditKey: key)
    }

    public func export(masterKey: SymmetricKey) async throws -> [AuditEvent] {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        return try export(auditKey: auditKey)
    }

    /// Returns only the bounded recent window used by the local App. Full
    /// audit export remains unavailable on the App-control protocol.
    public func recent(limit: Int = 100) async throws -> [AuditEvent] {
        try await recentWithDiagnostics(limit: limit).events
    }

    /// Returns the bounded recent window together with safe diagnostics for
    /// records that could not be read or authenticated. The legacy `recent`
    /// overload above keeps its array-shaped source compatibility for callers
    /// that do not need diagnostics.
    public func recentWithDiagnostics(limit: Int = 100) async throws -> AuditReadResult {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try prepareDirectory()
        let key = try await auditKeyProvider()
        return try recent(limit: limit, auditKey: key)
    }

    public func recent(limit: Int = 100, masterKey: SymmetricKey) async throws -> [AuditEvent] {
        try await recentWithDiagnostics(limit: limit, masterKey: masterKey).events
    }

    public func recentWithDiagnostics(limit: Int = 100, masterKey: SymmetricKey) async throws -> AuditReadResult {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        return try recent(limit: limit, auditKey: auditKey)
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

    private func append(_ event: AuditEvent, auditKey: SymmetricKey) async throws {
        try prepareDirectory()
        let eventData = try encoder.encode(event)
        let recordID = UUID().uuidString
        let createdAt = now()
        let sealed = try AES.GCM.seal(
            eventData,
            using: auditKey,
            authenticating: Self.authenticatedAuditEventAssociatedData(
                id: recordID,
                createdAt: createdAt
            )
        )
        let record = EncryptedAuditEventRecord(
            id: recordID,
            createdAt: createdAt,
            metadataVersion: Self.authenticatedAuditEventMetadataVersion,
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        let url = directoryURL.appending(path: "\(record.id).audit.json")
        try encoder.encode(record).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func export(auditKey: SymmetricKey) throws -> [AuditEvent] {
        try prepareDirectory()
        let records = try eventRecords()
        let events = try records.map { _, record in
            try open(record, using: auditKey)
        }
        return events.sorted { $0.timestamp < $1.timestamp }
    }

    private func recent(limit: Int, auditKey: SymmetricKey) throws -> AuditReadResult {
        let boundedLimit = min(max(limit, 1), 100)
        let recordResult = try readEventRecords()
        var events: [AuditEvent] = []
        var integrityFailureCount = recordResult.diagnostics.integrityFailureCount

        // Authenticate and decode every structurally readable record before
        // sorting or applying the top-N bound. In v2, the outer createdAt is
        // authenticated metadata; it must never decide which records receive
        // integrity verification.
        for (_, record) in recordResult.records {
            do {
                events.append(try open(record, using: auditKey))
            } catch {
                integrityFailureCount += 1
            }
        }

        return AuditReadResult(
            events: Array(events.sorted { $0.timestamp > $1.timestamp }.prefix(boundedLimit)),
            diagnostics: AuditReadDiagnostics(
                unreadableRecordCount: recordResult.diagnostics.unreadableRecordCount,
                integrityFailureCount: integrityFailureCount
            )
        )
    }

    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directoryURL.path
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
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: keyURL.path
        )
        return SymmetricKey(data: keyData)
    }

    private func eventRecords() throws -> [(URL, EncryptedAuditEventRecord)] {
        let result = try readEventRecords()
        guard !result.diagnostics.hasIssues else {
            throw EncryptedAuditLogError.integrityFailed
        }
        return result.records.sorted { lhs, rhs in
            lhs.1.createdAt < rhs.1.createdAt
        }
    }

    private func readEventRecords() throws -> AuditRecordReadResult {
        let urls = try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )
        var records: [(URL, EncryptedAuditEventRecord)] = []
        var unreadableRecordCount = 0
        for url in urls where url.lastPathComponent.hasSuffix(".audit.json") {
            do {
                records.append((
                    url,
                    try decoder.decode(
                        EncryptedAuditEventRecord.self,
                        from: Data(contentsOf: url)
                    )
                ))
            } catch {
                unreadableRecordCount += 1
            }
        }
        return AuditRecordReadResult(
            records: records,
            diagnostics: AuditReadDiagnostics(unreadableRecordCount: unreadableRecordCount)
        )
    }

    private func open(_ record: EncryptedAuditEventRecord, using auditKey: SymmetricKey) throws -> AuditEvent {
        do {
            let associatedData: Data
            switch record.metadataVersion {
            case 1:
                associatedData = Self.legacyAuditEventAssociatedData
            case Self.authenticatedAuditEventMetadataVersion:
                associatedData = Self.authenticatedAuditEventAssociatedData(
                    id: record.id,
                    createdAt: record.createdAt
                )
            default:
                throw EncryptedAuditLogError.integrityFailed
            }
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )
            let data = try AES.GCM.open(
                box,
                using: auditKey,
                authenticating: associatedData
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

    private static func authenticatedAuditEventAssociatedData(id: String, createdAt: Date) -> Data {
        var data = Data("AgentSecretVault.AuditEvent.v2\n".utf8)
        data.append(contentsOf: id.utf8)
        data.append(0)
        data.append(contentsOf: createdAt.timeIntervalSince1970.description.utf8)
        return data
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
    let metadataVersion: Int
    let ciphertext: Data
    let nonce: Data
    let tag: Data

    init(
        id: String,
        createdAt: Date,
        metadataVersion: Int = 2,
        ciphertext: Data,
        nonce: Data,
        tag: Data
    ) {
        self.id = id
        self.createdAt = createdAt
        self.metadataVersion = metadataVersion
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case createdAt
        case metadataVersion
        case ciphertext
        case nonce
        case tag
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        // Records written before metadata binding have no version field and
        // remain readable with the legacy event associated data.
        metadataVersion = try container.decodeIfPresent(Int.self, forKey: .metadataVersion) ?? 1
        ciphertext = try container.decode(Data.self, forKey: .ciphertext)
        nonce = try container.decode(Data.self, forKey: .nonce)
        tag = try container.decode(Data.self, forKey: .tag)
    }
}

private struct AuditRecordReadResult: Sendable {
    let records: [(URL, EncryptedAuditEventRecord)]
    let diagnostics: AuditReadDiagnostics
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
