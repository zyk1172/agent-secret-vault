import Foundation

public enum SecretCatalogAgentError: Error, Equatable, Sendable {
    case unavailable
    case migrationRequired
    case externalModification
    case invalidCatalog
    case missingLease
    case invalidLease
    case leaseExpired
    case insufficientLeaseScope
    case revisionConflict
    case invalidOperation
    case approvalRequired
}

/// The smallest unit of authority an Agent can carry when changing the
/// managed catalog.  Structure authority is intentionally a superset of
/// metadata authority; the inverse is never true.
public enum CatalogWriteScope: String, Codable, CaseIterable, Sendable {
    case metadata
    case structure

    public func permits(_ required: CatalogWriteScope) -> Bool {
        self == .structure || self == required
    }
}

public enum CatalogWriteLeaseError: Error, Equatable, Sendable {
    case invalidNonce
    case expired
    case tooLong
    case insufficientScope
}

/// A lease is issued by the App control plane.  The shared MCP socket can
/// present one but has no operation that creates, extends, or signs one.
public struct CatalogWriteLease: Codable, Equatable, Sendable {
    public static let maximumLifetime: TimeInterval = 600

    public let scope: CatalogWriteScope
    public let issuedAt: Date
    public let expiresAt: Date
    public let nonce: String

    public init(
        scope: CatalogWriteScope,
        issuedAt: Date,
        expiresAt: Date,
        nonce: String
    ) {
        self.scope = scope
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.nonce = nonce
    }

    public static func generated(
        scope: CatalogWriteScope,
        issuedAt: Date = Date(),
        duration: TimeInterval = maximumLifetime
    ) throws -> Self {
        guard duration > 0, duration <= maximumLifetime else {
            throw CatalogWriteLeaseError.tooLong
        }
        return Self(
            scope: scope,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(duration),
            nonce: try SecretCatalogOpaqueID.generate()
        )
    }

    public func validate(
        requiredScope: CatalogWriteScope,
        now: Date = Date()
    ) throws {
        guard (try? SecretCatalogOpaqueID.validate(nonce)) != nil else {
            throw CatalogWriteLeaseError.invalidNonce
        }
        guard expiresAt > now else {
            throw CatalogWriteLeaseError.expired
        }
        guard issuedAt <= expiresAt,
              expiresAt.timeIntervalSince(issuedAt) <= Self.maximumLifetime
        else {
            throw CatalogWriteLeaseError.tooLong
        }
        guard scope.permits(requiredScope) else {
            throw CatalogWriteLeaseError.insufficientScope
        }
    }
}

/// Metadata-only patch accepted by the Agent catalog service.  The service
/// rejects secret transitions and secret-bearing values on this path; secret
/// binding has a separate operation and approval boundary.
public struct CatalogMetadataPatch: Codable, Equatable, Sendable {
    public let title: String?
    public let aliases: [String]?
    public let tags: [String]?
    public let endpoints: [CatalogEndpoint]?
    public let notes: String?
    public let fields: [SecretCatalogFieldValue]?

    public init(
        title: String? = nil,
        aliases: [String]? = nil,
        tags: [String]? = nil,
        endpoints: [CatalogEndpoint]? = nil,
        notes: String? = nil,
        fields: [SecretCatalogFieldValue]? = nil
    ) {
        self.title = title
        self.aliases = aliases
        self.tags = tags
        self.endpoints = endpoints
        self.notes = notes
        self.fields = fields
    }
}

public struct CatalogDraftRequest: Codable, Equatable, Sendable {
    public let indexID: String
    public let title: String
    public let type: String
    public let aliases: [String]
    public let tags: [String]
    public let fields: [SecretCatalogFieldValue]

    public init(
        indexID: String,
        title: String,
        type: String = "credential",
        aliases: [String] = [],
        tags: [String] = [],
        fields: [SecretCatalogFieldValue] = []
    ) {
        self.indexID = indexID
        self.title = title
        self.type = type
        self.aliases = aliases
        self.tags = tags
        self.fields = fields
    }
}

public struct CatalogDraft: Codable, Equatable, Sendable {
    public let draftID: String
    public let baseRevision: UInt64
    public let entry: SecretCatalogEntryMatch

    public init(draftID: String, baseRevision: UInt64, entry: SecretCatalogEntryMatch) {
        self.draftID = draftID
        self.baseRevision = baseRevision
        self.entry = entry
    }
}

public struct CatalogWriteResult: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let entry: SecretCatalogEntryMatch?

    public init(revision: UInt64, entry: SecretCatalogEntryMatch? = nil) {
        self.revision = revision
        self.entry = entry
    }
}

public struct CatalogValidationResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64?

    public init(status: SecretCatalogSearchStatus, revision: UInt64? = nil) {
        self.status = status
        self.revision = revision
    }
}
