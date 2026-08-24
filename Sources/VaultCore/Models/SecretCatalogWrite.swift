import Foundation

public enum SecretCatalogAgentError: Error, Equatable, Sendable {
    case unavailable
    case legacyCatalogUnsupported
    case integrityMissing
    case externalModification
    case pendingExternalChange
    case invalidCatalog
    case agentWriteNotAllowed
    case revisionConflict
    case invalidOperation
    case approvalRequired
    /// The Catalog write failed and at least one newly-created opaque record
    /// could not be deleted. The ID is persisted in cleanup metadata for a
    /// later orphan scan/reconciliation; plaintext is never included.
    case cleanupRequired
}

/// The user-facing App-control setting for Agent catalog writes.  The
/// authorization state stays in the App/Agent control plane; MCP callers never
/// supply or manufacture a token, nonce, or lease.
public enum CatalogAgentWriteMode: String, Codable, CaseIterable, Sendable {
    case disabled
    /// Safe catalog editing is the normal Agent mode. It is an App-controlled
    /// on/off preference, not a ten-minute structure lease.
    case safe
    /// Kept for wire compatibility with older clients. New mutations must use
    /// CatalogMutationPolicyEngine instead of treating these as global gates.
    case metadata
    case structure

    public var displayName: String {
        switch self {
        case .disabled: return "禁止 Agent 修改"
        case .safe: return "允许安全目录编辑"
        case .metadata: return "仅允许普通元数据"
        case .structure: return "允许结构修改"
        }
    }

    public func permits(_ required: CatalogAgentWriteScope) -> Bool {
        switch self {
        case .disabled: return false
        case .safe: return true
        case .metadata: return required == .metadata
        case .structure: return true
        }
    }
}

public struct CatalogAgentWriteAuthorizationStatus: Codable, Equatable, Sendable {
    public let mode: CatalogAgentWriteMode
    public let expiresAt: Date?

    public init(mode: CatalogAgentWriteMode, expiresAt: Date? = nil) {
        self.mode = mode
        self.expiresAt = expiresAt
    }

    public func isActive(at date: Date = Date()) -> Bool {
        if mode == .safe {
            return true
        }
        return mode != .disabled && (expiresAt.map { $0 > date } ?? false)
    }
}

/// The smallest unit of authority checked by the Agent catalog service.
/// Structure authority is intentionally a superset of metadata authority;
/// callers never carry a token or nonce for this scope.
public enum CatalogAgentWriteScope: String, Codable, CaseIterable, Sendable {
    case metadata
    case structure

    public func permits(_ required: CatalogAgentWriteScope) -> Bool {
        self == .structure || self == required
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
    public let endpoints: [CatalogEndpoint]
    public let notes: String?
    public let fields: [SecretCatalogFieldValue]

    public init(
        indexID: String,
        title: String,
        type: String = "credential",
        aliases: [String] = [],
        tags: [String] = [],
        endpoints: [CatalogEndpoint] = [],
        notes: String? = nil,
        fields: [SecretCatalogFieldValue] = []
    ) {
        self.indexID = indexID
        self.title = title
        self.type = type
        self.aliases = aliases
        self.tags = tags
        self.endpoints = endpoints
        self.notes = notes
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

/// Plaintext supplied only for the duration of an App-controlled Entry edit.
/// It is never a Catalog value and is consumed by the service before the
/// resulting opaque reference is written to Markdown.
public struct CatalogSecretInput: Codable, Equatable, Sendable {
    public let key: String
    public let label: String
    public let plaintext: String

    public init(key: String, label: String, plaintext: String) {
        self.key = key
        self.label = label
        self.plaintext = plaintext
    }
}

public struct CatalogWriteResult: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let entry: SecretCatalogEntryMatch?
    /// Opaque reference returned only by the App-controlled secure-input
    /// flow. It is never plaintext and is optional so existing catalog write
    /// responses remain wire-compatible.
    public let secretReference: String?

    public init(
        revision: UInt64,
        entry: SecretCatalogEntryMatch? = nil,
        secretReference: String? = nil
    ) {
        self.revision = revision
        self.entry = entry
        self.secretReference = secretReference
    }
}

public struct CatalogValidationResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64?
    public let pendingExternalChange: CatalogPendingExternalChange?

    public init(
        status: SecretCatalogSearchStatus,
        revision: UInt64? = nil,
        pendingExternalChange: CatalogPendingExternalChange? = nil
    ) {
        self.status = status
        self.revision = revision
        self.pendingExternalChange = pendingExternalChange
    }
}

/// Opaque identity for the exact external document that was shown for local
/// approval.  Hashes are concurrency tokens only; no Markdown or secret value
/// is exposed through AppControl.
public struct CatalogPendingExternalChange: Codable, Equatable, Sendable {
    public let acceptedRevision: UInt64
    public let rawSHA256: String
    public let semanticSHA256: String

    public init(acceptedRevision: UInt64, rawSHA256: String, semanticSHA256: String) {
        self.acceptedRevision = acceptedRevision
        self.rawSHA256 = rawSHA256
        self.semanticSHA256 = semanticSHA256
    }
}
