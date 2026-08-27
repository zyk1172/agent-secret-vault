import Foundation

/// The field classification is metadata only.  It never contains or derives a
/// secret value.
public enum SecretCatalogField: String, Codable, CaseIterable, Sendable {
    case username
    case password
    case token
    case apiKey
    case cookie
    case privateKey
    case other

    public var displayName: String {
        switch self {
        case .username:
            return "用户名"
        case .password:
            return "密码"
        case .token:
            return "Token"
        case .apiKey:
            return "API Key"
        case .cookie:
            return "Cookie"
        case .privateKey:
            return "私钥"
        case .other:
            return "其他"
        }
    }

    public static func fromKey(_ key: String) -> Self? {
        let normalized = key
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "-", with: "")

        switch normalized {
        case "账号", "用户名", "user", "username", "login", "account":
            return .username
        case "密码", "password", "pass", "pwd":
            return .password
        case "token", "令牌", "访问令牌", "bearertoken":
            return .token
        case "api", "apikey", "api密钥", "密钥":
            return .apiKey
        case "cookie", "cookies":
            return .cookie
        case "私钥", "privatekey", "sshkey":
            return .privateKey
        case "其他", "other":
            return .other
        default:
            return nil
        }
    }
}

public enum SecretCatalogSearchStatus: String, Codable, Sendable {
    case found = "FOUND"
    case notFound = "NOT_FOUND"
    case invalidQuery = "INVALID_QUERY"
    case unavailable = "CATALOG_UNAVAILABLE"
    case legacyCatalogUnsupported = "LEGACY_CATALOG_UNSUPPORTED"
    case integrityMissing = "INTEGRITY_MISSING"
    case externalModification = "EXTERNAL_CATALOG_MODIFICATION"
    case pendingExternalChange = "PENDING_EXTERNAL_CHANGE"
    case invalidCatalog = "CATALOG_INVALID"
}

public struct SecretCatalogIndexMatch: Codable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let aliases: [String]
    public let tags: [String]

    public init(id: String, title: String, aliases: [String] = [], tags: [String] = []) {
        self.id = id
        self.title = title
        self.aliases = aliases
        self.tags = tags
    }
}

/// A non-sensitive Index projection used for Catalog browsing.  Unlike the
/// Entry-centric search result, this projection intentionally includes empty
/// Indexes so an Agent can continue a create/read workflow without reading
/// selection sidecars or the Markdown document.
public struct SecretCatalogIndexSummary: Codable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let aliases: [String]
    public let tags: [String]
    public let entryCount: Int

    public init(
        id: String,
        title: String,
        aliases: [String] = [],
        tags: [String] = [],
        entryCount: Int
    ) {
        self.id = id
        self.title = title
        self.aliases = aliases
        self.tags = tags
        self.entryCount = entryCount
    }
}

public struct SecretCatalogFieldMatch: Codable, Equatable, Sendable {
    public let key: String
    public let label: String
    public let type: SecretCatalogFieldType
    public let value: SecretCatalogValue?
    public let secretRef: String?

    public init(
        key: String,
        label: String,
        type: SecretCatalogFieldType,
        value: SecretCatalogValue? = nil,
        secretRef: String? = nil
    ) {
        self.key = key
        self.label = label
        self.type = type
        self.value = value
        self.secretRef = secretRef
    }
}

public struct SecretCatalogEntryMatch: Codable, Equatable, Sendable {
    public let id: String
    public let indexId: String
    public let title: String
    public let type: String
    public let aliases: [String]
    public let endpoints: [CatalogEndpoint]
    public let fields: [SecretCatalogFieldMatch]
    public let notes: String?
    public let tags: [String]

    public init(
        id: String,
        indexId: String,
        title: String,
        type: String,
        aliases: [String] = [],
        endpoints: [CatalogEndpoint] = [],
        fields: [SecretCatalogFieldMatch] = [],
        notes: String? = nil,
        tags: [String] = []
    ) {
        self.id = id
        self.indexId = indexId
        self.title = title
        self.type = type
        self.aliases = aliases
        self.endpoints = endpoints
        self.fields = fields
        self.notes = notes
        self.tags = tags
    }
}

/// Entry-centric response shared by `secret_search` and
/// `secret_catalog_search`.  It contains only allowed metadata plus opaque
/// `secret://` handles; it never contains a decrypted value.
public struct SecretCatalogMatch: Codable, Equatable, Sendable {
    public let index: SecretCatalogIndexMatch
    public let entry: SecretCatalogEntryMatch

    public init(index: SecretCatalogIndexMatch, entry: SecretCatalogEntryMatch) {
        self.index = index
        self.entry = entry
    }
}

public struct SecretCatalogSearchResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let matches: [SecretCatalogMatch]

    public init(status: SecretCatalogSearchStatus, matches: [SecretCatalogMatch] = []) {
        self.status = status
        self.matches = matches
    }
}

public struct SecretCatalogIndexListResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64
    public let indices: [SecretCatalogIndexSummary]

    public init(
        status: SecretCatalogSearchStatus = .found,
        revision: UInt64,
        indices: [SecretCatalogIndexSummary] = []
    ) {
        self.status = status
        self.revision = revision
        self.indices = indices
    }
}

public struct SecretCatalogEntryListResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64
    public let indexID: String
    public let entries: [SecretCatalogEntryMatch]

    public init(
        status: SecretCatalogSearchStatus,
        revision: UInt64,
        indexID: String,
        entries: [SecretCatalogEntryMatch] = []
    ) {
        self.status = status
        self.revision = revision
        self.indexID = indexID
        self.entries = entries
    }
}
