import CryptoKit
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

/// A parsed entry from the human-maintained sensitive-information catalog.
/// `contextTerms` is kept local for deterministic matching and is never part
/// of the MCP result.
/// Legacy flat entry produced by the pre-v2 heuristic parser.  It remains
/// available only as migration input and must not be used as the managed
/// catalog model.
public struct LegacySecretCatalogEntry: Codable, Equatable, Sendable {
    public let reference: String
    public let service: String?
    public let field: SecretCatalogField
    public let label: String?
    public let destinations: [String]
    public let purpose: String?
    public let groupID: String?
    public let contextTerms: [String]

    public init(
        reference: String,
        service: String? = nil,
        field: SecretCatalogField = .other,
        label: String? = nil,
        destinations: [String] = [],
        purpose: String? = nil,
        groupID: String? = nil,
        contextTerms: [String] = []
    ) {
        self.reference = reference
        self.service = service
        self.field = field
        self.label = label
        self.destinations = destinations
        self.purpose = purpose
        self.groupID = groupID
        self.contextTerms = contextTerms
    }

    public static func stableGroupID(
        service: String?,
        destinations: [String],
        headingPath: [String]
    ) -> String? {
        let normalizedService = service.map(normalizeForSearch) ?? ""
        let normalizedDestinations = destinations
            .map(normalizeForSearch)
            .filter { !$0.isEmpty }
            .sorted()
        let normalizedHeadings = headingPath
            .map(normalizeForSearch)
            .filter { !$0.isEmpty }

        let seedParts: [String]
        if !normalizedService.isEmpty || !normalizedDestinations.isEmpty {
            seedParts = [normalizedService] + normalizedDestinations
        } else {
            seedParts = normalizedHeadings
        }
        guard !seedParts.isEmpty else {
            return nil
        }

        let seed = seedParts.joined(separator: "|")
        let digest = SHA256.hash(data: Data(seed.utf8))
        let token = digest.prefix(10).map { String(format: "%02x", $0) }.joined()
        return "group-\(token)"
    }

    public static func normalizeForSearch(_ value: String) -> String {
        value
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
            .lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// Metadata read from an encrypted envelope without decrypting it.
public struct SecretCatalogRecordMetadata: Equatable, Sendable {
    public let reference: String
    public let policy: SecretPolicy
    public let label: String?
    public let allowedDestinations: [String]

    public init(
        reference: String,
        policy: SecretPolicy,
        label: String?,
        allowedDestinations: [String] = []
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.allowedDestinations = allowedDestinations
    }
}

/// The only catalog payload allowed to cross the Swift IPC boundary.
public struct SecretCatalogMatch: Codable, Equatable, Sendable {
    public let reference: String
    public let service: String?
    public let field: SecretCatalogField
    public let label: String?
    public let policy: SecretPolicy
    public let destinations: [String]
    public let purpose: String?
    public let groupID: String?

    public init(
        reference: String,
        service: String?,
        field: SecretCatalogField,
        label: String?,
        policy: SecretPolicy,
        destinations: [String] = [],
        purpose: String? = nil,
        groupID: String? = nil
    ) {
        self.reference = reference
        self.service = service
        self.field = field
        self.label = label
        self.policy = policy
        self.destinations = destinations
        self.purpose = purpose
        self.groupID = groupID
    }
}

public enum SecretCatalogSearchStatus: String, Codable, Sendable {
    case found = "FOUND"
    case notFound = "NOT_FOUND"
    case invalidQuery = "INVALID_QUERY"
    case unavailable = "CATALOG_UNAVAILABLE"
}

public struct SecretCatalogSearchResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let matches: [SecretCatalogMatch]

    public init(status: SecretCatalogSearchStatus, matches: [SecretCatalogMatch] = []) {
        self.status = status
        self.matches = matches
    }
}
