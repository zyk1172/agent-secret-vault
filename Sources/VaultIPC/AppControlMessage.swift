import Foundation
import VaultCore

public enum AppControlRequest: Codable, Equatable, Sendable {
    case catalogStatus
    case catalogAdoptExternalV2
    case setCatalogAgentWriteMode(mode: CatalogAgentWriteMode, duration: TimeInterval?)
    case revokeCatalogAgentWrite
    case catalogAgentWriteStatus
    case catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    )
    case catalogCreateEntry(request: CatalogDraftRequest, expectedRevision: UInt64)
    case catalogUpdateEntry(entry: SecretCatalogEntry, expectedRevision: UInt64)
    case catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    )
    case catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    )

    private enum CodingKeys: String, CodingKey {
        case type
        case duration
        case entryID
        case key
        case label
        case plaintext
        case policy
        case title
        case aliases
        case tags
        case expectedRevision
        case secretRef
        case mode
        case request
        case entry
    }

    private enum RequestType: String, Codable {
        case catalogStatus
        case catalogAdoptExternalV2
        case setCatalogAgentWriteMode
        case revokeCatalogAgentWrite
        case catalogAgentWriteStatus
        case catalogCreateIndex
        case catalogCreateEntry
        case catalogUpdateEntry
        case catalogBindExistingSecret
        case catalogSecureInput
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .catalogStatus:
            self = .catalogStatus
        case .catalogAdoptExternalV2:
            self = .catalogAdoptExternalV2
        case .setCatalogAgentWriteMode:
            self = .setCatalogAgentWriteMode(
                mode: try container.decode(CatalogAgentWriteMode.self, forKey: .mode),
                duration: try container.decodeIfPresent(TimeInterval.self, forKey: .duration)
            )
        case .revokeCatalogAgentWrite:
            self = .revokeCatalogAgentWrite
        case .catalogAgentWriteStatus:
            self = .catalogAgentWriteStatus
        case .catalogCreateIndex:
            self = .catalogCreateIndex(
                title: try container.decode(String.self, forKey: .title),
                aliases: try container.decode([String].self, forKey: .aliases),
                tags: try container.decode([String].self, forKey: .tags),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogCreateEntry:
            self = .catalogCreateEntry(
                request: try container.decode(CatalogDraftRequest.self, forKey: .request),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogUpdateEntry:
            self = .catalogUpdateEntry(
                entry: try container.decode(SecretCatalogEntry.self, forKey: .entry),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogBindExistingSecret:
            self = .catalogBindExistingSecret(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                secretRef: try container.decode(String.self, forKey: .secretRef),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogSecureInput:
            self = .catalogSecureInput(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                plaintext: try container.decode(String.self, forKey: .plaintext),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .catalogStatus:
            try container.encode(RequestType.catalogStatus, forKey: .type)
        case .catalogAdoptExternalV2:
            try container.encode(RequestType.catalogAdoptExternalV2, forKey: .type)
        case let .setCatalogAgentWriteMode(mode, duration):
            try container.encode(RequestType.setCatalogAgentWriteMode, forKey: .type)
            try container.encode(mode, forKey: .mode)
            try container.encodeIfPresent(duration, forKey: .duration)
        case .revokeCatalogAgentWrite:
            try container.encode(RequestType.revokeCatalogAgentWrite, forKey: .type)
        case .catalogAgentWriteStatus:
            try container.encode(RequestType.catalogAgentWriteStatus, forKey: .type)
        case let .catalogCreateIndex(title, aliases, tags, expectedRevision):
            try container.encode(RequestType.catalogCreateIndex, forKey: .type)
            try container.encode(title, forKey: .title)
            try container.encode(aliases, forKey: .aliases)
            try container.encode(tags, forKey: .tags)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogCreateEntry(request, expectedRevision):
            try container.encode(RequestType.catalogCreateEntry, forKey: .type)
            try container.encode(request, forKey: .request)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogUpdateEntry(entry, expectedRevision):
            try container.encode(RequestType.catalogUpdateEntry, forKey: .type)
            try container.encode(entry, forKey: .entry)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
            try container.encode(RequestType.catalogBindExistingSecret, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encode(secretRef, forKey: .secretRef)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogSecureInput(entryID, key, label, plaintext, policy):
            try container.encode(RequestType.catalogSecureInput, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(plaintext, forKey: .plaintext)
            try container.encode(policy, forKey: .policy)
        }
    }
}

public enum AppControlResponse: Codable, Equatable, Sendable {
    case catalogStatus(CatalogValidationResult)
    case catalogAgentWriteStatus(CatalogAgentWriteAuthorizationStatus)
    case catalogWriteResult(CatalogWriteResult)
    case secretBound(reference: String, revision: UInt64)
    case operationCompleted
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case status
        case reference
        case revision
        case result
        case code
    }

    private enum ResponseType: String, Codable {
        case catalogStatus
        case catalogAgentWriteStatus
        case catalogWriteResult
        case secretBound
        case operationCompleted
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .catalogStatus:
            self = .catalogStatus(try container.decode(CatalogValidationResult.self, forKey: .status))
        case .catalogAgentWriteStatus:
            self = .catalogAgentWriteStatus(try container.decode(CatalogAgentWriteAuthorizationStatus.self, forKey: .status))
        case .catalogWriteResult:
            self = .catalogWriteResult(try container.decode(CatalogWriteResult.self, forKey: .result))
        case .secretBound:
            self = .secretBound(
                reference: try container.decode(String.self, forKey: .reference),
                revision: try container.decode(UInt64.self, forKey: .revision)
            )
        case .operationCompleted:
            self = .operationCompleted
        case .failure:
            self = .failure(code: try container.decode(String.self, forKey: .code))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .catalogStatus(status):
            try container.encode(ResponseType.catalogStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .catalogAgentWriteStatus(status):
            try container.encode(ResponseType.catalogAgentWriteStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .catalogWriteResult(result):
            try container.encode(ResponseType.catalogWriteResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .secretBound(reference, revision):
            try container.encode(ResponseType.secretBound, forKey: .type)
            try container.encode(reference, forKey: .reference)
            try container.encode(revision, forKey: .revision)
        case .operationCompleted:
            try container.encode(ResponseType.operationCompleted, forKey: .type)
        case let .failure(code):
            try container.encode(ResponseType.failure, forKey: .type)
            try container.encode(code, forKey: .code)
        }
    }
}

public struct AuthenticatedAppControlRequest: Codable, Equatable, Sendable {
    public let capabilityToken: CapabilityToken
    public let request: AppControlRequest

    public init(capabilityToken: CapabilityToken, request: AppControlRequest) {
        self.capabilityToken = capabilityToken
        self.request = request
    }
}

public protocol AppControlServicing: Sendable {
    func catalogStatus() async throws -> CatalogValidationResult
    func adoptCatalogExternalV2() async throws -> CatalogValidationResult
    func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus
    func revokeCatalogAgentWrite() async
    func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus
    func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64)
}
