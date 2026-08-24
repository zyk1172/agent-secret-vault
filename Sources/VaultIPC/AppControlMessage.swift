import Foundation
import VaultCore

public enum AppControlRequest: Codable, Equatable, Sendable {
    case issueCatalogLease(scope: CatalogWriteScope, duration: TimeInterval?)
    case revokeCatalogLease(nonce: String)
    case catalogStatus
    case catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    )
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
        case scope
        case duration
        case nonce
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
    }

    private enum RequestType: String, Codable {
        case issueCatalogLease
        case revokeCatalogLease
        case catalogStatus
        case catalogCreateIndex
        case catalogBindExistingSecret
        case catalogSecureInput
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .issueCatalogLease:
            self = .issueCatalogLease(
                scope: try container.decode(CatalogWriteScope.self, forKey: .scope),
                duration: try container.decodeIfPresent(TimeInterval.self, forKey: .duration)
            )
        case .revokeCatalogLease:
            self = .revokeCatalogLease(nonce: try container.decode(String.self, forKey: .nonce))
        case .catalogStatus:
            self = .catalogStatus
        case .catalogCreateIndex:
            self = .catalogCreateIndex(
                title: try container.decode(String.self, forKey: .title),
                aliases: try container.decode([String].self, forKey: .aliases),
                tags: try container.decode([String].self, forKey: .tags),
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
        case let .issueCatalogLease(scope, duration):
            try container.encode(RequestType.issueCatalogLease, forKey: .type)
            try container.encode(scope, forKey: .scope)
            try container.encodeIfPresent(duration, forKey: .duration)
        case let .revokeCatalogLease(nonce):
            try container.encode(RequestType.revokeCatalogLease, forKey: .type)
            try container.encode(nonce, forKey: .nonce)
        case .catalogStatus:
            try container.encode(RequestType.catalogStatus, forKey: .type)
        case let .catalogCreateIndex(title, aliases, tags, expectedRevision):
            try container.encode(RequestType.catalogCreateIndex, forKey: .type)
            try container.encode(title, forKey: .title)
            try container.encode(aliases, forKey: .aliases)
            try container.encode(tags, forKey: .tags)
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
    case lease(CatalogWriteLease)
    case catalogStatus(CatalogValidationResult)
    case catalogWriteResult(CatalogWriteResult)
    case secretBound(reference: String, revision: UInt64)
    case operationCompleted
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case lease
        case status
        case reference
        case revision
        case result
        case code
    }

    private enum ResponseType: String, Codable {
        case lease
        case catalogStatus
        case catalogWriteResult
        case secretBound
        case operationCompleted
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .lease:
            self = .lease(try container.decode(CatalogWriteLease.self, forKey: .lease))
        case .catalogStatus:
            self = .catalogStatus(try container.decode(CatalogValidationResult.self, forKey: .status))
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
        case let .lease(lease):
            try container.encode(ResponseType.lease, forKey: .type)
            try container.encode(lease, forKey: .lease)
        case let .catalogStatus(status):
            try container.encode(ResponseType.catalogStatus, forKey: .type)
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
    func issueCatalogLease(scope: CatalogWriteScope, duration: TimeInterval?) async throws -> CatalogWriteLease
    func revokeCatalogLease(nonce: String) async
    func catalogStatus() async throws -> CatalogValidationResult
    func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
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
