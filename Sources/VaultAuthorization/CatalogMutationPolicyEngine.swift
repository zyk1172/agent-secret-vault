import Foundation
import VaultCore

/// The risk boundary for Catalog mutations. Agent write authorization answers
/// whether safe editing is enabled; this engine answers whether a requested
/// mutation is safe, requires local approval, or is never allowed.
public enum CatalogMutationKind: String, Codable, CaseIterable, Sendable {
    case createIndex
    case createEntry
    case patchMetadata
    case addMetadataField
    case createSecretPlaceholder
    case validate
    case bindExistingSecret
    case replaceSecret
    case deleteSecret
    case deleteSecretBearingEntry
    case deleteSecretBearingIndex
    case changeSecretType
    case changeSecretTarget
    case changeSecretPolicy
    case batchMutation
    case importExport
    case plaintextSecretInCatalog
    case directManagedFileWrite
    case forgedSecretReference
    case agentSelfApproval
}

public struct CatalogMutationDescriptor: Codable, Equatable, Sendable {
    public let kind: CatalogMutationKind
    public let touchesExistingSecret: Bool
    public let changesSecretTarget: Bool

    public init(
        kind: CatalogMutationKind,
        touchesExistingSecret: Bool = false,
        changesSecretTarget: Bool = false
    ) {
        self.kind = kind
        self.touchesExistingSecret = touchesExistingSecret
        self.changesSecretTarget = changesSecretTarget
    }
}

public enum CatalogMutationDecision: String, Codable, Equatable, Sendable {
    case silent
    case approvalRequired
    case denied
}

public struct CatalogMutationPolicyEngine: Sendable {
    public init() {}

    public func evaluate(_ descriptor: CatalogMutationDescriptor) -> CatalogMutationDecision {
        switch descriptor.kind {
        case .plaintextSecretInCatalog, .directManagedFileWrite,
             .forgedSecretReference, .agentSelfApproval:
            return .denied

        case .bindExistingSecret, .replaceSecret, .deleteSecret,
             .deleteSecretBearingEntry, .deleteSecretBearingIndex,
             .changeSecretType, .changeSecretTarget, .changeSecretPolicy,
             .batchMutation, .importExport:
            return .approvalRequired

        case .patchMetadata:
            if descriptor.touchesExistingSecret || descriptor.changesSecretTarget {
                return .approvalRequired
            }
            return .silent

        case .createIndex, .createEntry, .addMetadataField,
             .createSecretPlaceholder, .validate:
            return .silent
        }
    }

    public func requireSilent(_ descriptor: CatalogMutationDescriptor) throws {
        switch evaluate(descriptor) {
        case .silent:
            return
        case .approvalRequired:
            throw SecretCatalogAgentError.approvalRequired
        case .denied:
            throw SecretCatalogAgentError.invalidOperation
        }
    }
}
