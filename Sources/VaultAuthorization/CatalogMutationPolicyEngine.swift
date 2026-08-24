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
    public let semanticKinds: [CatalogSemanticChangeKind]

    public init(
        kind: CatalogMutationKind,
        touchesExistingSecret: Bool = false,
        changesSecretTarget: Bool = false,
        semanticKinds: [CatalogSemanticChangeKind] = []
    ) {
        self.kind = kind
        self.touchesExistingSecret = touchesExistingSecret
        self.changesSecretTarget = changesSecretTarget
        self.semanticKinds = semanticKinds
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
        case .plaintextSecretInCatalog, .forgedSecretReference, .agentSelfApproval:
            return .denied

        case .directManagedFileWrite:
            return aggregate(descriptor.semanticKinds.map { evaluateSemantic($0) })

        case .batchMutation:
            if descriptor.semanticKinds.isEmpty {
                return descriptor.touchesExistingSecret || descriptor.changesSecretTarget ? .approvalRequired : .silent
            }
            return aggregate(descriptor.semanticKinds.map { evaluateSemantic($0) })

        case .bindExistingSecret, .replaceSecret, .deleteSecret,
             .deleteSecretBearingEntry, .deleteSecretBearingIndex,
             .changeSecretType, .changeSecretTarget, .changeSecretPolicy,
             .importExport:
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

    public func evaluate(
        _ diff: CatalogSemanticDiff,
        transport: CatalogMutationKind = .directManagedFileWrite
    ) -> CatalogMutationDecision {
        evaluate(CatalogMutationDescriptor(
            kind: transport,
            touchesExistingSecret: diff.touchesExistingSecret,
            changesSecretTarget: diff.changesSecretTarget,
            semanticKinds: diff.changes.map(\.kind)
        ))
    }

    private func evaluateSemantic(_ kind: CatalogSemanticChangeKind) -> CatalogMutationDecision {
        switch kind {
        case .bindExistingSecret, .replaceSecret, .deleteSecret,
             .deleteSecretBearingEntry, .deleteSecretBearingIndex,
             .changeSecretType, .changeSecretTarget:
            return .approvalRequired
        case .createIndex, .updateIndexMetadata, .deleteIndex,
             .createEntry, .updateEntryMetadata, .moveEntry, .deleteEntry,
             .addMetadataField, .updateMetadataField, .removeMetadataField,
             .createSecretPlaceholder:
            return .silent
        }
    }

    private func aggregate(_ decisions: [CatalogMutationDecision]) -> CatalogMutationDecision {
        if decisions.contains(.denied) { return .denied }
        if decisions.contains(.approvalRequired) { return .approvalRequired }
        return .silent
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
