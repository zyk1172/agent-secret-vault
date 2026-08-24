import Foundation
import VaultCore
import VaultExecution

public enum AppControlRequestHandlerError: Error, Equatable, Sendable {
    case unsupportedRequest
}

public struct AppControlRequestHandler: Sendable {
    private let service: any AppControlServicing

    public init(service: any AppControlServicing) {
        self.service = service
    }

    public func handle(_ request: AppControlRequest) async -> AppControlResponse {
        do {
            switch request {
            case .catalogStatus:
                return .catalogStatus(try await service.catalogStatus())
            case .catalogAdoptExternalV2:
                return .catalogStatus(try await service.adoptCatalogExternalV2())
            case let .setCatalogAgentWriteMode(mode, duration):
                return .catalogAgentWriteStatus(try await service.setCatalogAgentWriteMode(mode: mode, duration: duration))
            case .revokeCatalogAgentWrite:
                await service.revokeCatalogAgentWrite()
                return .operationCompleted
            case .catalogAgentWriteStatus:
                return .catalogAgentWriteStatus(await service.catalogAgentWriteStatus())
            case let .catalogCreateIndex(title, aliases, tags, expectedRevision):
                return .catalogWriteResult(try await service.catalogCreateIndex(
                    title: title,
                    aliases: aliases,
                    tags: tags,
                    expectedRevision: expectedRevision
                ))
            case let .catalogCreateEntry(request, expectedRevision):
                return .catalogWriteResult(try await service.catalogCreateEntry(request, expectedRevision: expectedRevision))
            case let .catalogUpdateEntry(entry, expectedRevision):
                return .catalogWriteResult(try await service.catalogUpdateEntry(entry, expectedRevision: expectedRevision))
            case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
                return .catalogWriteResult(try await service.catalogBindExistingSecret(
                    entryID: entryID,
                    key: key,
                    secretRef: secretRef,
                    expectedRevision: expectedRevision
                ))
            case let .catalogSecureInput(entryID, key, label, plaintext, policy):
                let result = try await service.catalogSecureInput(
                    entryID: entryID,
                    key: key,
                    label: label,
                    plaintext: plaintext,
                    policy: policy
                )
                return .secretBound(reference: result.reference, revision: result.revision)
            }
        } catch let error as SecretCatalogAgentError {
            return .failure(code: Self.catalogCode(error))
        } catch let error as SecretOperationError {
            return .failure(code: Self.operationCode(error))
        } catch {
            return .failure(code: "APP_CONTROL_REQUEST_FAILED")
        }
    }

    private static func catalogCode(_ error: SecretCatalogAgentError) -> String {
        switch error {
        case .unavailable: return "CATALOG_UNAVAILABLE"
        case .legacyCatalogUnsupported: return "LEGACY_CATALOG_UNSUPPORTED"
        case .integrityMissing: return "INTEGRITY_MISSING"
        case .externalModification: return "EXTERNAL_CATALOG_MODIFICATION"
        case .invalidCatalog: return "CATALOG_INVALID"
        case .agentWriteNotAllowed: return "CATALOG_AGENT_WRITE_NOT_ALLOWED"
        case .revisionConflict: return "CATALOG_REVISION_CONFLICT"
        case .invalidOperation: return "CATALOG_INVALID_OPERATION"
        case .approvalRequired: return "CATALOG_APPROVAL_REQUIRED"
        }
    }

    private static func operationCode(_ error: SecretOperationError) -> String {
        switch error {
        case .operationDenied: return "CATALOG_OPERATION_DENIED"
        case .authorizationCancelled: return "CATALOG_AUTHORIZATION_CANCELLED"
        case .authorizationDenied: return "CATALOG_AUTHORIZATION_DENIED"
        case .authorizationTimeout: return "CATALOG_AUTHORIZATION_TIMEOUT"
        case .authorizationUnavailable: return "CATALOG_AUTHORIZATION_UNAVAILABLE"
        default: return "CATALOG_OPERATION_FAILED"
        }
    }
}
