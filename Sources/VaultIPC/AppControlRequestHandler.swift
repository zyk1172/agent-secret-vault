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
            case let .issueCatalogLease(scope, duration):
                return .lease(try await service.issueCatalogLease(scope: scope, duration: duration))
            case let .revokeCatalogLease(nonce):
                await service.revokeCatalogLease(nonce: nonce)
                return .operationCompleted
            case .catalogStatus:
                return .catalogStatus(try await service.catalogStatus())
            case let .catalogCreateIndex(title, aliases, tags, expectedRevision):
                return .catalogWriteResult(try await service.catalogCreateIndex(
                    title: title,
                    aliases: aliases,
                    tags: tags,
                    expectedRevision: expectedRevision
                ))
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
        } catch let error as CatalogWriteLeaseError {
            return .failure(code: Self.leaseCode(error))
        } catch let error as SecretCatalogAgentError {
            return .failure(code: Self.catalogCode(error))
        } catch let error as SecretOperationError {
            return .failure(code: Self.operationCode(error))
        } catch {
            return .failure(code: "APP_CONTROL_REQUEST_FAILED")
        }
    }

    private static func leaseCode(_ error: CatalogWriteLeaseError) -> String {
        switch error {
        case .invalidNonce: return "CATALOG_LEASE_INVALID"
        case .expired: return "CATALOG_LEASE_EXPIRED"
        case .tooLong: return "CATALOG_LEASE_TOO_LONG"
        case .insufficientScope: return "CATALOG_LEASE_SCOPE_INSUFFICIENT"
        }
    }

    private static func catalogCode(_ error: SecretCatalogAgentError) -> String {
        switch error {
        case .unavailable: return "CATALOG_UNAVAILABLE"
        case .migrationRequired: return "MIGRATION_REQUIRED"
        case .externalModification: return "EXTERNAL_CATALOG_MODIFICATION"
        case .invalidCatalog: return "CATALOG_INVALID"
        case .missingLease: return "CATALOG_LEASE_REQUIRED"
        case .invalidLease: return "CATALOG_LEASE_INVALID"
        case .leaseExpired: return "CATALOG_LEASE_EXPIRED"
        case .insufficientLeaseScope: return "CATALOG_LEASE_SCOPE_INSUFFICIENT"
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
