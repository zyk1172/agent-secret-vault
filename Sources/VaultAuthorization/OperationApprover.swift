import Foundation

public enum OperationAuthorizationError: Error, Equatable, Sendable {
    case cancelled
    case denied
    case timeout
    case unavailable
}

public protocol OperationApproving: Sendable {
    func approve(summary: String) async throws
}

/// Uses Apple's system-owned Touch ID / device-owner authentication UI.  The
/// summary is deliberately generated from policy-controlled fields and never
/// contains secret material.
public struct LocalOperationApprover: OperationApproving {
    private let authenticator: any BiometricAuthorizing

    public init(authenticator: any BiometricAuthorizing = LocalAuthenticator()) {
        self.authenticator = authenticator
    }

    public func approve(summary: String) async throws {
        do {
            try await authenticator.evaluate(reason: summary)
        } catch let error as BiometricAuthorizationError {
            switch error {
            case .cancelled:
                throw OperationAuthorizationError.cancelled
            case .unavailable:
                throw OperationAuthorizationError.unavailable
            case .lockout, .authenticationFailed:
                throw OperationAuthorizationError.denied
            }
        } catch is CancellationError {
            throw OperationAuthorizationError.cancelled
        } catch {
            throw OperationAuthorizationError.denied
        }
    }
}
