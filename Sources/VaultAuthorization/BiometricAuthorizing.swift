import Foundation

public protocol BiometricAuthorizing: Sendable {
    func evaluate(reason: String) async throws
}

public enum BiometricAuthorizationError: Error, Equatable, Sendable {
    case cancelled
    case lockout
    case unavailable
    case authenticationFailed
}
