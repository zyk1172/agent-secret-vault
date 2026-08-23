import Foundation
import LocalAuthentication

public protocol BiometricAuthorizing: Sendable {
    func evaluate(reason: String) async throws
}

/// A single LAContext which has already completed the user authentication
/// policy.  It is deliberately passed to Keychain queries so Security does
/// not create a second authentication context for the same operation.
public final class LocalAuthenticationContext: @unchecked Sendable {
    let rawContext: LAContext

    init(rawContext: LAContext) {
        self.rawContext = rawContext
    }
}

/// Implemented by authenticators that can hand the evaluated LAContext to a
/// Keychain material store.  The compatibility fallback in DeviceKeyStore is
/// only used by test/dedicated non-Keychain authorizers.
protocol KeychainContextAuthorizing: BiometricAuthorizing {
    func makeAuthenticationContext(reason: String) async throws -> LocalAuthenticationContext
}

public enum BiometricAuthorizationError: Error, Equatable, Sendable {
    case cancelled
    case lockout
    case unavailable
    case authenticationFailed
}
