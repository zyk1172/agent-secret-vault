import Foundation
import LocalAuthentication

protocol LocalAuthenticationEvaluating: Sendable {
    func evaluate(policy: LAPolicy, localizedReason: String) async throws -> Bool
    func evaluate(
        policy: LAPolicy,
        localizedReason: String,
        using context: LocalAuthenticationContext
    ) async throws -> Bool
}

extension LocalAuthenticationEvaluating {
    func evaluate(
        policy: LAPolicy,
        localizedReason: String,
        using context: LocalAuthenticationContext
    ) async throws -> Bool {
        try await evaluate(policy: policy, localizedReason: localizedReason)
    }
}

public struct LocalAuthenticator: BiometricAuthorizing, KeychainContextAuthorizing {
    public let policy: LAPolicy
    private let evaluator: any LocalAuthenticationEvaluating

    public init(policy: LAPolicy = .deviceOwnerAuthentication) {
        self.init(policy: policy, evaluator: LAContextEvaluator())
    }

    init(
        policy: LAPolicy = .deviceOwnerAuthentication,
        evaluator: any LocalAuthenticationEvaluating
    ) {
        self.policy = policy
        self.evaluator = evaluator
    }

    public func evaluate(reason: String) async throws {
        _ = try await makeAuthenticationContext(reason: reason)
    }

    func makeAuthenticationContext(reason: String) async throws -> LocalAuthenticationContext {
        let context = LocalAuthenticationContext(rawContext: LAContext())
        do {
            let success = try await evaluator.evaluate(
                policy: policy,
                localizedReason: reason,
                using: context
            )
            guard success else {
                throw BiometricAuthorizationError.authenticationFailed
            }
            return context
        } catch let error as BiometricAuthorizationError {
            throw error
        } catch {
            throw Self.mapAuthenticationError(error)
        }
    }

    private static func mapAuthenticationError(_ error: Error?) -> BiometricAuthorizationError {
        guard let error else {
            return .authenticationFailed
        }

        let nsError = error as NSError
        guard nsError.domain == LAError.errorDomain,
              let code = LAError.Code(rawValue: nsError.code)
        else {
            return .authenticationFailed
        }

        switch code {
        case .userCancel, .appCancel, .systemCancel:
            return .cancelled
        case .biometryLockout:
            return .lockout
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
            return .unavailable
        default:
            return .authenticationFailed
        }
    }
}

private struct LAContextEvaluator: LocalAuthenticationEvaluating {
    func evaluate(policy: LAPolicy, localizedReason: String) async throws -> Bool {
        try await evaluate(
            policy: policy,
            localizedReason: localizedReason,
            using: LocalAuthenticationContext(rawContext: LAContext())
        )
    }

    func evaluate(
        policy: LAPolicy,
        localizedReason: String,
        using context: LocalAuthenticationContext
    ) async throws -> Bool {
        try await withCheckedThrowingContinuation { continuation in
            context.rawContext.evaluatePolicy(policy, localizedReason: localizedReason) { success, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                continuation.resume(returning: success)
            }
        }
    }
}
