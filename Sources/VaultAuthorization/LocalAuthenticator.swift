import Foundation
import LocalAuthentication

protocol LocalAuthenticationEvaluating: Sendable {
    func evaluate(policy: LAPolicy, localizedReason: String) async throws -> Bool
}

public struct LocalAuthenticator: BiometricAuthorizing {
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
        do {
            let success = try await evaluator.evaluate(policy: policy, localizedReason: reason)
            guard success else {
                throw BiometricAuthorizationError.authenticationFailed
            }
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
        let context = LAContext()

        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: localizedReason) { success, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                continuation.resume(returning: success)
            }
        }
    }
}
