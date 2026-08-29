import CryptoKit
import Foundation

/// The risk state used by the local policy engine.  This is deliberately not
/// a numeric risk class: a denied operation is not a more convenient form of
/// approval, and the state machine must keep that distinction explicit.
public enum OperationRisk: String, Codable, CaseIterable, Sendable {
    case silent
    case approvalRequired
    case denied

    public var severity: Int {
        switch self {
        case .silent:
            return 0
        case .approvalRequired:
            return 1
        case .denied:
            return 2
        }
    }

    public static func max(_ lhs: Self, _ rhs: Self) -> Self {
        lhs.severity >= rhs.severity ? lhs : rhs
    }
}

public struct AgentRiskAssessment: Codable, Equatable, Sendable {
    public let declaredRisk: OperationRisk
    public let reason: String
    public let intendedEffect: String

    public init(
        declaredRisk: OperationRisk,
        reason: String,
        intendedEffect: String
    ) {
        self.declaredRisk = declaredRisk
        self.reason = reason
        self.intendedEffect = intendedEffect
    }

    public static let conservativeDefault = AgentRiskAssessment(
        declaredRisk: .silent,
        reason: "Agent did not provide a risk assessment",
        intendedEffect: "unspecified"
    )
}

public enum SecretOperationAction: String, Codable, CaseIterable, Sendable {
    case vaultStatus
    case usagePolicy
    case inspectReference
    case checkReferenceExists
    case sshCommand
    case httpRequest
    case apiRequest
    case databaseQuery
    case sftpTransfer
    case browserLogin
    case localAppFill
    case revealPlaintext
    case copyPlaintext
    case exportPlaintext
    case deleteSecret
    case changeSecretPolicy
    case changeDestinationBinding
    case changeAllowlist
    case changeAuthorizationRules
    case changeKeychain
    case migrateMasterKey
    case importRecoveryKey
    case exportRecoveryKey
    case restoreVault
    case clearVault
    case batchDelete
    case resetVault
    case localExecution
}

/// Stable, sanitized failure states exposed on the local IPC boundary.  The
/// enum deliberately contains no free-form error text so a rejected request
/// cannot turn an exception message into a secret/log exfiltration channel.
public enum SecretOperationError: Error, Equatable, Sendable {
    case operationDenied
    case authorizationCancelled
    case authorizationDenied
    case authorizationTimeout
    case authorizationUnavailable
    case actionExecutorUnavailable
    case actionExecutionFailed
    case redirectRequiresReview
    case outputQuarantined

    public var responseCode: String {
        switch self {
        case .operationDenied:
            return "OPERATION_DENIED"
        case .authorizationCancelled:
            return "AUTHORIZATION_CANCELLED"
        case .authorizationDenied:
            return "AUTHORIZATION_DENIED"
        case .authorizationTimeout:
            return "AUTHORIZATION_TIMEOUT"
        case .authorizationUnavailable:
            return "AUTHORIZATION_UNAVAILABLE"
        case .actionExecutorUnavailable:
            return "ACTION_EXECUTOR_UNAVAILABLE"
        case .actionExecutionFailed:
            return "ACTION_EXECUTION_FAILED"
        case .redirectRequiresReview:
            return "REDIRECT_REQUIRES_REVIEW"
        case .outputQuarantined:
            return "ACTION_OUTPUT_QUARANTINED"
        }
    }
}

public enum SecretOperationProtocol: String, Codable, CaseIterable, Sendable {
    case ssh
    case http
    case https
    case sftp
    case scp
    case postgres
    case mysql
    case browser
    case localApp
    case file
}

public enum SecretFileOperation: String, Codable, CaseIterable, Sendable {
    case list
    case read
    case download
    case upload
    case write
    case overwrite
    case move
    case delete
}

/// Metadata needed by the policy engine.  It is safe to pass across IPC:
/// there is no encrypted record or plaintext value here.
public struct SecretPolicyMetadata: Codable, Equatable, Sendable {
    public let reference: SecretReference
    public let policy: SecretPolicy
    public let label: String?
    public let allowedDestinations: [String]
    public let allowedProtocols: [String]

    public init(
        reference: SecretReference,
        policy: SecretPolicy,
        label: String?,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = []
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.allowedDestinations = allowedDestinations
        self.allowedProtocols = allowedProtocols
    }
}

/// A complete, plaintext-free description of one operation.  `parameters`
/// contains only action parameters and opaque references; the local policy
/// engine treats it as untrusted input and never treats an agent assessment as
/// authorization.
public struct SecretOperationDescriptor: Codable, Equatable, Sendable {
    public let actionType: SecretOperationAction
    public let secretReferences: [SecretReference]
    public let destination: String?
    public let port: Int?
    public let protocolType: SecretOperationProtocol?
    public let command: String?
    public let httpMethod: String?
    public let url: String?
    public let databaseStatement: String?
    public let fileOperation: SecretFileOperation?
    public let fileTarget: String?
    public let localAppBundleID: String?
    public let requestedEffects: [String]
    public let parameters: [String: String]
    public let agentAssessment: AgentRiskAssessment

    public init(
        actionType: SecretOperationAction,
        secretReferences: [SecretReference] = [],
        destination: String? = nil,
        port: Int? = nil,
        protocolType: SecretOperationProtocol? = nil,
        command: String? = nil,
        httpMethod: String? = nil,
        url: String? = nil,
        databaseStatement: String? = nil,
        fileOperation: SecretFileOperation? = nil,
        fileTarget: String? = nil,
        localAppBundleID: String? = nil,
        requestedEffects: [String] = [],
        parameters: [String: String] = [:],
        agentAssessment: AgentRiskAssessment = .conservativeDefault
    ) {
        self.actionType = actionType
        self.secretReferences = secretReferences
        self.destination = destination
        self.port = port
        self.protocolType = protocolType
        self.command = command
        self.httpMethod = httpMethod
        self.url = url
        self.databaseStatement = databaseStatement
        self.fileOperation = fileOperation
        self.fileTarget = fileTarget
        self.localAppBundleID = localAppBundleID
        self.requestedEffects = requestedEffects
        self.parameters = parameters
        self.agentAssessment = agentAssessment
    }

    public var normalizedDestination: String? {
        Self.normalizeDestination(destination ?? url)
    }

    public var normalizedPath: String? {
        if let url, let parsedURL = URL(string: url) {
            return parsedURL.path.isEmpty ? "/" : parsedURL.path
        }
        return fileTarget
    }

    public var commandHash: String? {
        guard let command else {
            return nil
        }
        return Self.sha256Hex(Data(command.utf8))
    }

    /// Stable enough for a short-lived local ticket because sorted JSON makes
    /// dictionary ordering deterministic and all fields are included.
    public var operationHash: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = (try? encoder.encode(self)) ?? Data()
        return Self.sha256Hex(data)
    }

    public func replacingDestination(_ destination: String, url: String? = nil) -> Self {
        Self(
            actionType: actionType,
            secretReferences: secretReferences,
            destination: destination,
            port: port,
            protocolType: protocolType,
            command: command,
            httpMethod: httpMethod,
            url: url ?? self.url,
            databaseStatement: databaseStatement,
            fileOperation: fileOperation,
            fileTarget: fileTarget,
            localAppBundleID: localAppBundleID,
            requestedEffects: requestedEffects,
            parameters: parameters,
            agentAssessment: agentAssessment
        )
    }

    public static func normalizeDestination(_ value: String?) -> String? {
        guard var value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }

        if let url = URL(string: value), let host = url.host {
            let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !normalizedHost.isEmpty else {
                return nil
            }
            if let port = url.port {
                return "\(normalizedHost):\(port)"
            }
            return normalizedHost
        }

        if value.hasPrefix("[") && value.hasSuffix("]") {
            value.removeFirst()
            value.removeLast()
        }
        return value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public struct PolicyDecision: Codable, Equatable, Sendable {
    public let risk: OperationRisk
    public let reasons: [String]
    public let normalizedDestination: String?
    public let requiredApproval: Bool
    public let policyRuleID: String

    public init(
        risk: OperationRisk,
        reasons: [String],
        normalizedDestination: String?,
        requiredApproval: Bool,
        policyRuleID: String
    ) {
        self.risk = risk
        self.reasons = reasons
        self.normalizedDestination = normalizedDestination
        self.requiredApproval = requiredApproval
        self.policyRuleID = policyRuleID
    }
}
