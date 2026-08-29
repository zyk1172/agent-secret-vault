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

    public var authorizationRequirement: AuthorizationRequirement {
        switch self {
        case .silent:
            return .none
        case .approvalRequired:
            return .reusableApproval
        case .denied:
            return .denied
        }
    }
}

/// Risk and authorization reuse are separate policy dimensions. A destructive
/// operation can therefore require a new device-owner decision even when a
/// reusable approval lease for ordinary writes is still active.
public enum AuthorizationRequirement: String, Codable, CaseIterable, Sendable {
    case none
    case reusableApproval
    case freshApprovalRequired
    case denied

    public var severity: Int {
        switch self {
        case .none: return 0
        case .reusableApproval: return 1
        case .freshApprovalRequired: return 2
        case .denied: return 3
        }
    }

    public static func max(_ lhs: Self, _ rhs: Self) -> Self {
        lhs.severity >= rhs.severity ? lhs : rhs
    }

    public var requiresApproval: Bool {
        self == .reusableApproval || self == .freshApprovalRequired
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
    case invalidOperationParameters
    case sessionNotFound
    case sessionExpired
    case sessionScopeMismatch
    case sessionControlUnavailable
    case sessionLimitReached
    case batchValidationFailed
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
        case .invalidOperationParameters:
            return "ARGUMENT_VALIDATION"
        case .sessionNotFound:
            return "SESSION_NOT_FOUND"
        case .sessionExpired:
            return "SESSION_EXPIRED"
        case .sessionScopeMismatch:
            return "SESSION_SCOPE_MISMATCH"
        case .sessionControlUnavailable:
            return "SESSION_CONTROL_UNAVAILABLE"
        case .sessionLimitReached:
            return "SESSION_LIMIT_REACHED"
        case .batchValidationFailed:
            return "BATCH_VALIDATION_FAILED"
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

public enum SSHCommandBatchValidationError: Error, Equatable, Sendable {
    case empty
    case tooManyCommands
    case executableMissing
    case executableTooLong
    case executableContainsControlCharacter
    case tooManyArguments
    case argumentTooLong
    case argumentContainsControlCharacter
    case encodedBatchTooLarge
}

/// Structured SSH input. The command is still encoded as one safely quoted
/// remote-shell string at the final OpenSSH boundary; callers never provide a
/// raw shell fragment.
public struct SSHCommandSpec: Codable, Equatable, Hashable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String] = []) {
        self.executable = executable
        self.arguments = arguments
    }

    public func validate(
        maxExecutableLength: Int = 128,
        maxArgumentCount: Int = 32,
        maxArgumentLength: Int = 4_096
    ) throws {
        guard !executable.isEmpty else { throw SSHCommandBatchValidationError.executableMissing }
        guard executable.utf8.count <= maxExecutableLength else {
            throw SSHCommandBatchValidationError.executableTooLong
        }
        guard !executable.unicodeScalars.contains(where: Self.isUnsafeExecutableScalar) else {
            throw SSHCommandBatchValidationError.executableContainsControlCharacter
        }
        guard arguments.count <= maxArgumentCount else {
            throw SSHCommandBatchValidationError.tooManyArguments
        }
        for argument in arguments {
            guard argument.utf8.count <= maxArgumentLength else {
                throw SSHCommandBatchValidationError.argumentTooLong
            }
            guard !argument.unicodeScalars.contains(where: Self.isUnsafeArgumentScalar) else {
                throw SSHCommandBatchValidationError.argumentContainsControlCharacter
            }
        }
    }

    private static func isUnsafeExecutableScalar(_ scalar: UnicodeScalar) -> Bool {
        scalar.value < 0x20 || scalar.value == 0x7F
    }

    /// Tabs, newlines, and carriage returns are valid literal argument bytes
    /// when the remote encoder places the complete argument inside POSIX
    /// single quotes. NUL and other controls are rejected because they cannot
    /// be represented safely in an argv value or may act as terminal/control
    /// injection data on the remote side.
    private static func isUnsafeArgumentScalar(_ scalar: UnicodeScalar) -> Bool {
        scalar.value == 0
            || ((scalar.value < 0x20 || scalar.value == 0x7F)
                && scalar.value != 0x09
                && scalar.value != 0x0A
                && scalar.value != 0x0D)
    }
}

public struct SSHCommandBatch: Codable, Equatable, Sendable {
    public static let maxCommands = 32
    public static let maxEncodedBytes = 256 * 1024

    public let commands: [SSHCommandSpec]
    public let stopOnFailure: Bool

    public init(commands: [SSHCommandSpec], stopOnFailure: Bool = true) {
        self.commands = commands
        self.stopOnFailure = stopOnFailure
    }

    public func validate() throws {
        guard !commands.isEmpty else { throw SSHCommandBatchValidationError.empty }
        guard commands.count <= Self.maxCommands else {
            throw SSHCommandBatchValidationError.tooManyCommands
        }
        for command in commands {
            try command.validate()
        }
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(self), data.count <= Self.maxEncodedBytes else {
            throw SSHCommandBatchValidationError.encodedBatchTooLarge
        }
    }
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
    /// Opaque transport handle. It is never used as an authorization grant;
    /// the service still validates the kernel-derived principal and policy for
    /// every command.
    public let sessionID: String?
    public let sshCommandBatch: SSHCommandBatch?
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
        sessionID: String? = nil,
        sshCommandBatch: SSHCommandBatch? = nil,
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
        self.sessionID = sessionID
        self.sshCommandBatch = sshCommandBatch
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
        if let sshCommandBatch,
           let data = try? JSONEncoder().encode(sshCommandBatch) {
            return Self.sha256Hex(data)
        }
        guard let command else {
            return nil
        }
        return Self.sha256Hex(Data(command.utf8))
    }

    /// Stable enough for a short-lived local ticket because sorted JSON makes
    /// dictionary ordering deterministic. Transport handles are intentionally
    /// excluded: a sessionID identifies a reusable connection, not the
    /// operation's authorization subject, so replacing an expired transport
    /// must not change the exact operation ticket.
    public var operationHash: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = (try? encoder.encode(AuthorizationHashPayload(descriptor: self))) ?? Data()
        return Self.sha256Hex(data)
    }

    private struct AuthorizationHashPayload: Codable {
        let actionType: SecretOperationAction
        let secretReferences: [SecretReference]
        let destination: String?
        let port: Int?
        let protocolType: SecretOperationProtocol?
        let command: String?
        let httpMethod: String?
        let url: String?
        let databaseStatement: String?
        let fileOperation: SecretFileOperation?
        let fileTarget: String?
        let localAppBundleID: String?
        let sshCommandBatch: SSHCommandBatch?
        let requestedEffects: [String]
        let parameters: [String: String]
        let agentAssessment: AgentRiskAssessment

        init(descriptor: SecretOperationDescriptor) {
            actionType = descriptor.actionType
            secretReferences = descriptor.secretReferences
            destination = descriptor.destination
            port = descriptor.port
            protocolType = descriptor.protocolType
            command = descriptor.command
            httpMethod = descriptor.httpMethod
            url = descriptor.url
            databaseStatement = descriptor.databaseStatement
            fileOperation = descriptor.fileOperation
            fileTarget = descriptor.fileTarget
            localAppBundleID = descriptor.localAppBundleID
            sshCommandBatch = descriptor.sshCommandBatch
            requestedEffects = descriptor.requestedEffects
            parameters = descriptor.parameters
            agentAssessment = descriptor.agentAssessment
        }
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
            sessionID: sessionID,
            sshCommandBatch: sshCommandBatch,
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
    public let authorizationRequirement: AuthorizationRequirement
    public let policyRuleID: String

    public init(
        risk: OperationRisk,
        reasons: [String],
        normalizedDestination: String?,
        requiredApproval: Bool,
        policyRuleID: String,
        authorizationRequirement: AuthorizationRequirement? = nil
    ) {
        self.risk = risk
        self.reasons = reasons
        self.normalizedDestination = normalizedDestination
        self.requiredApproval = requiredApproval
        self.authorizationRequirement = authorizationRequirement ?? risk.authorizationRequirement
        self.policyRuleID = policyRuleID
    }

    private enum CodingKeys: String, CodingKey {
        case risk, reasons, normalizedDestination, requiredApproval, authorizationRequirement, policyRuleID
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let risk = try container.decode(OperationRisk.self, forKey: .risk)
        self.init(
            risk: risk,
            reasons: try container.decode([String].self, forKey: .reasons),
            normalizedDestination: try container.decodeIfPresent(String.self, forKey: .normalizedDestination),
            requiredApproval: try container.decodeIfPresent(Bool.self, forKey: .requiredApproval) ?? (risk != .silent),
            policyRuleID: try container.decode(String.self, forKey: .policyRuleID),
            authorizationRequirement: try container.decodeIfPresent(AuthorizationRequirement.self, forKey: .authorizationRequirement)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(risk, forKey: .risk)
        try container.encode(reasons, forKey: .reasons)
        try container.encodeIfPresent(normalizedDestination, forKey: .normalizedDestination)
        try container.encode(requiredApproval, forKey: .requiredApproval)
        try container.encode(authorizationRequirement, forKey: .authorizationRequirement)
        try container.encode(policyRuleID, forKey: .policyRuleID)
    }
}
