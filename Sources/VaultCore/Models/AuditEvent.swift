import Foundation

public struct AuditEvent: Codable, Equatable, Sendable {
    public static let allowedEncodedKeys: Set<String> = [
        "timestamp",
        "integration",
        "referenceID",
        "operation",
        "risk",
        "authorizationOutcome",
        "declaredTarget",
        "status",
        "exitCode"
    ]

    public let timestamp: Date
    public let integration: String
    public let referenceID: String?
    public let operation: AuditOperation
    public let risk: Int
    public let authorizationOutcome: AuditAuthorizationOutcome
    public let declaredTarget: String?
    public let status: AuditStatus
    public let exitCode: Int32?

    public init(
        timestamp: Date,
        integration: String,
        referenceID: String?,
        operation: AuditOperation,
        risk: Int,
        authorizationOutcome: AuditAuthorizationOutcome,
        declaredTarget: String?,
        status: AuditStatus,
        exitCode: Int32?
    ) {
        self.timestamp = timestamp
        self.integration = integration
        self.referenceID = referenceID
        self.operation = operation
        self.risk = risk
        self.authorizationOutcome = authorizationOutcome
        self.declaredTarget = declaredTarget
        self.status = status
        self.exitCode = exitCode
    }
}

public enum AuditOperation: String, Codable, Equatable, Sendable {
    case status
    case reveal
    case create
    case secureExecute
}

public enum AuditAuthorizationOutcome: String, Codable, Equatable, Sendable {
    case approved
    case denied
    case notRequired
}

public enum AuditStatus: String, Codable, Equatable, Sendable {
    case displayedToUser
    case created
    case completed
    case quarantined
    case failure
}
