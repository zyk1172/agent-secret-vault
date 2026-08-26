import Foundation

public struct AuditEvent: Codable, Equatable, Sendable {
    public static let allowedEncodedKeys: Set<String> = [
        "eventID",
        "timestamp",
        "source",
        "integration",
        "referenceID",
        "referenceCount",
        "operation",
        "risk",
        "authorizationOutcome",
        "declaredTarget",
        "status",
        "exitCode"
    ]

    public let id: UUID
    public let timestamp: Date
    public let source: AuditSource
    public let integration: String
    public let referenceID: String?
    public let referenceCount: Int
    public let operation: AuditOperation
    public let risk: Int
    public let authorizationOutcome: AuditAuthorizationOutcome
    public let declaredTarget: String?
    public let status: AuditStatus
    public let exitCode: Int32?

    public init(
        id: UUID = UUID(),
        timestamp: Date,
        source: AuditSource = .agent,
        integration: String,
        referenceID: String?,
        referenceCount: Int = 0,
        operation: AuditOperation,
        risk: Int,
        authorizationOutcome: AuditAuthorizationOutcome,
        declaredTarget: String?,
        status: AuditStatus,
        exitCode: Int32?
    ) {
        self.id = id
        self.timestamp = timestamp
        self.source = source
        self.integration = integration
        self.referenceID = referenceID
        self.referenceCount = max(0, referenceCount)
        self.operation = operation
        self.risk = risk
        self.authorizationOutcome = authorizationOutcome
        self.declaredTarget = declaredTarget
        self.status = status
        self.exitCode = exitCode
    }

    private enum CodingKeys: String, CodingKey {
        case id = "eventID"
        case timestamp
        case source
        case integration
        case referenceID
        case referenceCount
        case operation
        case risk
        case authorizationOutcome
        case declaredTarget
        case status
        case exitCode
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let integration = try container.decode(String.self, forKey: .integration)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.timestamp = try container.decode(Date.self, forKey: .timestamp)
        self.source = try container.decodeIfPresent(AuditSource.self, forKey: .source)
            ?? AuditSource(integration: integration)
        self.integration = integration
        self.referenceID = try container.decodeIfPresent(String.self, forKey: .referenceID)
        self.referenceCount = max(
            0,
            try container.decodeIfPresent(Int.self, forKey: .referenceCount)
                ?? (self.referenceID == nil ? 0 : 1)
        )
        self.operation = try container.decode(AuditOperation.self, forKey: .operation)
        self.risk = try container.decode(Int.self, forKey: .risk)
        self.authorizationOutcome = try container.decode(AuditAuthorizationOutcome.self, forKey: .authorizationOutcome)
        self.declaredTarget = try container.decodeIfPresent(String.self, forKey: .declaredTarget)
        self.status = try container.decode(AuditStatus.self, forKey: .status)
        self.exitCode = try container.decodeIfPresent(Int32.self, forKey: .exitCode)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(source, forKey: .source)
        try container.encode(integration, forKey: .integration)
        try container.encodeIfPresent(referenceID, forKey: .referenceID)
        try container.encode(referenceCount, forKey: .referenceCount)
        try container.encode(operation, forKey: .operation)
        try container.encode(risk, forKey: .risk)
        try container.encode(authorizationOutcome, forKey: .authorizationOutcome)
        try container.encodeIfPresent(declaredTarget, forKey: .declaredTarget)
        try container.encode(status, forKey: .status)
        try container.encodeIfPresent(exitCode, forKey: .exitCode)
    }
}

public enum AuditSource: String, Codable, Equatable, Sendable {
    case app
    case agent

    public var displayName: String {
        switch self {
        case .app: return "App"
        case .agent: return "Agent"
        }
    }

    fileprivate init(integration: String) {
        self = integration.localizedCaseInsensitiveContains("app-control") ? .app : .agent
    }
}

public enum AuditOperation: String, Codable, Equatable, Sendable {
    case status
    case reveal
    case create
    case secureExecute
    case catalogMutation
    case authorization
    case credentialUse
    case formatCheck
    case formatRepair

    public var displayName: String {
        switch self {
        case .status: return "状态检查"
        case .reveal: return "本机显示"
        case .create: return "创建密文"
        case .secureExecute: return "智能体安全执行"
        case .catalogMutation: return "目录修改"
        case .authorization: return "本机授权"
        case .credentialUse: return "凭据使用"
        case .formatCheck: return "检查格式"
        case .formatRepair: return "修复格式"
        }
    }
}

public enum AuditAuthorizationOutcome: String, Codable, Equatable, Sendable {
    case approved
    case denied
    case notRequired
    case requested
    case cancelled
    case expired

    public var displayName: String {
        switch self {
        case .approved: return "已授权"
        case .denied: return "已拒绝"
        case .notRequired: return "无需授权"
        case .requested: return "待授权"
        case .cancelled: return "已取消"
        case .expired: return "已过期"
        }
    }
}

public enum AuditStatus: String, Codable, Equatable, Sendable {
    case displayedToUser
    case created
    case completed
    case quarantined
    case failure
    case requested
    case cancelled
    case expired

    public var displayName: String {
        switch self {
        case .displayedToUser: return "已显示"
        case .created: return "已创建"
        case .completed: return "已完成"
        case .quarantined: return "已隔离"
        case .failure: return "失败"
        case .requested: return "已请求"
        case .cancelled: return "已取消"
        case .expired: return "已过期"
        }
    }
}

/// The only audit shape exposed to the App UI. It intentionally omits
/// reference IDs and all decrypted values.
public struct CatalogSecurityAuditEntry: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let source: AuditSource
    public let operation: AuditOperation
    public let authorizationOutcome: AuditAuthorizationOutcome
    public let result: AuditStatus
    public let target: String
    public let referenceCount: Int

    public init(
        id: UUID,
        timestamp: Date,
        source: AuditSource,
        operation: AuditOperation,
        authorizationOutcome: AuditAuthorizationOutcome,
        result: AuditStatus,
        target: String,
        referenceCount: Int
    ) {
        self.id = id
        self.timestamp = timestamp
        self.source = source
        self.operation = operation
        self.authorizationOutcome = authorizationOutcome
        self.result = result
        self.target = target
        self.referenceCount = max(0, referenceCount)
    }
}
