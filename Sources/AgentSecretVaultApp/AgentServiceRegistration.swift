import Foundation
import ServiceManagement

public enum AgentServiceStatus: String, Equatable, Sendable {
    case registered
    case running
    case requiresApproval
    case notRegistered
    case unavailable

    public var displayName: String {
        switch self {
        case .registered:
            return "已注册"
        case .running:
            return "运行中"
        case .requiresApproval:
            return "需要用户批准"
        case .notRegistered:
            return "未注册"
        case .unavailable:
            return "异常"
        }
    }
}

/// UI-only control plane for the launchd-managed Agent. It never starts a
/// second in-process server and it never stops the Agent when the App exits.
@MainActor
public final class AgentServiceRegistration {
    public static let shared = AgentServiceRegistration()
    public static let plistName = "com.agent-secret-vault.SVLT.agent.plist"

    private let service: SMAppService
    private let defaults: UserDefaults
    private let disabledKey = "agentServiceExplicitlyDisabled"

    public init(
        service: SMAppService? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.service = service ?? SMAppService.agent(plistName: Self.plistName)
        self.defaults = defaults
    }

    public var status: AgentServiceStatus {
        switch service.status {
        case .enabled:
            return .registered
        case .requiresApproval:
            return .requiresApproval
        case .notRegistered:
            return .notRegistered
        case .notFound:
            return .unavailable
        @unknown default:
            return .unavailable
        }
    }

    public func register() throws {
        try service.register()
        defaults.set(false, forKey: disabledKey)
    }

    public func unregister() throws {
        try service.unregister()
        defaults.set(true, forKey: disabledKey)
    }

    public func restart() throws {
        try service.unregister()
        try register()
    }

    /// First launch is the only implicit registration point. A user who
    /// explicitly unregisters the service is not trapped in an auto-register
    /// loop; settings can call `register()` again.
    public func registerIfNeeded() throws {
        guard !defaults.bool(forKey: disabledKey), service.status == .notRegistered else {
            return
        }
        try register()
    }
}
