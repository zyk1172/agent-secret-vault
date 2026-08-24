import Foundation
import ServiceManagement

public enum AgentServiceStatus: String, Equatable, Sendable {
    case registered
    case running
    case requiresApproval
    case notRegistered
    case disabled
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
        case .disabled:
            return "已停用"
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
    private let registeredVersionKey = "agentServiceRegisteredBundleVersion"
    private let registeredAgentFingerprintKey = "agentServiceRegisteredAgentFingerprint"

    public init(
        service: SMAppService? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.service = service ?? SMAppService.agent(plistName: Self.plistName)
        self.defaults = defaults
    }

    public var status: AgentServiceStatus {
        if isExplicitlyDisabled {
            return .disabled
        }
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

    public var isExplicitlyDisabled: Bool {
        defaults.bool(forKey: disabledKey)
    }

    public func register() throws {
        try service.register()
        defaults.set(false, forKey: disabledKey)
        defaults.set(Self.currentBundleVersion, forKey: registeredVersionKey)
        defaults.set(Self.currentAgentFingerprint, forKey: registeredAgentFingerprintKey)
    }

    public func unregister() throws {
        try service.unregister()
        defaults.set(true, forKey: disabledKey)
    }

    /// Waits until ServiceManagement has finished unregistering the job.
    /// The synchronous API can return while launchd is still reaping the
    /// previous Agent process, which makes an immediate status read stale.
    public func unregisterAndWait() async throws {
        try await unregisterAndWaitForLaunchd()
        defaults.set(true, forKey: disabledKey)
    }

    public func restart() async throws {
        if isExplicitlyDisabled {
            try register()
            return
        }
        try await unregisterAndWaitForLaunchd()
        try register()
    }

    /// First launch is the only implicit registration point. A user who
    /// explicitly unregisters the service is not trapped in an auto-register
    /// loop; settings can call `register()` again.
    public func registerIfNeeded() async throws {
        guard !isExplicitlyDisabled else {
            return
        }

        switch service.status {
        case .notRegistered:
            try register()
        case .enabled:
            let versionChanged = defaults.string(forKey: registeredVersionKey) != Self.currentBundleVersion
            let agentChanged = defaults.string(forKey: registeredAgentFingerprintKey) != Self.currentAgentFingerprint
            guard versionChanged || agentChanged else {
                return
            }
            // SMAppService keeps the old submitted executable alive across an
            // App copy/update. Re-register when either the release identity or
            // the embedded executable changes so same-version test installs
            // also run the binary that is currently inside this App bundle.
            try await unregisterAndWaitForLaunchd()
            try register()
        case .requiresApproval:
            return
        case .notFound:
            // A manual service removal or a stale launchd registration can
            // leave the embedded plist present while SMAppService reports
            // notFound. Re-submit the in-bundle service so the App can
            // recover without requiring the user to reinstall.
            try register()
        @unknown default:
            return
        }
    }

    /// The synchronous SMAppService unregister API returns before launchd has
    /// reaped a running helper. Re-registering in that window can leave the
    /// managed job pointing at the old bundle-relative executable. Await the
    /// completion callback before installing a changed Agent.
    private func unregisterAndWaitForLaunchd() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            service.unregister { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private static var currentBundleVersion: String {
        let shortVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String ?? "unknown"
        let buildVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String ?? "unknown"
        return "\(shortVersion) (\(buildVersion))"
    }

    private static var currentAgentFingerprint: String {
        let agentURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent("SVLTAgent", isDirectory: false)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: agentURL.path),
              let fileSize = attributes[.size] as? NSNumber,
              let modificationDate = attributes[.modificationDate] as? Date
        else {
            return "unavailable"
        }
        return "\(fileSize.uint64Value):\(modificationDate.timeIntervalSince1970)"
    }
}
