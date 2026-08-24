import Foundation
import VaultCore

/// Server-side authorization for Agent catalog writes.  The App-control
/// channel changes this state; the ordinary MCP/Agent channel can only ask
/// whether the current authorization permits an operation.
public actor CatalogAgentWriteAuthorization {
    public static let maximumLifetime: TimeInterval = 600

    private let now: @Sendable () -> Date
    // Safe catalog editing is opt-in at the App-control preference level, but
    // is enabled by default so ordinary directory creation does not require a
    // temporary structure lease. Dangerous mutations still go through the
    // CatalogMutationPolicyEngine and local approval.
    private var currentMode: CatalogAgentWriteMode = .safe
    private var currentExpiry: Date?

    public init(now: @escaping @Sendable () -> Date = Date.init) {
        self.now = now
    }

    @discardableResult
    public func enable(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval = 600
    ) throws -> CatalogAgentWriteAuthorizationStatus {
        guard mode != .disabled,
              mode == .safe || (duration > 0 && duration <= Self.maximumLifetime)
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let issuedAt = now()
        currentMode = mode
        currentExpiry = mode == .safe ? nil : issuedAt.addingTimeInterval(duration)
        return status()
    }

    public func revoke() {
        currentMode = .disabled
        currentExpiry = nil
    }

    public func status() -> CatalogAgentWriteAuthorizationStatus {
        let expiry = currentExpiry
        if currentMode != .disabled, let expiry, expiry <= now() {
            currentMode = .disabled
            currentExpiry = nil
            return CatalogAgentWriteAuthorizationStatus(mode: .disabled)
        }
        return CatalogAgentWriteAuthorizationStatus(mode: currentMode, expiresAt: expiry)
    }

    public func validate(requiredScope: CatalogAgentWriteScope) throws {
        let current = status()
        guard current.isActive(at: now()), current.mode.permits(requiredScope) else {
            throw SecretCatalogAgentError.agentWriteNotAllowed
        }
    }

    /// Safe mutations use this preference rather than the legacy metadata /
    /// structure lease. It remains App-controlled; the Agent has no setter.
    public func validateSafeWrite() throws {
        guard status().mode == .safe else {
            throw SecretCatalogAgentError.agentWriteNotAllowed
        }
    }
}
