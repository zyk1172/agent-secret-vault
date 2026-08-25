import Foundation
import VaultCore

/// Server-side authorization for Agent catalog writes.  The App-control
/// channel changes this state; the ordinary MCP/Agent channel can only ask
/// whether the current authorization permits an operation.
public actor CatalogAgentWriteAuthorization {
    public static let maximumLifetime: TimeInterval = 600
    public static let maximumExtendedLifetime: TimeInterval = 1800

    private let now: @Sendable () -> Date
    private var currentMode: CatalogAgentWriteMode = .disabled
    private var currentExpiry: Date?
    private var currentRemainingUses: Int?

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
        currentExpiry = issuedAt.addingTimeInterval(duration)
        currentRemainingUses = nil
        return status()
    }

    public func grant(_ duration: CatalogAgentWriteAccessDuration) -> CatalogAgentWriteAuthorizationStatus {
        let issuedAt = now()
        currentMode = .safe
        currentExpiry = issuedAt.addingTimeInterval(duration.lifetime)
        currentRemainingUses = duration == .singleUse ? 1 : nil
        return status()
    }

    public func revoke() {
        currentMode = .disabled
        currentExpiry = nil
    }

    public func status() -> CatalogAgentWriteAuthorizationStatus {
        let expiry = currentExpiry
        if currentMode != .disabled, let expiry, expiry <= now() {
            revoke()
        }
        if currentMode == .safe, let remaining = currentRemainingUses, remaining <= 0 {
            revoke()
        }
        return CatalogAgentWriteAuthorizationStatus(
            mode: currentMode,
            expiresAt: currentMode == .disabled ? nil : expiry,
            remainingUses: currentRemainingUses
        )
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
        if let remaining = currentRemainingUses {
            currentRemainingUses = remaining - 1
        }
    }
}
