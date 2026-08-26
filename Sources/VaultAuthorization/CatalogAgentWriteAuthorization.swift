import Foundation
import VaultCore

/// Server-side, one-shot authorization for one exact Agent Catalog mutation.
/// There is deliberately no global safe-write lease: an approved ticket is
/// keyed by its request UUID, expires quickly, and is consumed only when the
/// same operation binding is submitted.
public actor CatalogAgentWriteAuthorization {
    public static let ticketLifetime: TimeInterval = 60

    private struct ApprovedTicket: Sendable {
        let requestID: UUID
        let intent: CatalogAgentWriteIntent
        let expiresAt: Date
    }

    private let now: @Sendable () -> Date
    private var approvedTickets: [UUID: ApprovedTicket] = [:]

    public init(now: @escaping @Sendable () -> Date = Date.init) {
        self.now = now
    }

    /// Legacy AppControl setter. It remains callable for wire compatibility,
    /// but no non-disabled mode can create authority anymore.
    @available(*, deprecated, message: "Use an operation-bound App approval")
    @discardableResult
    public func enable(
        mode: CatalogAgentWriteMode,
        duration _: TimeInterval = CatalogAgentWriteAuthorization.ticketLifetime
    ) throws -> CatalogAgentWriteAuthorizationStatus {
        guard mode == .disabled else {
            throw SecretCatalogAgentError.agentWriteNotAllowed
        }
        revoke()
        return status()
    }

    /// Legacy grant API. It is intentionally a no-op that returns a disabled
    /// status, so an old caller cannot silently recreate a generic lease.
    @available(*, deprecated, message: "Use approve(requestID:intent:)")
    public func grant(_: CatalogAgentWriteAccessDuration) -> CatalogAgentWriteAuthorizationStatus {
        revoke()
        return status()
    }

    @discardableResult
    public func approve(
        requestID: UUID,
        intent: CatalogAgentWriteIntent,
        lifetime: TimeInterval = CatalogAgentWriteAuthorization.ticketLifetime
    ) -> CatalogAgentWriteAuthorizationStatus {
        purgeExpired()
        let boundedIntent = intent.bound(to: requestID)
        approvedTickets[requestID] = ApprovedTicket(
            requestID: requestID,
            intent: boundedIntent,
            expiresAt: now().addingTimeInterval(min(max(lifetime, 1), Self.ticketLifetime))
        )
        return status()
    }

    /// Consumes the ticket exactly once. The candidate binding is compared
    /// before removal; a revision, target, operation, or semantic digest
    /// change therefore cannot reuse the user's previous approval.
    public func consume(
        requestID: UUID,
        intent: CatalogAgentWriteIntent
    ) throws {
        purgeExpired()
        guard let ticket = approvedTickets[requestID],
              ticket.requestID == requestID,
              ticket.intent.matches(intent)
        else {
            throw SecretCatalogAgentError.agentWriteNotAllowed
        }
        approvedTickets.removeValue(forKey: requestID)
    }

    public func revoke() {
        approvedTickets.removeAll(keepingCapacity: false)
    }

    public func revoke(requestID: UUID) {
        approvedTickets.removeValue(forKey: requestID)
    }

    public func status() -> CatalogAgentWriteAuthorizationStatus {
        purgeExpired()
        guard let ticket = approvedTickets.values.min(by: { $0.expiresAt < $1.expiresAt }) else {
            return CatalogAgentWriteAuthorizationStatus(mode: .disabled)
        }
        return CatalogAgentWriteAuthorizationStatus(
            mode: .safe,
            expiresAt: ticket.expiresAt,
            remainingUses: 1
        )
    }

    /// Kept only so old call sites fail closed rather than gaining a generic
    /// mode. New code must consume an operation-bound ticket.
    @available(*, deprecated, message: "Use consume(requestID:intent:)")
    public func validateSafeWrite() throws {
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    /// Legacy scope validation is deliberately fail-closed. Keeping this
    /// symbol avoids turning an old IPC client into a source of implicit
    /// authority while it migrates to an operation-bound ticket.
    @available(*, deprecated, message: "Use consume(requestID:intent:)")
    public func validate(requiredScope _: CatalogAgentWriteScope) throws {
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    private func purgeExpired() {
        let current = now()
        approvedTickets = approvedTickets.filter { $0.value.expiresAt > current }
    }
}
