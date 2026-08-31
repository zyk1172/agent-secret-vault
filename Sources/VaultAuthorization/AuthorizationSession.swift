import Foundation
import Dispatch

/// In-memory authorization state owned by one running Agent. It is cleared by
/// the daemon on sleep, screen lock, session changes, explicit lock, and
/// process restart. No timer is required; expiry is checked on use.
public actor AuthorizationSession {
    private let readTTL: TimeInterval?
    private let credentialTTL: TimeInterval
    private let externalSendTTL: TimeInterval
    private let executionTTL: TimeInterval
    private let now: @Sendable () -> Date
    private let monotonicNow: @Sendable () -> UInt64

    private var readAuthorized = false
    private var readExpiresAt: Date?
    private var credentialAuthorized = false
    private var credentialExpiresAt: Date?
    private var externalSendExpiresAt: [String: Date] = [:]
    private struct ExecutionAuthorizationLease: Sendable {
        let monotonicDeadline: UInt64
        let expiresAt: Date
    }
    private var executionLeases: [ExecutionAuthorizationScope: ExecutionAuthorizationLease] = [:]
    private var singleUseAuthorizations: Set<RiskClass> = []

    public init(
        readTTL: TimeInterval? = nil,
        credentialTTL: TimeInterval = 600,
        externalSendTTL: TimeInterval = 60,
        executionTTL: TimeInterval = 300,
        monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.readTTL = readTTL
        self.credentialTTL = credentialTTL
        self.externalSendTTL = externalSendTTL
        self.executionTTL = executionTTL
        self.monotonicNow = monotonicNow
        self.now = now
    }

    public func authorizeRead() async {
        readAuthorized = true
        readExpiresAt = readTTL.map { now().addingTimeInterval($0) }
    }

    public func authorizeCredential() async {
        guard credentialTTL > 0 else {
            credentialAuthorized = false
            credentialExpiresAt = nil
            return
        }
        credentialAuthorized = true
        credentialExpiresAt = now().addingTimeInterval(credentialTTL)
    }

    public func authorizeExternalSend(destination: String) async {
        guard !destination.isEmpty, externalSendTTL > 0 else {
            return
        }
        externalSendExpiresAt[destination] = now().addingTimeInterval(externalSendTTL)
    }

    /// Opens a fixed, in-memory authorization window for purpose-built Agent
    /// execution. The expiry is absolute: using the window never extends it.
    @discardableResult
    public func authorizeExecution(for scope: ExecutionAuthorizationScope) -> Date? {
        guard let durationNanoseconds = executionDurationNanoseconds() else {
            executionLeases.removeValue(forKey: scope)
            return nil
        }

        let (deadline, overflow) = monotonicNow().addingReportingOverflow(durationNanoseconds)
        guard !overflow else {
            executionLeases.removeValue(forKey: scope)
            return nil
        }

        let expiresAt = now().addingTimeInterval(executionTTL)
        executionLeases[scope] = ExecutionAuthorizationLease(
            monotonicDeadline: deadline,
            expiresAt: expiresAt
        )
        return expiresAt
    }

    public func executionAuthorizationWindowEnabled() -> Bool {
        executionDurationNanoseconds() != nil
    }

    /// Returns the configured duration for the user-facing approval notice.
    /// The lease itself still uses the monotonic deadline above; this value is
    /// only descriptive and must never be used for authorization decisions.
    public func executionAuthorizationWindowDuration() -> TimeInterval? {
        guard executionAuthorizationWindowEnabled() else {
            return nil
        }
        return executionTTL
    }

    public func hasActiveExecutionAuthorization(for scope: ExecutionAuthorizationScope) -> Bool {
        guard let lease = executionLeases[scope] else {
            return false
        }
        guard monotonicNow() < lease.monotonicDeadline else {
            executionLeases.removeValue(forKey: scope)
            return false
        }
        return true
    }

    public func executionAuthorizationExpiresAt(for scope: ExecutionAuthorizationScope) -> Date? {
        guard hasActiveExecutionAuthorization(for: scope) else {
            return nil
        }
        return executionLeases[scope]?.expiresAt
    }

    public func invalidateExecutionAuthorization(for scope: ExecutionAuthorizationScope) {
        executionLeases.removeValue(forKey: scope)
    }

    public func authorizeSingleUse(for risk: RiskClass) async {
        guard risk != .read else {
            await authorizeRead()
            return
        }
        singleUseAuthorizations.insert(risk)
    }

    public func consumeAuthorization(for risk: RiskClass) async -> Bool {
        switch risk {
        case .read:
            return consumeRead()
        case .writeOrExternalSend, .deleteOrCredentialChange:
            return singleUseAuthorizations.remove(risk) != nil
        }
    }

    public func consumeCredential() async -> Bool {
        guard credentialAuthorized else {
            return false
        }
        guard let credentialExpiresAt, now() < credentialExpiresAt else {
            credentialAuthorized = false
            self.credentialExpiresAt = nil
            return false
        }
        return true
    }

    public func consumeExternalSend(destination: String) async -> Bool {
        guard !destination.isEmpty,
              let expiresAt = externalSendExpiresAt[destination]
        else {
            // Keep the old single-use API usable for callers that deliberately
            // requested a generic external-send authorization. Destination-
            // bound authorizations always use the dictionary above.
            return singleUseAuthorizations.remove(.writeOrExternalSend) != nil
        }
        guard now() < expiresAt else {
            externalSendExpiresAt[destination] = nil
            return false
        }
        return true
    }

    public func invalidate() async {
        readAuthorized = false
        readExpiresAt = nil
        credentialAuthorized = false
        credentialExpiresAt = nil
        externalSendExpiresAt.removeAll()
        executionLeases.removeAll()
        singleUseAuthorizations.removeAll()
    }

    private func consumeRead() -> Bool {
        guard readAuthorized else {
            return false
        }
        if let readExpiresAt, now() >= readExpiresAt {
            readAuthorized = false
            self.readExpiresAt = nil
            return false
        }
        return true
    }

    private func executionDurationNanoseconds() -> UInt64? {
        guard executionTTL.isFinite, executionTTL > 0 else {
            return nil
        }
        let durationNanoseconds = executionTTL * 1_000_000_000
        guard durationNanoseconds.isFinite,
              durationNanoseconds >= 1,
              durationNanoseconds < Double(UInt64.max)
        else {
            return nil
        }
        return UInt64(durationNanoseconds)
    }
}
