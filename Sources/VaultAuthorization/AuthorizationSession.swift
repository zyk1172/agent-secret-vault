import Foundation

/// In-memory authorization state owned by one running Agent. It is cleared by
/// the daemon on sleep, screen lock, session changes, explicit lock, and
/// process restart. No timer is required; expiry is checked on use.
public actor AuthorizationSession {
    private let readTTL: TimeInterval?
    private let credentialTTL: TimeInterval
    private let externalSendTTL: TimeInterval
    private let executionTTL: TimeInterval
    private let now: @Sendable () -> Date

    private var readAuthorized = false
    private var readExpiresAt: Date?
    private var credentialAuthorized = false
    private var credentialExpiresAt: Date?
    private var externalSendExpiresAt: [String: Date] = [:]
    private var executionExpiresAt: Date?
    private var singleUseAuthorizations: Set<RiskClass> = []

    public init(
        readTTL: TimeInterval? = nil,
        credentialTTL: TimeInterval = 600,
        externalSendTTL: TimeInterval = 60,
        executionTTL: TimeInterval = 300,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.readTTL = readTTL
        self.credentialTTL = credentialTTL
        self.externalSendTTL = externalSendTTL
        self.executionTTL = executionTTL
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
    public func authorizeExecution() -> Date? {
        guard executionTTL > 0 else {
            executionExpiresAt = nil
            return nil
        }
        let expiresAt = now().addingTimeInterval(executionTTL)
        executionExpiresAt = expiresAt
        return expiresAt
    }

    public func hasActiveExecutionAuthorization() -> Bool {
        guard let executionExpiresAt else {
            return false
        }
        guard now() < executionExpiresAt else {
            self.executionExpiresAt = nil
            return false
        }
        return true
    }

    public func executionAuthorizationExpiresAt() -> Date? {
        guard hasActiveExecutionAuthorization() else {
            return nil
        }
        return executionExpiresAt
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
        executionExpiresAt = nil
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
}
