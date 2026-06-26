import Foundation

public actor AuthorizationSession {
    private let readTTL: TimeInterval
    private let now: @Sendable () -> Date
    private var readExpiresAt: Date?
    private var singleUseAuthorizations: Set<RiskClass> = []

    public init(
        readTTL: TimeInterval = 300,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.readTTL = readTTL
        self.now = now
    }

    public func authorizeRead() async {
        readExpiresAt = now().addingTimeInterval(readTTL)
    }

    public func authorizeSingleUse(for risk: RiskClass) async {
        guard risk != .read else {
            readExpiresAt = now().addingTimeInterval(readTTL)
            return
        }

        singleUseAuthorizations.insert(risk)
    }

    public func consumeAuthorization(for risk: RiskClass) async -> Bool {
        switch risk {
        case .read:
            guard let readExpiresAt, now() < readExpiresAt else {
                self.readExpiresAt = nil
                return false
            }
            return true
        case .writeOrExternalSend, .deleteOrCredentialChange:
            return singleUseAuthorizations.remove(risk) != nil
        }
    }

    public func invalidate() async {
        readExpiresAt = nil
        singleUseAuthorizations.removeAll()
    }
}
