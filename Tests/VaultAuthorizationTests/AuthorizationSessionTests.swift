import Foundation
import Testing
@testable import VaultAuthorization

@Test func readAuthorizationExpiresAtConfiguredTTL() async {
    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let session = AuthorizationSession(readTTL: 300) { clock.now }

    await session.authorizeRead()

    #expect(await session.consumeAuthorization(for: .read))

    clock.now = Date(timeIntervalSinceReferenceDate: 1_299.999)
    #expect(await session.consumeAuthorization(for: .read))

    clock.now = Date(timeIntervalSinceReferenceDate: 1_300)
    #expect(await session.consumeAuthorization(for: .read) == false)
}

@Test func externalSendAuthorizationIsSingleUse() async {
    let session = AuthorizationSession()

    await session.authorizeSingleUse(for: .writeOrExternalSend)

    #expect(await session.consumeAuthorization(for: .writeOrExternalSend))
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
}

@Test func deleteAuthorizationIsSingleUse() async {
    let session = AuthorizationSession()

    await session.authorizeSingleUse(for: .deleteOrCredentialChange)

    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange))
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

@Test func readAuthorizationCannotAuthorizeHigherRiskClass() async {
    let session = AuthorizationSession()

    await session.authorizeRead()

    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

@Test func invalidateClearsAuthorizations() async {
    let session = AuthorizationSession()

    await session.authorizeRead()
    await session.authorizeSingleUse(for: .writeOrExternalSend)
    await session.invalidate()

    #expect(await session.consumeAuthorization(for: .read) == false)
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date

    init(_ now: Date) {
        self.storedNow = now
    }

    var now: Date {
        get {
            lock.withLock {
                storedNow
            }
        }
        set {
            lock.withLock {
                storedNow = newValue
            }
        }
    }
}
