import Foundation
import Testing
@testable import VaultAuthorization

@Test func defaultReadAuthorizationSurvivesTimeUntilExplicitInvalidation() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let session = AuthorizationSession(readTTL: nil, now: { clock.now })

    await session.authorizeRead()
    clock.now = Date(timeIntervalSinceReferenceDate: 10_000_000)

    #expect(await session.consumeAuthorization(for: .read))
    await session.invalidate()
    #expect(await session.consumeAuthorization(for: .read) == false)
}

@Test func credentialAuthorizationIsReusableUntilConfiguredTTL() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 2_000))
    let session = AuthorizationSession(
        credentialTTL: 300,
        now: { clock.now }
    )

    await session.authorizeCredential()
    #expect(await session.consumeCredential())
    #expect(await session.consumeCredential())

    clock.now = Date(timeIntervalSinceReferenceDate: 2_300)
    #expect(await session.consumeCredential() == false)
}

@Test func externalSendAuthorizationIsBoundToDestination() async {
    let clock = PolicyTestClock(Date(timeIntervalSinceReferenceDate: 3_000))
    let session = AuthorizationSession(
        externalSendTTL: 300,
        now: { clock.now }
    )

    await session.authorizeExternalSend(destination: "api.openai.com")
    #expect(await session.consumeExternalSend(destination: "api.openai.com"))
    #expect(await session.consumeExternalSend(destination: "github.com") == false)

    clock.now = Date(timeIntervalSinceReferenceDate: 3_301)
    #expect(await session.consumeExternalSend(destination: "api.openai.com") == false)
}

@Test func deleteAuthorizationRemainsSingleUse() async {
    let session = AuthorizationSession()
    await session.authorizeSingleUse(for: .deleteOrCredentialChange)

    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange))
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

private final class PolicyTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date

    init(_ now: Date) {
        storedNow = now
    }

    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }
}
