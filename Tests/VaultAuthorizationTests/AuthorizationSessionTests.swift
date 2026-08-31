import Foundation
import Testing
@testable import VaultAuthorization

private let testExecutionScope = ExecutionAuthorizationScope(
    principal: "agent",
    secretReferenceIDs: ["secret://0123456789ABCDEFGHJKMNPQRS"],
    normalizedDestination: "qnap.local",
    port: 22,
    protocolType: "ssh",
    actionFamily: "sshCommand",
    generation: 7
)

@Test func readAuthorizationExpiresAtConfiguredTTL() async {
    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let session = AuthorizationSession(readTTL: 300, now: { clock.now })

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

@Test func executionAuthorizationUsesAnAbsoluteTTL() async {
    let start = Date(timeIntervalSinceReferenceDate: 2_000)
    let clock = TestClock(start)
    let monotonicStart: UInt64 = 10_000_000_000
    clock.monotonicNow = monotonicStart
    let session = AuthorizationSession(
        executionTTL: 300,
        monotonicNow: { clock.monotonicNow },
        now: { clock.now }
    )

    let expiresAt = await session.authorizeExecution(for: testExecutionScope)

    #expect(expiresAt == start.addingTimeInterval(300))
    #expect(await session.executionAuthorizationExpiresAt(for: testExecutionScope) == expiresAt)

    clock.now = start.addingTimeInterval(299.999)
    clock.monotonicNow = monotonicStart + 299_999_000_000
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
    #expect(await session.executionAuthorizationExpiresAt(for: testExecutionScope) == expiresAt)

    clock.now = start.addingTimeInterval(300)
    clock.monotonicNow = monotonicStart + 300_000_000_000
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope) == false)
    #expect(await session.executionAuthorizationExpiresAt(for: testExecutionScope) == nil)
}

@Test func executionAuthorizationCanBeDisabledWithoutChangingOtherAuthorizations() async {
    let session = AuthorizationSession(
        credentialTTL: 600,
        externalSendTTL: 60,
        executionTTL: 0
    )

    #expect(await session.authorizeExecution(for: testExecutionScope) == nil)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope) == false)

    await session.authorizeCredential()
    #expect(await session.consumeCredential())
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
    _ = await session.authorizeExecution(for: testExecutionScope)
    await session.invalidate()

    #expect(await session.consumeAuthorization(for: .read) == false)
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope) == false)
}

@Test func executionAuthorizationDoesNotCrossScopes() async {
    let session = AuthorizationSession(executionTTL: 300)
    let otherScope = ExecutionAuthorizationScope(
        principal: "agent",
        secretReferenceIDs: ["secret://0123456789ABCDEFGHJKMNPQRT"],
        normalizedDestination: "other.local",
        port: 22,
        protocolType: "ssh",
        actionFamily: "sshCommand",
        generation: 7
    )

    _ = await session.authorizeExecution(for: testExecutionScope)

    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
    #expect(await session.hasActiveExecutionAuthorization(for: otherScope) == false)
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date
    private var storedMonotonicNow: UInt64 = 0

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

    var monotonicNow: UInt64 {
        get {
            lock.withLock {
                storedMonotonicNow
            }
        }
        set {
            lock.withLock {
                storedMonotonicNow = newValue
            }
        }
    }
}
