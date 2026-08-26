import Foundation
import Testing
import VaultAuthorization
import VaultCore

private func catalogWriteIntent(
    requestID: UUID = UUID(),
    operation: CatalogAgentWriteOperation = .createEntry,
    revision: UInt64 = 1
) -> CatalogAgentWriteIntent {
    CatalogAgentWriteIntent(
        requestID: requestID,
        operation: operation,
        indexID: "0123456789ABCDEFGHJKMNPQRS",
        entryID: "0123456789ABCDEFGHJKMNPQRT",
        acceptedRevision: revision,
        candidateSemanticSHA256: String(repeating: "a", count: 64)
    )
}

@Test func catalogAgentWriteAuthorizationRequiresExactOperationBinding() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 100))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })
    let requestID = UUID()
    let intent = catalogWriteIntent(requestID: requestID)

    #expect(await authorization.status().mode == .disabled)
    do {
        try await authorization.validateSafeWrite()
        Issue.record("expected disabled authorization")
    } catch let error as SecretCatalogAgentError {
        #expect(error == .agentWriteNotAllowed)
    }

    _ = await authorization.approve(requestID: requestID, intent: intent)
    #expect(await authorization.status().mode == .safe)
    #expect(await authorization.status().remainingUses == 1)

    let wrongOperation = CatalogAgentWriteIntent(
        requestID: requestID,
        operation: .patchMetadata,
        indexID: intent.indexID,
        entryID: intent.entryID,
        acceptedRevision: intent.acceptedRevision,
        candidateSemanticSHA256: intent.candidateSemanticSHA256
    )
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.consume(requestID: requestID, intent: wrongOperation)
    }

    try await authorization.consume(requestID: requestID, intent: intent)
    #expect(await authorization.status().mode == .disabled)
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.consume(requestID: requestID, intent: intent)
    }
}

@Test func catalogAgentWriteAuthorizationExpiresAndCannotBeRecreatedByLegacySetter() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 200))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })
    let requestID = UUID()
    let intent = catalogWriteIntent(requestID: requestID)

    _ = await authorization.approve(requestID: requestID, intent: intent, lifetime: 60)
    clock.now = Date(timeIntervalSinceReferenceDate: 261)
    #expect(await authorization.status().mode == .disabled)
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.consume(requestID: requestID, intent: intent)
    }

    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        _ = try await authorization.enable(mode: .safe, duration: 60)
    }
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.validate(requiredScope: .structure)
    }
}

@Test func catalogAgentWriteGrantIsOneShotRevocableAndNeverGeneric() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 300))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })
    let requestID = UUID()
    let intent = catalogWriteIntent(requestID: requestID)

    let grantStatus = await authorization.grant(.tenMinutes)
    #expect(grantStatus.mode == .disabled)

    _ = await authorization.approve(requestID: requestID, intent: intent)
    #expect(await authorization.status().remainingUses == 1)
    try await authorization.consume(requestID: requestID, intent: intent)
    #expect(await authorization.status().mode == .disabled)

    _ = await authorization.approve(requestID: requestID, intent: intent)
    await authorization.revoke(requestID: requestID)
    #expect(await authorization.status().mode == .disabled)
}

private final class TestCatalogAuthorizationClock: @unchecked Sendable {
    var now: Date

    init(_ now: Date) {
        self.now = now
    }
}
