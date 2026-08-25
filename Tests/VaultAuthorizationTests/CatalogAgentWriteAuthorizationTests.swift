import Foundation
import Testing
import VaultAuthorization
import VaultCore

@Test func catalogAgentWriteAuthorizationIsAppControlledAndScoped() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 100))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })

    #expect(await authorization.status().mode == .disabled)
    do {
        try await authorization.validateSafeWrite()
        Issue.record("expected disabled authorization")
    } catch let error as SecretCatalogAgentError {
        #expect(error == .agentWriteNotAllowed)
    }
    _ = await authorization.grant(.tenMinutes)
    #expect(await authorization.status().mode == .safe)
    try await authorization.validateSafeWrite()

    let metadataStatus = try await authorization.enable(mode: .metadata, duration: 60)
    #expect(metadataStatus.mode == .metadata)
    try await authorization.validate(requiredScope: .metadata)
    do {
        try await authorization.validate(requiredScope: .structure)
        Issue.record("expected scope denial")
    } catch let error as SecretCatalogAgentError { #expect(error == .agentWriteNotAllowed) }

    _ = try await authorization.enable(mode: .structure, duration: 60)
    try await authorization.validate(requiredScope: .metadata)
    try await authorization.validate(requiredScope: .structure)

    await authorization.revoke()
    do {
        try await authorization.validateSafeWrite()
        Issue.record("expected revoked authorization")
    } catch let error as SecretCatalogAgentError { #expect(error == .agentWriteNotAllowed) }
}

@Test func catalogAgentWriteAuthorizationExpiresAndCannotBeExtendedPastTenMinutes() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 200))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })

    await #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try await authorization.enable(mode: .structure, duration: 601)
    }

    _ = try await authorization.enable(mode: .metadata, duration: 60)
    clock.now = Date(timeIntervalSinceReferenceDate: 261)
    #expect(await authorization.status().mode == .disabled)
    do {
        try await authorization.validate(requiredScope: .metadata)
        Issue.record("expected expired authorization")
    } catch let error as SecretCatalogAgentError { #expect(error == .agentWriteNotAllowed) }

    _ = try await authorization.enable(mode: .metadata, duration: 60)
    await authorization.revoke()
    #expect(await authorization.status().mode == .disabled)
}

@Test func catalogAgentWriteGrantIsBoundedRevocableAndSingleUse() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 300))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })

    _ = await authorization.grant(.singleUse)
    #expect(await authorization.status().remainingUses == 1)
    try await authorization.validateSafeWrite()
    #expect(await authorization.status().mode == .disabled)

    _ = await authorization.grant(.tenMinutes)
    clock.now = Date(timeIntervalSinceReferenceDate: 901)
    do {
        try await authorization.validateSafeWrite()
        Issue.record("expected expired safe-write authorization")
    } catch let error as SecretCatalogAgentError {
        #expect(error == .agentWriteNotAllowed)
    }

    _ = await authorization.grant(.thirtyMinutes)
    await authorization.revoke()
    #expect(await authorization.status().mode == .disabled)
}

private final class TestCatalogAuthorizationClock: @unchecked Sendable {
    var now: Date

    init(_ now: Date) {
        self.now = now
    }
}
