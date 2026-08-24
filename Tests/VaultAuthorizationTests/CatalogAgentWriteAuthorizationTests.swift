import Foundation
import Testing
import VaultAuthorization
import VaultCore

@Test func catalogAgentWriteAuthorizationIsAppControlledAndScoped() async throws {
    let clock = TestCatalogAuthorizationClock(Date(timeIntervalSinceReferenceDate: 100))
    let authorization = CatalogAgentWriteAuthorization(now: { clock.now })

    #expect(await authorization.status().mode == .safe)
    try await authorization.validateSafeWrite()

    let metadataStatus = try await authorization.enable(mode: .metadata, duration: 60)
    #expect(metadataStatus.mode == .metadata)
    try await authorization.validate(requiredScope: .metadata)
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.validate(requiredScope: .structure)
    }

    _ = try await authorization.enable(mode: .structure, duration: 60)
    try await authorization.validate(requiredScope: .metadata)
    try await authorization.validate(requiredScope: .structure)

    await authorization.revoke()
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.validateSafeWrite()
    }
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
    await #expect(throws: SecretCatalogAgentError.agentWriteNotAllowed) {
        try await authorization.validate(requiredScope: .metadata)
    }

    _ = try await authorization.enable(mode: .metadata, duration: 60)
    await authorization.revoke()
    #expect(await authorization.status().mode == .disabled)
}

private final class TestCatalogAuthorizationClock: @unchecked Sendable {
    var now: Date

    init(_ now: Date) {
        self.now = now
    }
}
