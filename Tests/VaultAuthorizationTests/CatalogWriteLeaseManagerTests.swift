import Foundation
import Testing
import VaultAuthorization
import VaultCore

@Test func leaseManagerRequiresIssuedNonceAndHonorsScopeAndExpiry() async throws {
    let clock = TestLeaseClock(Date(timeIntervalSinceReferenceDate: 100))
    let manager = CatalogWriteLeaseManager(now: { clock.now })
    let metadataLease = try await manager.issue(scope: .metadata, duration: 60)

    try await manager.validate(metadataLease, requiredScope: .metadata)
    let scopeError = await leaseError {
        try await manager.validate(metadataLease, requiredScope: .structure)
    }
    #expect(scopeError == .insufficientScope)

    clock.now = Date(timeIntervalSinceReferenceDate: 161)
    let expiryError = await leaseError {
        try await manager.validate(metadataLease, requiredScope: .metadata)
    }
    #expect(expiryError == .expired)

    let forged = CatalogWriteLease(
        scope: .structure,
        issuedAt: Date(timeIntervalSinceReferenceDate: 100),
        expiresAt: Date(timeIntervalSinceReferenceDate: 200),
        nonce: metadataLease.nonce
    )
    let nonceError = await leaseError {
        try await manager.validate(forged, requiredScope: .metadata)
    }
    #expect(nonceError == .invalidNonce)
}

@Test func leaseCannotExceedTenMinutes() {
    #expect(throws: CatalogWriteLeaseError.tooLong) {
        _ = try CatalogWriteLease.generated(scope: .structure, duration: 601)
    }
}

private final class TestLeaseClock: @unchecked Sendable {
    var now: Date

    init(_ now: Date) {
        self.now = now
    }
}

private func leaseError(
    _ operation: () async throws -> Void
) async -> CatalogWriteLeaseError? {
    do {
        try await operation()
        return nil
    } catch let error as CatalogWriteLeaseError {
        return error
    } catch {
        return nil
    }
}
