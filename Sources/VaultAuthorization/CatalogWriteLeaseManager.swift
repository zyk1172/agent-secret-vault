import Foundation
import VaultCore

/// App-owned lease registry.  A caller can submit a lease to the Agent, but
/// only the App-control path is given access to `issue` and `revoke`.
public actor CatalogWriteLeaseManager {
    private var activeLeases: [String: CatalogWriteLease] = [:]
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = Date.init) {
        self.now = now
    }

    public func issue(
        scope: CatalogWriteScope,
        duration: TimeInterval? = nil
    ) throws -> CatalogWriteLease {
        let lease = try CatalogWriteLease.generated(
            scope: scope,
            issuedAt: now(),
            duration: duration ?? CatalogWriteLease.maximumLifetime
        )
        activeLeases[lease.nonce] = lease
        return lease
    }

    public func revoke(nonce: String) {
        activeLeases.removeValue(forKey: nonce)
    }

    public func revokeAll() {
        activeLeases.removeAll()
    }

    public func validate(
        _ lease: CatalogWriteLease,
        requiredScope: CatalogWriteScope
    ) throws {
        try lease.validate(requiredScope: requiredScope, now: now())
        guard let issued = activeLeases[lease.nonce], issued == lease else {
            throw CatalogWriteLeaseError.invalidNonce
        }
    }

    public func activeLeasesCount() -> Int {
        activeLeases.count
    }
}
