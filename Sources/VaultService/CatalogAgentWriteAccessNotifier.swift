import Foundation
import VaultCore

/// Agent-to-App notification for bounded write-access grants. The payload is
/// a fixed enum request; free-form agent text is deliberately absent.
public struct CatalogAgentWriteAccessNotifier: Sendable {
    private let activateApp: @Sendable () -> Void
    private let presentHandler: (@Sendable (CatalogAgentWriteAccessRequest) -> Void)?

    public init(
        present presentHandler: ((@Sendable (CatalogAgentWriteAccessRequest) -> Void))? = nil,
        activateApp: @escaping @Sendable () -> Void = Self.activateSVLTApp
    ) {
        self.activateApp = activateApp
        self.presentHandler = presentHandler
    }

    public func present(_ request: CatalogAgentWriteAccessRequest) {
        if let presentHandler { presentHandler(request) }
        DistributedNotificationCenter.default().post(
            name: CatalogAgentWriteAccessRequest.notificationName,
            object: nil,
            userInfo: ["requestID": request.id.uuidString]
        )
        activateApp()
    }

    /// Notifies an already-running App that the authoritative pending queue
    /// changed. Unlike `present`, this does not activate or launch the App;
    /// it is used for expiry/cancellation cleanup.
    public func notifyQueueChanged(requestID: UUID) {
        DistributedNotificationCenter.default().post(
            name: CatalogAgentWriteAccessRequest.notificationName,
            object: nil,
            userInfo: ["requestID": requestID.uuidString]
        )
    }

    public static func activateSVLTApp() {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/open")
        process.arguments = ["-b", "com.agent-secret-vault.SVLT"]
        try? process.run()
    }
}
