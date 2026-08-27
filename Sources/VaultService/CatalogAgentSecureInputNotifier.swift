import Foundation

/// Agent-to-App notification for secure input. The distributed payload is
/// only an opaque request ID; field labels and entry titles are fetched over
/// the authenticated local IPC channel.
public struct CatalogAgentSecureInputNotifier: Sendable {
    private let activateApp: @Sendable () -> Void
    private let presentHandler: (@Sendable (UUID) -> Void)?

    public init(
        present presentHandler: ((@Sendable (UUID) -> Void))? = nil,
        activateApp: @escaping @Sendable () -> Void = Self.activateSVLTApp
    ) {
        self.activateApp = activateApp
        self.presentHandler = presentHandler
    }

    public func present(requestID: UUID) {
        if let presentHandler { presentHandler(requestID) }
        DistributedNotificationCenter.default().post(
            name: Self.notificationName,
            object: nil,
            userInfo: ["requestID": requestID.uuidString]
        )
        activateApp()
    }

    public func notifyQueueChanged(requestID: UUID) {
        DistributedNotificationCenter.default().post(
            name: Self.notificationName,
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

    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.catalog.secure-input-request"
    )
}
