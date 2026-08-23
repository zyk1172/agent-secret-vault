import Foundation

/// Agent-to-App UI bridge. Only a session identifier is broadcast; the
/// plaintext remains in the Agent session store and is fetched by the native
/// App's explicit UI client request. The Agent never imports AppKit/SwiftUI or
/// creates a window.
public struct AgentUIRequestNotifier: RevealSessionPresenting, Sendable {
    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.ui.reveal-request"
    )

    private let activateApp: @Sendable () -> Void

    public init(activateApp: @escaping @Sendable () -> Void = Self.activateSVLTApp) {
        self.activateApp = activateApp
    }

    public func present(sessionID: String, store: RevealSessionStore) async {
        DistributedNotificationCenter.default().post(
            name: Self.notificationName,
            object: nil,
            userInfo: ["sessionID": sessionID]
        )
        activateApp()
    }

    public static func activateSVLTApp() {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/open")
        process.arguments = ["-b", "com.agent-secret-vault.SVLT"]
        try? process.run()
    }
}
