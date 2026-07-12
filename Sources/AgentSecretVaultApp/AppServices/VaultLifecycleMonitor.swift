import AppKit
import Foundation

@MainActor
public final class VaultLifecycleMonitor {
    public typealias ClearAction = @MainActor @Sendable () async -> Void

    private let applicationNotificationCenter: NotificationCenter
    private let workspaceNotificationCenter: NotificationCenter
    private let clearAction: ClearAction
    private var observerTokens: [NSObjectProtocol] = []

    public init(
        applicationNotificationCenter: NotificationCenter = .default,
        workspaceNotificationCenter: NotificationCenter = NSWorkspace.shared.notificationCenter,
        clearAction: @escaping ClearAction
    ) {
        self.applicationNotificationCenter = applicationNotificationCenter
        self.workspaceNotificationCenter = workspaceNotificationCenter
        self.clearAction = clearAction
    }

    public func start() {
        guard observerTokens.isEmpty else {
            return
        }

        observe(NSApplication.didResignActiveNotification, on: applicationNotificationCenter)
        observe(NSWorkspace.screensDidSleepNotification, on: workspaceNotificationCenter)
        observe(NSWorkspace.willSleepNotification, on: workspaceNotificationCenter)
        observe(NSWorkspace.sessionDidResignActiveNotification, on: workspaceNotificationCenter)
        observe(NSApplication.willTerminateNotification, on: applicationNotificationCenter)
    }

    private func observe(_ name: Notification.Name, on center: NotificationCenter) {
        let clearAction = clearAction
        observerTokens.append(
            center.addObserver(forName: name, object: nil, queue: .main) { _ in
                Task { @MainActor in
                    await clearAction()
                }
            }
        )
    }
}
