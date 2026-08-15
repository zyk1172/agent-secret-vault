import AppKit
import Foundation

@MainActor
public final class VaultLifecycleMonitor {
    public typealias ClearAction = @MainActor @Sendable () async -> Void

    private let applicationNotificationCenter: NotificationCenter
    private let workspaceNotificationCenter: NotificationCenter
    private let clearAction: ClearAction
    private let lockAction: ClearAction?
    private var observerTokens: [NSObjectProtocol] = []

    public init(
        applicationNotificationCenter: NotificationCenter = .default,
        workspaceNotificationCenter: NotificationCenter = NSWorkspace.shared.notificationCenter,
        clearAction: @escaping ClearAction,
        lockAction: ClearAction? = nil
    ) {
        self.applicationNotificationCenter = applicationNotificationCenter
        self.workspaceNotificationCenter = workspaceNotificationCenter
        self.clearAction = clearAction
        self.lockAction = lockAction
    }

    public func start() {
        guard observerTokens.isEmpty else {
            return
        }

        observe(NSApplication.didResignActiveNotification, on: applicationNotificationCenter, action: clearAction)
        observe(NSWorkspace.screensDidSleepNotification, on: workspaceNotificationCenter, action: lockAction ?? clearAction)
        observe(NSWorkspace.willSleepNotification, on: workspaceNotificationCenter, action: lockAction ?? clearAction)
        observe(NSWorkspace.sessionDidResignActiveNotification, on: workspaceNotificationCenter, action: lockAction ?? clearAction)
        observe(NSApplication.willTerminateNotification, on: applicationNotificationCenter, action: lockAction ?? clearAction)
    }

    public func stop() {
        for token in observerTokens {
            applicationNotificationCenter.removeObserver(token)
            workspaceNotificationCenter.removeObserver(token)
        }
        observerTokens.removeAll()
    }

    private func observe(
        _ name: Notification.Name,
        on center: NotificationCenter,
        action: @escaping ClearAction
    ) {
        observerTokens.append(
            center.addObserver(forName: name, object: nil, queue: .main) { _ in
                Task { @MainActor in
                    await action()
                }
            }
        )
    }
}
