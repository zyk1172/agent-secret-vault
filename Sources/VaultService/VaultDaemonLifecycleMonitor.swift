import Foundation

/// Foundation-only lifecycle bridge for the background Agent. It observes
/// system/session notifications instead of importing AppKit or running a
/// timer. Focus changes in the GUI app are deliberately not part of this
/// monitor.
public final class VaultDaemonLifecycleMonitor: @unchecked Sendable {
    public typealias LockAction = @Sendable () async -> Void

    private static let lockNotifications: [Notification.Name] = [
        Notification.Name("com.apple.screenIsLocked"),
        Notification.Name("com.apple.systemSleep"),
        Notification.Name("com.apple.sessionDidResignActive"),
        Notification.Name("com.apple.logoutInitiated"),
        Notification.Name("com.apple.userDidSwitch")
    ]

    private let notificationCenter: DistributedNotificationCenter
    private let lockAction: LockAction
    private var observerTokens: [NSObjectProtocol] = []

    public init(
        notificationCenter: DistributedNotificationCenter = .default(),
        lockAction: @escaping LockAction
    ) {
        self.notificationCenter = notificationCenter
        self.lockAction = lockAction
    }

    public func start() {
        guard observerTokens.isEmpty else {
            return
        }

        observerTokens = Self.lockNotifications.map { name in
            notificationCenter.addObserver(forName: name, object: nil, queue: nil) { [lockAction] _ in
                Task {
                    await lockAction()
                }
            }
        }
    }

    public func stop() {
        for token in observerTokens {
            notificationCenter.removeObserver(token)
        }
        observerTokens.removeAll()
    }
}
