import Foundation

/// Cross-process notification for a newly persisted audit event. The
/// notification carries no event data; the App re-reads the bounded,
/// encrypted recent window through AppControl.
public enum CatalogSecurityAuditNotifier {
    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.security-audit-appended"
    )

    public static func notify() {
        DistributedNotificationCenter.default().post(
            name: notificationName,
            object: nil
        )
    }
}
