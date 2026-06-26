import AppKit
import AgentSecretVaultApp
import SwiftUI

@main
struct AgentSecretVaultApplication: App {
    @NSApplicationDelegateAdaptor(AgentSecretVaultAppDelegate.self) private var appDelegate
    @State private var secureViewerModel = SecureViewerModel()

    var body: some Scene {
        WindowGroup {
            SecureViewerView(model: secureViewerModel)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    secureViewerModel.handleFocusChanged(isFocused: false)
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                }
        }
        .commands {
            CommandGroup(replacing: .pasteboard) {}
        }
    }
}

final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }
}
