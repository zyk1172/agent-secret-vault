import AppKit
import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func appSceneProvidesWindowStyleMenuBarExtra() throws {
    let source = try appSource()

    #expect(source.contains("MenuBarExtra("))
    #expect(source.contains(".menuBarExtraStyle(.window)"))
    #expect(source.contains("MenuBarVaultPanel("))
}

@Test func appSceneUsesSingletonMainWindow() throws {
    let source = try appSource()

    #expect(source.contains("Window(\"Agent Secret Vault\", id: MenuBarPresentation.mainWindowID)"))
    #expect(!source.contains("WindowGroup(id: MenuBarPresentation.mainWindowID)"))
}

@Test func appDelegateKeepsProcessAliveUntilMenuBarQuit() throws {
    let source = try appSource()

    #expect(source.contains("applicationShouldTerminateAfterLastWindowClosed"))
    #expect(source.contains("requestMenuBarTermination"))
    #expect(source.contains("applicationShouldTerminate"))
    #expect(source.contains("permitsTermination ? .terminateNow : .terminateCancel"))
    #expect(source.contains("CommandGroup(replacing: .appTermination) {}"))
}

@Test func runtimeOwnsLifecycleMonitorAndMenuQuitAwaitsCleanup() throws {
    let source = try appSource()

    #expect(source.contains("private var lifecycleMonitor: VaultLifecycleMonitor?"))
    #expect(source.contains("lifecycleMonitor = VaultLifecycleMonitor"))
    #expect(source.contains("func clearRevealSessions() async"))
    #expect(source.contains("requestMenuBarTermination(cleanup: runtime.clearRevealSessions)"))
    #expect(source.contains("cleanup: @escaping @MainActor () async -> Void"))
    #expect(source.contains("await cleanup()"))
}

@Test @MainActor func lifecycleMonitorHandlesEachSecurityBoundaryOnce() async {
    let applicationCenter = NotificationCenter()
    let workspaceCenter = NotificationCenter()
    let counter = LifecycleClearCounter(expectedCount: 5)
    let monitor = VaultLifecycleMonitor(
        applicationNotificationCenter: applicationCenter,
        workspaceNotificationCenter: workspaceCenter
    ) {
        await counter.increment()
    }

    monitor.start()
    monitor.start()
    applicationCenter.post(name: NSApplication.didResignActiveNotification, object: nil)
    workspaceCenter.post(name: NSWorkspace.screensDidSleepNotification, object: nil)
    workspaceCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
    workspaceCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
    applicationCenter.post(name: NSApplication.willTerminateNotification, object: nil)

    await counter.waitForExpectedCount()
    #expect(await counter.count == 5)
}

private func appSource() throws -> String {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}

private actor LifecycleClearCounter {
    private(set) var count = 0
    private let expectedCount: Int
    private var waiter: CheckedContinuation<Void, Never>?

    init(expectedCount: Int) {
        self.expectedCount = expectedCount
    }

    func increment() {
        count += 1
        if count == expectedCount {
            waiter?.resume()
            waiter = nil
        }
    }

    func waitForExpectedCount() async {
        guard count < expectedCount else {
            return
        }
        await withCheckedContinuation { continuation in
            waiter = continuation
        }
    }
}
