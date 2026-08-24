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

    #expect(source.contains("Window(\"SVLT\", id: MenuBarPresentation.mainWindowID)"))
    #expect(!source.contains("WindowGroup(id: MenuBarPresentation.mainWindowID)"))
}

@Test func appDelegateKeepsProcessAliveButAllowsSystemTerminationAfterCleanup() throws {
    let source = try appSource()

    #expect(source.contains("applicationShouldTerminateAfterLastWindowClosed"))
    #expect(source.contains("requestMenuBarTermination"))
    #expect(source.contains("applicationShouldTerminate"))
    #expect(source.contains("return .terminateLater"))
    #expect(source.contains("sender.reply(toApplicationShouldTerminate: true)"))
    #expect(!source.contains("permitsTermination ? .terminateNow : .terminateCancel"))
    #expect(!source.contains("CommandGroup(replacing: .appTermination) {}"))
}

@Test func appUsesLaunchdAgentClientInsteadOfOwningVaultLifecycle() throws {
    let source = try appSource()

    #expect(source.contains("private var agentClient: VaultIPCClient?"))
    #expect(source.contains("AgentServiceRegistration.shared"))
    #expect(source.contains("try await registration.registerIfNeeded()"))
    #expect(source.contains("func clearRevealSessions() async"))
    #expect(source.contains("func shutdown() async"))
    #expect(!source.contains("unlockLowProtection"))
    #expect(!source.contains("controller.start()"))
    #expect(!source.contains("controller?.stop()"))
}

@Test func agentServiceActionsRoundTripThroughRuntimeState() throws {
    let source = try appSource()

    #expect(source.contains("agentServiceActionInFlight"))
    #expect(source.contains("func enableAgentService() async"))
    #expect(source.contains("func disableAgentService() async"))
    #expect(source.contains("func restartAgentService() async"))
    #expect(source.contains("unregisterAndWait()"))
    #expect(source.contains("reconnectAfterServiceAction()"))
    #expect(source.contains("AGENT_SERVICE_DISABLE_FAILED"))
}

@Test func disabledAgentStatusHasExplicitPresentation() {
    #expect(AgentServiceStatus.disabled.displayName == "已停用")
}

@Test func menuBarProtectedDeleteRequestDeletesTheRecord() throws {
    let source = try appSource()

    #expect(source.contains("runtime.deleteRecord(reference)"))
    #expect(source.contains("func deleteRecord(_ reference: String) async"))
    #expect(source.contains("agentClient.deleteRecord(reference)"))
    #expect(!source.contains("runtime.requestPermanentDeleteAuthorization()"))
    #expect(!source.contains("func requestPermanentDeleteAuthorization() async"))
}

@Test @MainActor func lifecycleMonitorHandlesEachSecurityBoundaryOnce() async {
    let applicationCenter = NotificationCenter()
    let workspaceCenter = NotificationCenter()
    let counter = LifecycleClearCounter()
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

    await drainMainActorTasks(until: { await counter.count == 5 })
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
    func increment() {
        count += 1
    }
}

@MainActor
private func drainMainActorTasks(until condition: () async -> Bool) async {
    for _ in 0..<100 {
        if await condition() {
            return
        }
        await Task.yield()
    }
}
