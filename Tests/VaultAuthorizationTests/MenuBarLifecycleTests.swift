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

@Test func appSceneUsesFixedMainWindowSize() throws {
    let source = try appSource()

    #expect(source.contains(".frame(width: 1280, height: 820)"))
    #expect(source.contains(".defaultSize(width: 1280, height: 820)"))
    #expect(source.contains(".windowResizability(.contentSize)"))
    #expect(!source.contains(".windowResizability(.contentMinSize)"))
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

@Test func appTreatsResignActiveAsTransientCatalogFocusLoss() throws {
    let source = try appSource()
    guard let start = source.range(of: "NSApplication.didResignActiveNotification"),
          let end = source.range(of: "NSWorkspace.screensDidSleepNotification", range: start.upperBound..<source.endIndex)
    else {
        Issue.record("application focus-loss handler not found")
        return
    }

    let handler = source[start.lowerBound..<end.lowerBound]
    #expect(handler.contains("vaultWorkbenchTransientFocusLost"))
    #expect(handler.contains("runtime.clearRevealSessionsForTransientFocusLoss()"))
    #expect(!handler.contains("runtime.clearRevealSessions()"))
    #expect(!handler.contains("runtime.cancelAllSecureInputRequests()"))
}

@Test func transientRevealCleanupDoesNotBroadcastCatalogSecurityInvalidation() throws {
    let source = try appSource()
    guard let start = source.range(of: "func clearRevealSessionsForTransientFocusLoss() async"),
          let end = source.range(of: "    func lockVault() async", range: start.upperBound..<source.endIndex)
    else {
        Issue.record("transient reveal cleanup helper not found")
        return
    }

    let helper = source[start.lowerBound..<end.lowerBound]
    #expect(helper.contains("RevealSessionLifecycle.clearPresentedSessionsForFocusLoss()"))
    #expect(helper.contains("uiRevealSessionStore.clearAll()"))
    #expect(helper.contains("agentClient?.clearRevealSessions()"))
    #expect(!helper.contains("vaultWorkbenchSecurityStateInvalidated"))
    #expect(!helper.contains("cancelAllSecureInputRequests()"))

    // Hard security paths must continue to retain the broadcast/full cleanup.
    #expect(source.contains("name: .vaultWorkbenchSecurityStateInvalidated"))
    #expect(source.contains("RevealSessionLifecycle.clearAll()"))
}

@Test func menuBarDoesNotClearSharedRevealStateOnTransientAppFocusLoss() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)
    #expect(!source.contains("NSApplication.didResignActiveNotification"))
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

@Test func menuBarOmitsLegacyRecordMaintenanceActions() throws {
    let source = try appSource()

    #expect(!source.contains("runtime.deleteRecord(reference)"))
    #expect(!source.contains("func deleteRecord(_ reference: String) async"))
    #expect(!source.contains("requestPermanentDeleteAuthorization"))
    #expect(!source.contains("orphanScanResult"))
    #expect(!source.contains("敏感扫描"))
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
