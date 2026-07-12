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

@Test func runtimeOwnsLifecycleMonitorAndMenuQuitUsesTerminationCoordinator() throws {
    let source = try appSource()

    #expect(source.contains("private var lifecycleMonitor: VaultLifecycleMonitor?"))
    #expect(source.contains("lifecycleMonitor = VaultLifecycleMonitor"))
    #expect(source.contains("func clearRevealSessions() async"))
    #expect(source.contains("requestMenuBarTermination(cleanup: runtime.clearRevealSessions)"))
    #expect(source.contains("private let terminationCoordinator = MenuBarTerminationCoordinator"))
    #expect(source.contains("await terminationCoordinator.requestTermination(cleanup: cleanup)"))
}

@Test func menuBarProtectedDeleteRequestUsesFreshLocalAuthorization() throws {
    let source = try appSource()

    #expect(source.contains("runtime.requestPermanentDeleteAuthorization()"))
    #expect(source.contains("func requestPermanentDeleteAuthorization() async"))
    #expect(source.contains("for: .credential"))
    #expect(source.contains("请求删除本机加密记录"))
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

@Test @MainActor func menuTerminationRemainsDeniedWhileCleanupIsSuspended() async {
    let cleanup = SuspendedCleanup()
    let termination = TerminationRecorder()
    let coordinator = MenuBarTerminationCoordinator {
        termination.recordTermination()
    }

    let request = Task { @MainActor in
        await coordinator.requestTermination {
            await cleanup.run()
        }
    }

    await drainMainActorTasks(until: { cleanup.invocationCount == 1 })

    #expect(!coordinator.permitsTermination)
    #expect(termination.count == 0)

    cleanup.finish()
    await drainMainActorTasks(until: { termination.count == 1 })

    #expect(coordinator.permitsTermination)
    #expect(termination.count == 1)
    _ = request
}

@Test @MainActor func menuTerminationPermitsAndTerminatesAfterCleanupCompletes() async {
    let cleanup = SuspendedCleanup()
    let termination = TerminationRecorder()
    let coordinator = MenuBarTerminationCoordinator {
        termination.recordTermination()
    }

    let request = Task { @MainActor in
        await coordinator.requestTermination {
            await cleanup.run()
        }
    }

    await drainMainActorTasks(until: { cleanup.invocationCount == 1 })
    cleanup.finish()
    await drainMainActorTasks(until: { termination.count == 1 })

    #expect(coordinator.permitsTermination)
    #expect(cleanup.invocationCount == 1)
    #expect(termination.count == 1)
    _ = request
}

@Test @MainActor func duplicateMenuTerminationRequestsCleanUpAndTerminateOnce() async {
    let cleanup = SuspendedCleanup()
    let termination = TerminationRecorder()
    let coordinator = MenuBarTerminationCoordinator {
        termination.recordTermination()
    }

    let firstRequest = Task { @MainActor in
        await coordinator.requestTermination {
            await cleanup.run()
        }
    }

    await drainMainActorTasks(until: { cleanup.invocationCount == 1 })

    let duplicateRequest = Task { @MainActor in
        await coordinator.requestTermination {
            await cleanup.run()
        }
    }
    await drainMainActorTasks(until: { cleanup.invocationCount == 1 })

    #expect(cleanup.invocationCount == 1)
    #expect(termination.count == 0)

    cleanup.finish()
    await drainMainActorTasks(until: { termination.count == 1 })

    #expect(cleanup.invocationCount == 1)
    #expect(termination.count == 1)
    _ = firstRequest
    _ = duplicateRequest
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

@MainActor
private final class SuspendedCleanup {
    private var finishContinuation: CheckedContinuation<Void, Never>?
    private(set) var invocationCount = 0

    func run() async {
        invocationCount += 1
        await withCheckedContinuation { continuation in
            finishContinuation = continuation
        }
    }

    func finish() {
        finishContinuation?.resume()
        finishContinuation = nil
    }
}

@MainActor
private final class TerminationRecorder {
    private(set) var count = 0

    func recordTermination() {
        count += 1
    }
}
