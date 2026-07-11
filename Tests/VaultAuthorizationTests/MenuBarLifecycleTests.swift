import Foundation
import Testing

@Test func appSceneProvidesWindowStyleMenuBarExtra() throws {
    let source = try appSource()

    #expect(source.contains("MenuBarExtra("))
    #expect(source.contains(".menuBarExtraStyle(.window)"))
    #expect(source.contains("WindowGroup(id: MenuBarPresentation.mainWindowID)"))
    #expect(source.contains("MenuBarVaultPanel("))
    #expect(source.contains("clearRevealSessions: { runtime.clearRevealSessions() }"))
    #expect(source.contains("requestTermination: { appDelegate.requestMenuBarTermination() }"))
}

@Test func appDelegateKeepsProcessAliveUntilMenuBarQuit() throws {
    let source = try appSource()

    #expect(source.contains("applicationShouldTerminateAfterLastWindowClosed"))
    #expect(source.contains("requestMenuBarTermination"))
    #expect(source.contains("applicationShouldTerminate"))
    #expect(source.contains("permitsTermination ? .terminateNow : .terminateCancel"))
    #expect(source.contains("CommandGroup(replacing: .appTermination) {}"))
}

private func appSource() throws -> String {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}
