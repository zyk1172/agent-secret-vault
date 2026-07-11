import SwiftUI
import Testing
@testable import AgentSecretVaultApp

@Test func menuBarPresentationUsesCompactNativeDimensions() {
    #expect(MenuBarPresentation.statusItemSymbol == "lock.fill")
    #expect(MenuBarPresentation.panelSize == CGSize(width: 420, height: 600))
    #expect(MenuBarPresentation.mainWindowID == "agent-secret-vault-main")
}

@Test @MainActor func compactRestoreStateClearsOutputOnDismissal() {
    let state = MenuBarParagraphRestoreState()
    state.applyRestoredTextForTesting("temporary paragraph")
    state.clearSensitiveOutput()

    #expect(state.restoredText.isEmpty)
    #expect(state.errorText == nil)
}

@Test @MainActor func compactRestoreStateDoesNotRestoreAfterSensitiveOutputIsCleared() async {
    let state = MenuBarParagraphRestoreState()
    let controlledRestore = ControlledRestore()
    state.inputText = "secret://example"

    let restoreTask = Task { @MainActor in
        await state.restore { _ in
            await controlledRestore.restore()
        }
    }

    await controlledRestore.waitForStart()
    state.clearSensitiveOutput()
    await controlledRestore.resume(returning: "plaintext paragraph")
    await restoreTask.value

    #expect(state.restoredText.isEmpty)
    #expect(state.errorText == nil)
}

private actor ControlledRestore {
    private var hasStarted = false
    private var startContinuation: CheckedContinuation<Void, Never>?
    private var resultContinuation: CheckedContinuation<String, Never>?

    func restore() async -> String {
        await withCheckedContinuation { continuation in
            resultContinuation = continuation
            hasStarted = true
            startContinuation?.resume()
            startContinuation = nil
        }
    }

    func waitForStart() async {
        guard !hasStarted else { return }

        await withCheckedContinuation { continuation in
            startContinuation = continuation
        }
    }

    func resume(returning text: String) {
        resultContinuation?.resume(returning: text)
        resultContinuation = nil
    }
}
