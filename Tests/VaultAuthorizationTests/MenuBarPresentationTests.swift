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
            let text = try await controlledRestore.restore()
            return RestoredParagraph(text: text, values: [text])
        }
    }

    await controlledRestore.waitForStart()
    state.clearSensitiveOutput()
    await controlledRestore.resume(returning: "plaintext paragraph")
    await restoreTask.value

    #expect(state.restoredText.isEmpty)
    #expect(state.errorText == nil)
}

@Test @MainActor func compactRestoreStateDoesNotSurfaceLateNoSecretReferencesAfterSensitiveOutputIsCleared() async {
    await assertLateRestoreErrorAfterSensitiveOutputIsCleared(
        ParagraphRestoreBuilderError.noSecretReferences
    )
}

@Test @MainActor func compactRestoreStateDoesNotSurfaceLateInvalidReferenceAfterSensitiveOutputIsCleared() async {
    await assertLateRestoreErrorAfterSensitiveOutputIsCleared(
        ParagraphRestoreBuilderError.invalidReference
    )
}

@Test @MainActor func compactRestoreStateDoesNotSurfaceLateGenericErrorAfterSensitiveOutputIsCleared() async {
    await assertLateRestoreErrorAfterSensitiveOutputIsCleared(TestRestoreError.generic)
}

@MainActor
private func assertLateRestoreErrorAfterSensitiveOutputIsCleared(_ error: Error) async {
    let state = MenuBarParagraphRestoreState()
    let controlledRestore = ControlledRestore()
    state.inputText = "secret://example"

    let restoreTask = Task { @MainActor in
        await state.restore { _ in
            let text = try await controlledRestore.restore()
            return RestoredParagraph(text: text, values: [text])
        }
    }

    await controlledRestore.waitForStart()
    state.clearSensitiveOutput()
    await controlledRestore.resume(throwing: error)
    await restoreTask.value

    #expect(state.restoredText.isEmpty)
    #expect(state.errorText == nil)
}

private enum TestRestoreError: Error {
    case generic
}

private actor ControlledRestore {
    private var hasStarted = false
    private var startContinuation: CheckedContinuation<Void, Never>?
    private var resultContinuation: CheckedContinuation<String, Error>?

    func restore() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
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

    func resume(throwing error: Error) {
        resultContinuation?.resume(throwing: error)
        resultContinuation = nil
    }
}
