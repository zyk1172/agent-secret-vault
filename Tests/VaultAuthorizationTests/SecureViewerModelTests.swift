import Foundation
import Testing
@testable import AgentSecretVaultApp

@MainActor
@Test func focusLossClearsPlaintext() {
    let model = SecureViewerModel()
    model.show(plaintext: Data("temporary secret".utf8))

    #expect(model.displayText == "temporary secret")

    model.handleFocusChanged(isFocused: false)

    #expect(model.displayText == nil)
}

@MainActor
@Test func lockNotificationClearsPlaintext() {
    let model = SecureViewerModel()
    model.show(plaintext: Data("temporary secret".utf8))

    model.handleLockNotification()

    #expect(model.displayText == nil)
}

@MainActor
@Test func sleepNotificationClearsPlaintext() {
    let model = SecureViewerModel()
    model.show(plaintext: Data("temporary secret".utf8))

    model.handleSleepNotification()

    #expect(model.displayText == nil)
}

@MainActor
@Test func sessionExpiryClearsPlaintext() {
    let clock = TestClock(now: Date(timeIntervalSinceReferenceDate: 5_000))
    let model = SecureViewerModel(now: { clock.now })
    model.show(plaintext: Data("temporary secret".utf8), sessionTTL: 60)

    clock.now = Date(timeIntervalSinceReferenceDate: 5_059.999)
    model.expireSessionIfNeeded()
    #expect(model.displayText == "temporary secret")

    clock.now = Date(timeIntervalSinceReferenceDate: 5_060)
    model.expireSessionIfNeeded()
    #expect(model.displayText == nil)
}

@MainActor
@Test func explicitCloseClearsPlaintext() {
    let model = SecureViewerModel()
    model.show(plaintext: Data("temporary secret".utf8))

    model.close()

    #expect(model.displayText == nil)
}

@MainActor
@Test func clipboardClearOnlyClearsAppOwnedCopy() {
    let clipboard = FakeClipboard()
    let model = SecureViewerModel(clipboard: clipboard)
    model.show(plaintext: Data("temporary secret".utf8))

    model.copyFor60SecondsAfterConfirmation()
    #expect(clipboard.string == "temporary secret")

    model.clearClipboardIfOwned()

    #expect(clipboard.string == nil)
    #expect(clipboard.clearCount == 1)
}

@MainActor
@Test func clipboardClearDoesNotEraseExternallyChangedClipboard() {
    let clipboard = FakeClipboard()
    let model = SecureViewerModel(clipboard: clipboard)
    model.show(plaintext: Data("temporary secret".utf8))

    model.copyFor60SecondsAfterConfirmation()
    clipboard.simulateExternalChange(to: "user clipboard")
    model.clearClipboardIfOwned()

    #expect(clipboard.string == "user clipboard")
    #expect(clipboard.clearCount == 0)
}

@MainActor
private final class FakeClipboard: ClipboardManaging {
    private(set) var changeCount = 0
    private(set) var clearCount = 0
    private(set) var string: String?

    func setString(_ string: String) -> Int {
        changeCount += 1
        self.string = string
        return changeCount
    }

    func clear() {
        changeCount += 1
        clearCount += 1
        string = nil
    }

    func simulateExternalChange(to string: String) {
        changeCount += 1
        self.string = string
    }
}

@MainActor
private final class TestClock {
    var now: Date

    init(now: Date) {
        self.now = now
    }
}
