import AppKit
import Foundation
import Observation

@MainActor
public protocol ClipboardManaging: AnyObject {
    var changeCount: Int { get }
    func setString(_ string: String) -> Int
    func clear()
}

@MainActor
public final class SystemClipboard: ClipboardManaging {
    private let pasteboard: NSPasteboard

    public init(pasteboard: NSPasteboard = .general) {
        self.pasteboard = pasteboard
    }

    public var changeCount: Int {
        pasteboard.changeCount
    }

    public func setString(_ string: String) -> Int {
        pasteboard.clearContents()
        pasteboard.setString(string, forType: .string)
        return pasteboard.changeCount
    }

    public func clear() {
        pasteboard.clearContents()
    }
}

@MainActor
@Observable
public final class SecureViewerModel {
    @ObservationIgnored private let clipboard: any ClipboardManaging
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private var plaintext: Data?
    @ObservationIgnored private var clipboardOwnedChangeCount: Int?

    private var sessionExpiresAt: Date?

    public init(
        clipboard: any ClipboardManaging = SystemClipboard(),
        now: @escaping () -> Date = Date.init
    ) {
        self.clipboard = clipboard
        self.now = now
    }

    public var displayText: String? {
        guard let plaintext else {
            return nil
        }

        return String(data: plaintext, encoding: .utf8)
    }

    public func show(plaintext: Data, sessionTTL: TimeInterval? = nil) {
        clearPlaintext()
        self.plaintext = plaintext

        if let sessionTTL {
            sessionExpiresAt = now().addingTimeInterval(sessionTTL)
        }
    }

    public func handleFocusChanged(isFocused: Bool) {
        guard !isFocused else {
            return
        }

        clearPlaintext()
    }

    public func handleLockNotification() {
        clearPlaintext()
    }

    public func handleSleepNotification() {
        clearPlaintext()
    }

    public func expireSessionIfNeeded() {
        guard let sessionExpiresAt, now() >= sessionExpiresAt else {
            return
        }

        clearPlaintext()
    }

    public func close() {
        clearPlaintext()
    }

    public func copyFor60SecondsAfterConfirmation() {
        guard let displayText else {
            return
        }

        clipboardOwnedChangeCount = clipboard.setString(displayText)
    }

    public func clearClipboardIfOwned() {
        guard let clipboardOwnedChangeCount,
              clipboard.changeCount == clipboardOwnedChangeCount
        else {
            return
        }

        clipboard.clear()
        self.clipboardOwnedChangeCount = nil
    }

    private func clearPlaintext() {
        if let count = plaintext?.count {
            plaintext?.resetBytes(in: 0..<count)
        }

        plaintext = nil
        sessionExpiresAt = nil
    }
}
