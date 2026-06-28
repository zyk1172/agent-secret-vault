import AppKit
import SwiftUI

public final class RevealSessionPresenter: RevealSessionPresenting, @unchecked Sendable {
    public init() {}

    public func present(sessionID: String, store: RevealSessionStore) async {
        guard let paragraph = await store.paragraph(id: sessionID) else {
            return
        }

        await MainActor.run {
            RevealSessionWindowRegistry.shared.present(
                sessionID: sessionID,
                paragraph: paragraph,
                store: store
            )
        }
    }
}

@MainActor
private final class RevealSessionWindowRegistry {
    static let shared = RevealSessionWindowRegistry()

    private var controllers: [String: RevealSessionWindowController] = [:]

    func present(sessionID: String, paragraph: String, store: RevealSessionStore) {
        if let existing = controllers[sessionID] {
            existing.show()
            return
        }

        var closeAction: (() -> Void)?
        let view = RevealSessionWindow(resolvedParagraph: paragraph) {
            closeAction?()
        }
        let hostingController = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hostingController)
        let controller = RevealSessionWindowController(
            sessionID: sessionID,
            store: store,
            window: window
        ) { [weak self] closedSessionID in
            self?.controllers[closedSessionID] = nil
        }
        closeAction = { [weak controller] in
            controller?.close()
        }

        controllers[sessionID] = controller
        controller.show()
    }
}

@MainActor
private final class RevealSessionWindowController: NSObject, NSWindowDelegate {
    private let sessionID: String
    private let store: RevealSessionStore
    private let onClosed: (String) -> Void
    private let window: NSWindow
    private var didClear = false

    init(
        sessionID: String,
        store: RevealSessionStore,
        window: NSWindow,
        onClosed: @escaping (String) -> Void
    ) {
        self.sessionID = sessionID
        self.store = store
        self.window = window
        self.onClosed = onClosed
        super.init()

        window.title = "Agent Secret Vault Reveal"
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.isReleasedWhenClosed = false
        window.delegate = self
    }

    func show() {
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        window.close()
    }

    nonisolated func windowWillClose(_ notification: Notification) {
        Task { @MainActor in
            clearSessionIfNeeded()
            onClosed(sessionID)
        }
    }

    private func clearSessionIfNeeded() {
        guard !didClear else {
            return
        }
        didClear = true
        Task {
            await store.clear(id: sessionID)
        }
    }
}
