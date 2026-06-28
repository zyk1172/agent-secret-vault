import AppKit
import AgentSecretVaultApp
import CryptoKit
import SwiftUI
import VaultAuthorization
import VaultCore
import VaultIPC

@main
struct AgentSecretVaultApplication: App {
    @NSApplicationDelegateAdaptor(AgentSecretVaultAppDelegate.self) private var appDelegate
    @State private var secureViewerModel = SecureViewerModel()
    @StateObject private var runtime = AgentSecretVaultRuntime()

    var body: some Scene {
        WindowGroup {
            VaultWorkbenchView(status: runtime.status)
                .task {
                    await runtime.start()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    secureViewerModel.handleFocusChanged(isFocused: false)
                    runtime.clearRevealSessions()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    runtime.clearRevealSessions()
                }
        }
        .commands {
            CommandGroup(replacing: .pasteboard) {}
        }
    }
}

@MainActor
private final class AgentSecretVaultRuntime: ObservableObject {
    @Published var status = WorkbenchStatus(
        locked: true,
        ipcAvailable: false,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: false
    )

    private var controller: AppIPCController?
    private var started = false

    func start() async {
        guard !started else {
            return
        }
        started = true

        do {
            let runtime = try makeRuntime()
            controller = runtime.controller
            try runtime.controller.start()
            status = await runtime.services.status()
        } catch {
            status = WorkbenchStatus(
                locked: true,
                ipcAvailable: false,
                activeKnowledgeBaseRoot: nil,
                pluginConnected: false
            )
        }
    }

    func clearRevealSessions() {
        RevealSessionLifecycle.clearAll()
    }

    private func makeRuntime() throws -> (controller: AppIPCController, services: VaultAppServices) {
        let fileManager = FileManager.default
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let root = appSupport
            .appendingPathComponent("AgentSecretVault", isDirectory: true)
            .appendingPathComponent("Vault", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)

        let recordStore = FileRecordStore(baseDirectory: root)
        let deviceKeyStore = DeviceKeyStore()
        let encryptor = EncryptSelectionCoordinator(
            recordStore: recordStore,
            selectionReplacer: NoopSelectionReplacer(),
            deviceKeyStore: deviceKeyStore
        )
        let services = VaultAppServices(
            textEncryptor: encryptor,
            activeRoot: root,
            recordLister: recordStore,
            recordResolver: VaultRecordResolver(recordStore: recordStore),
            masterKeyProvider: {
                SymmetricKey(data: try await deviceKeyStore.deviceKey(reason: "Reveal paragraph"))
            },
            revealSessionStore: RevealSessionStore(defaultTTLSeconds: 60)
        )
        let server = try UnixSocketServer(configuration: .defaultConfiguration())
        let controller = AppIPCController(
            server: server,
            handler: IPCRequestHandler(service: services)
        )
        return (controller, services)
    }
}

private struct NoopSelectionReplacer: SelectionReplacing {
    func replaceSelection(with text: String) async throws {
        throw NoopSelectionReplacerError.unavailable
    }
}

private enum NoopSelectionReplacerError: Error {
    case unavailable
}

final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }
}
