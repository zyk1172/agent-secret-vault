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
        WindowGroup(id: MenuBarPresentation.mainWindowID) {
            VaultWorkbenchView(
                status: runtime.status,
                orphanScanResult: runtime.orphanScanResult,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                restoreParagraph: { text in
                    try await runtime.restoreParagraph(text)
                },
                refreshSavedReferences: {
                    await runtime.refreshSavedReferences()
                }
            )
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
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    runtime.clearRevealSessions()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
                    secureViewerModel.handleLockNotification()
                    runtime.clearRevealSessions()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    runtime.clearRevealSessions()
                }
        }
            .commands {
                CommandGroup(replacing: .pasteboard) {}
                CommandGroup(replacing: .appTermination) {}
                CommandMenu("导航") {
                    Button("控制台") {
                        navigateWorkbench(to: .overview)
                    }
                    .keyboardShortcut("1", modifiers: [.command])

                    Button("段落解密") {
                        navigateWorkbench(to: .paragraph)
                    }
                    .keyboardShortcut("2", modifiers: [.command])

                    Button("密文库") {
                        navigateWorkbench(to: .secrets)
                    }
                    .keyboardShortcut("3", modifiers: [.command])

                    Button("记录维护") {
                        navigateWorkbench(to: .records)
                    }
                    .keyboardShortcut("4", modifiers: [.command])

                    Button("智能体自动化") {
                        navigateWorkbench(to: .automation)
                    }
                    .keyboardShortcut("5", modifiers: [.command])

                    Button("安全边界") {
                        navigateWorkbench(to: .security)
                    }
                    .keyboardShortcut("6", modifiers: [.command])
                }
            }

        MenuBarExtra("Agent Secret Vault", systemImage: MenuBarPresentation.statusItemSymbol) {
            MenuBarVaultPanel(
                status: runtime.status,
                orphanScanResult: runtime.orphanScanResult,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                restoreParagraph: { text in
                    try await runtime.restoreParagraph(text)
                },
                refreshSavedReferences: {
                    await runtime.refreshSavedReferences()
                },
                clearRevealSessions: { runtime.clearRevealSessions() },
                requestTermination: { appDelegate.requestMenuBarTermination() }
            )
            .task {
                await runtime.start()
            }
        }
        .menuBarExtraStyle(.window)
    }

    private func navigateWorkbench(to section: VaultWorkbenchSection) {
        NotificationCenter.default.post(
            name: .vaultWorkbenchNavigate,
            object: nil,
            userInfo: ["section": section.rawValue]
        )
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
    @Published var orphanScanResult: OrphanScanResult?
    @Published var auditEntries: [AgentAutomationAuditEntry] = []
    @Published var savedReferences: [SecretReferenceMetadata] = []

    private var controller: AppIPCController?
    private var services: VaultAppServices?
    private var started = false

    func start() async {
        guard !started else {
            return
        }
        started = true

        do {
            let runtime = try makeRuntime()
            try? await runtime.protectionKeyStore.unlockLowProtection()
            controller = runtime.controller
            services = runtime.services
            try runtime.controller.start()
            status = await runtime.services.status()
            await refreshSavedReferences()
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

    func restoreParagraph(_ text: String) async throws -> String {
        guard let services else {
            throw AgentSecretVaultRuntimeError.notStarted
        }
        let request = try ParagraphRestoreBuilder.build(from: text)
        return try await services.restoreReferences(
            references: request.references,
            context: request.context
        )
    }

    func refreshSavedReferences() async {
        guard let services else {
            savedReferences = []
            return
        }
        do {
            savedReferences = try await services.savedSecretReferences()
        } catch {
            savedReferences = []
        }
    }

    private func makeRuntime() throws -> (
        controller: AppIPCController,
        services: VaultAppServices,
        protectionKeyStore: AppProtectionKeyStore
    ) {
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
        let auditRoot = appSupport
            .appendingPathComponent("AgentSecretVault", isDirectory: true)
            .appendingPathComponent("Audit", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: auditRoot, withIntermediateDirectories: true)

        let recordStore = FileRecordStore(baseDirectory: root)
        let auditLog = EncryptedAuditLog(directoryURL: auditRoot)
        let deviceKeyStore = DeviceKeyStore()
        let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)
        let wrappedMasterKeyStore = FileWrappedMasterKeyStore(
            fileURL: root
                .appendingPathComponent(".agent-secret-vault", isDirectory: true)
                .appendingPathComponent("master-key.json")
        )
        let masterKeyCoordinator = MasterKeyCoordinator(
            deviceKeyStore: deviceKeyStore,
            wrappedStore: wrappedMasterKeyStore
        )
        let vaultMasterKeyProvider: @Sendable (SecretPolicy, String) async throws -> Data = { policy, reason in
            let localWrappingKey = try await protectionKeyStore.deviceKey(for: policy, reason: reason)
            if try await wrappedMasterKeyStore.loadWrappedMasterKeySet() == nil,
               !(try await recordStore.recordIDs()).isEmpty
            {
                return try await masterKeyCoordinator.adoptExistingVault(
                    reason: reason,
                    localWrappingKey: localWrappingKey,
                    existingMasterKey: localWrappingKey
                )
            }
            return try await masterKeyCoordinator.unlock(reason: reason, localWrappingKey: localWrappingKey)
        }
        let encryptor = EncryptSelectionCoordinator(
            recordStore: recordStore,
            selectionReplacer: NoopSelectionReplacer(),
            masterKeyProvider: vaultMasterKeyProvider
        )
        let services = VaultAppServices(
            textEncryptor: encryptor,
            activeRoot: root,
            recordLister: recordStore,
            recordResolver: VaultRecordResolver(recordStore: recordStore),
            masterKeyProvider: { policy, reason in
                SymmetricKey(data: try await vaultMasterKeyProvider(policy, reason))
            },
            isUnlockedProvider: {
                await protectionKeyStore.isLowProtectionUnlocked
            },
            revealSessionStore: RevealSessionStore(defaultTTLSeconds: 60),
            orphanScanObserver: { [weak self] result in
                await MainActor.run {
                    self?.orphanScanResult = result
                }
            },
            statusObserver: { [weak self] status in
                await MainActor.run {
                    self?.status = status
                }
            },
            auditObserver: { [weak self] entry in
                await MainActor.run {
                    self?.recordAudit(entry)
                }
            },
            savedReferencesObserver: { [weak self] references in
                await MainActor.run {
                    self?.savedReferences = references
                }
            },
            auditLog: auditLog
        )
        let server = try UnixSocketServer(configuration: .defaultConfiguration())
        let controller = AppIPCController(
            server: server,
            handler: IPCRequestHandler(service: services)
        )
        return (controller, services, protectionKeyStore)
    }

    private func recordAudit(_ entry: AgentAutomationAuditEntry) {
        auditEntries.insert(entry, at: 0)
        if auditEntries.count > 20 {
            auditEntries.removeLast(auditEntries.count - 20)
        }
    }
}

private enum AgentSecretVaultRuntimeError: Error {
    case notStarted
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
    private var permitsTermination = false

    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func requestMenuBarTermination() {
        RevealSessionLifecycle.clearAll()
        permitsTermination = true
        NSApp.terminate(nil)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        permitsTermination ? .terminateNow : .terminateCancel
    }
}
