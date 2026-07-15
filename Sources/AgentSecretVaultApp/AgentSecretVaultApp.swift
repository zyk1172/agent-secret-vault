import AppKit
import AgentSecretVaultApp
import CryptoKit
import SwiftUI
import UniformTypeIdentifiers
import VaultAuthorization
import VaultCore
import VaultIPC

@main
struct AgentSecretVaultApplication: App {
    @NSApplicationDelegateAdaptor(AgentSecretVaultAppDelegate.self) private var appDelegate
    @State private var secureViewerModel = SecureViewerModel()
    @StateObject private var runtime: AgentSecretVaultRuntime

    init() {
        let runtime = AgentSecretVaultRuntimeStore.shared
        _runtime = StateObject(wrappedValue: runtime)
        Task { @MainActor in
            await runtime.start()
        }
    }

    var body: some Scene {
        Window("SVLT", id: MenuBarPresentation.mainWindowID) {
            VaultWorkbenchView(
                status: runtime.status,
                orphanScanResult: runtime.orphanScanResult,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                sensitiveIndexURL: runtime.sensitiveIndexURL,
                sensitiveIndexEntries: runtime.sensitiveIndexEntries,
                sensitiveScanRootURL: runtime.sensitiveScanRootURL,
                sensitiveScanCandidates: runtime.sensitiveScanCandidates,
                sensitiveScanRules: runtime.sensitiveScanRules,
                restoreParagraph: { text in
                    try await runtime.restoreParagraph(text)
                },
                refreshSavedReferences: {
                    await runtime.refreshSavedReferences()
                },
                chooseSensitiveIndex: {
                    runtime.chooseSensitiveIndex()
                },
                createSensitiveIndex: {
                    runtime.createSensitiveIndex()
                },
                refreshSensitiveIndex: {
                    await runtime.refreshSensitiveIndex()
                },
                chooseSensitiveScanRoot: {
                    runtime.chooseSensitiveScanRoot()
                },
                scanSensitiveInformation: {
                    await runtime.scanSensitiveInformation()
                },
                encryptSensitiveCandidates: { candidateIDs in
                    await runtime.encryptSensitiveCandidates(candidateIDs)
                },
                ignoreSensitiveCandidates: { candidateIDs in
                    await runtime.ignoreSensitiveCandidates(candidateIDs)
                },
                jumpToSensitiveCandidate: { candidate in
                    runtime.jumpToSensitiveCandidate(candidate)
                },
                deleteSensitiveCandidate: { candidate in
                    await runtime.deleteSensitiveCandidate(candidate)
                },
                addSensitiveScanRule: { rule in
                    runtime.addSensitiveScanRule(rule)
                },
                removeSensitiveScanRule: { id in
                    runtime.removeSensitiveScanRule(id)
                }
            )
                .task {
                    await runtime.start()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    secureViewerModel.handleFocusChanged(isFocused: false)
                    Task { await runtime.clearRevealSessions() }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    Task { await runtime.clearRevealSessions() }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    Task { await runtime.clearRevealSessions() }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
                    secureViewerModel.handleLockNotification()
                    Task { await runtime.clearRevealSessions() }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    Task { await runtime.clearRevealSessions() }
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

        MenuBarExtra("SVLT", systemImage: MenuBarPresentation.statusItemSymbol) {
            MenuBarVaultPanel(
                status: runtime.status,
                orphanScanResult: runtime.orphanScanResult,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                sensitiveScanRootURL: runtime.sensitiveScanRootURL,
                sensitiveScanCandidateCount: runtime.sensitiveScanCandidates.count,
                chooseSensitiveScanRoot: {
                    runtime.chooseSensitiveScanRoot()
                },
                rescanSensitiveInformation: {
                    await runtime.scanSensitiveInformation()
                },
                restoreParagraph: { text in
                    try await runtime.restoreParagraph(text)
                },
                refreshSavedReferences: {
                    await runtime.refreshSavedReferences()
                },
                clearRevealSessions: { await runtime.clearRevealSessions() },
                requestPermanentDelete: { _ in
                    Task {
                        await runtime.requestPermanentDeleteAuthorization()
                    }
                },
                requestTermination: {
                    await appDelegate.requestMenuBarTermination(cleanup: runtime.clearRevealSessions)
                }
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
private enum AgentSecretVaultRuntimeStore {
    static let shared = AgentSecretVaultRuntime()
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
    @Published var sensitiveIndexURL: URL?
    @Published var sensitiveIndexEntries: [SensitiveInformationDocumentReference] = []
    @Published var sensitiveIndexError: String?
    @Published var sensitiveScanRootURL: URL?
    @Published var sensitiveScanCandidates: [LocalSensitiveInformationCandidate] = []
    @Published var sensitiveScanError: String?
    @Published var sensitiveScanRules: [SensitiveScanRuleDefinition] = SensitiveScanRuleDefinition.defaults + SensitiveScanRulePreferences.customRules()

    private var controller: AppIPCController?
    private var services: VaultAppServices?
    private var protectionKeyStore: AppProtectionKeyStore?
    private var sensitiveIndexStore: SensitiveInformationDocumentStore?
    private var legacyRecordStore: FileRecordStore?
    private var lifecycleMonitor: VaultLifecycleMonitor?
    private var started = false
    private var isStarting = false

    func start() async {
        guard !started, !isStarting else {
            return
        }
        isStarting = true
        defer { isStarting = false }

        do {
            let runtime = try makeRuntime()
            try? await runtime.protectionKeyStore.unlockLowProtection()
            controller = runtime.controller
            services = runtime.services
            protectionKeyStore = runtime.protectionKeyStore
            sensitiveIndexStore = runtime.sensitiveIndexStore
            legacyRecordStore = runtime.legacyRecordStore
            sensitiveIndexURL = await runtime.sensitiveIndexStore.selectedDocumentURL()
            sensitiveScanRootURL = SensitiveIndexSelectionStore.selectedScanRootURL()
            do {
                _ = try await runtime.sensitiveIndexStore.prepareSelectedDocument()
                if let documentURL = await runtime.sensitiveIndexStore.selectedDocumentURL() {
                    SensitiveIndexSelectionStore.save(documentURL)
                    sensitiveIndexURL = documentURL
                }
            } catch {
                sensitiveIndexError = "无法整理敏感信息.md"
            }
            try runtime.controller.start()
            lifecycleMonitor = VaultLifecycleMonitor { [weak self] in
                await self?.clearRevealSessions()
            }
            lifecycleMonitor?.start()
            status = await runtime.services.status()
            await refreshSavedReferences()
            await refreshSensitiveIndex()
            started = true
        } catch {
            NSLog("SVLT runtime startup failed: %@", String(describing: error))
            sensitiveIndexError = "无法启动本地服务"
            status = WorkbenchStatus(
                locked: true,
                ipcAvailable: false,
                activeKnowledgeBaseRoot: nil,
                pluginConnected: false
            )
        }
    }

    func clearRevealSessions() async {
        RevealSessionLifecycle.clearAll()
        await services?.clearRevealSessions()
    }

    func requestPermanentDeleteAuthorization() async {
        guard let protectionKeyStore else {
            return
        }

        _ = try? await protectionKeyStore.deviceKey(
            for: .credential,
            reason: "请求删除本机加密记录"
        )
    }

    func restoreParagraph(_ text: String) async throws -> RestoredParagraph {
        guard let services else {
            throw AgentSecretVaultRuntimeError.notStarted
        }
        let request = try ParagraphRestoreBuilder.build(from: text)
        return try await services.restoreReferencesWithValues(
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

    func refreshSensitiveIndex() async {
        guard let sensitiveIndexStore else {
            sensitiveIndexEntries = []
            return
        }

        do {
            sensitiveIndexEntries = try await sensitiveIndexStore.references()
            sensitiveIndexError = nil
        } catch SensitiveInformationDocumentStoreError.noSelectedDocument {
            sensitiveIndexEntries = []
            sensitiveIndexError = nil
        } catch {
            sensitiveIndexEntries = []
            sensitiveIndexError = "无法读取所选敏感信息.md"
        }
    }

    func chooseSensitiveIndex() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText, .plainText]
        panel.message = "选择集中维护的敏感信息.md"
        panel.prompt = "选择"

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        Task { await activateSensitiveIndex(at: url) }
    }

    func createSensitiveIndex() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "敏感信息.md"
        panel.message = "新建集中维护的敏感信息.md"
        panel.prompt = "新建"

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        Task { await activateSensitiveIndex(at: url) }
    }

    private func activateSensitiveIndex(at url: URL) async {
        guard let sensitiveIndexStore else {
            return
        }
        let priorURL = await sensitiveIndexStore.selectedDocumentURL()

        do {
            try await sensitiveIndexStore.selectDocument(at: url)
            _ = try await sensitiveIndexStore.prepareSelectedDocument()
            SensitiveIndexSelectionStore.save(url)
            sensitiveIndexURL = url
            sensitiveIndexError = nil
            await refreshSensitiveIndex()
            await refreshSavedReferences()
        } catch {
            try? await sensitiveIndexStore.selectDocument(at: priorURL)
            sensitiveIndexError = "所选文件不是有效的敏感信息.md"
        }
    }

    func chooseSensitiveScanRoot() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.message = "选择要本地检查的 Markdown 文件或文件夹"
        panel.prompt = "选择"

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        sensitiveScanRootURL = url
        SensitiveIndexSelectionStore.saveScanRoot(url)
        Task { await scanSensitiveInformation() }
    }

    func scanSensitiveInformation() async {
        guard let sensitiveScanRootURL else {
            sensitiveScanCandidates = []
            sensitiveScanError = "请先选择 Markdown 文件或文件夹"
            return
        }

        do {
            let scanner = LocalSensitiveInformationScanner(rules: sensitiveScanRules)
            let ignored = SensitiveScanRulePreferences.ignoredCandidateIDs()
            sensitiveScanCandidates = try scanner.scan(
                target: sensitiveScanRootURL,
                excluding: sensitiveIndexURL
            ).filter { !ignored.contains($0.id) }
            sensitiveScanError = nil
        } catch {
            sensitiveScanCandidates = []
            sensitiveScanError = "无法读取所选 Markdown 内容"
        }
    }

    func encryptSensitiveCandidates(_ ids: Set<String>) async {
        guard !ids.isEmpty, let services, let sensitiveIndexStore else {
            return
        }

        let selected = sensitiveScanCandidates.filter { ids.contains($0.id) }
        var failed = false
        for candidate in selected {
            do {
                let reference = try await services.encryptText(
                    candidate.matchedValue,
                    label: candidate.title,
                    policy: .credential
                )
                try LocalSensitiveInformationWriter.replace(
                    candidate,
                    reference: reference
                )
                try await sensitiveIndexStore.appendParagraph(
                    candidate.replacingValue(in: candidate.paragraph, reference: reference),
                    title: candidate.title,
                    reference: reference
                )
            } catch {
                failed = true
            }
        }

        await refreshSensitiveIndex()
        await refreshSavedReferences()
        await scanSensitiveInformation()
        if failed {
            sensitiveScanError = "部分候选未写回：文件可能已修改，或尚未选择敏感信息.md"
        }
    }

    func ignoreSensitiveCandidates(_ ids: Set<String>) async {
        guard !ids.isEmpty else {
            return
        }
        SensitiveScanRulePreferences.ignore(ids)
        sensitiveScanCandidates.removeAll { ids.contains($0.id) }
    }

    func deleteSensitiveCandidate(_ candidate: LocalSensitiveInformationCandidate) async {
        guard let protectionKeyStore else {
            return
        }
        do {
            _ = try await protectionKeyStore.deviceKey(for: .credential, reason: "删除本地扫描命中值")
            try LocalSensitiveInformationWriter.remove(candidate)
            await scanSensitiveInformation()
        } catch {
            sensitiveScanError = "无法删除命中值：文件可能已修改"
        }
    }

    func jumpToSensitiveCandidate(_ candidate: LocalSensitiveInformationCandidate) {
        var components = URLComponents()
        components.scheme = "obsidian"
        components.host = "svlt"
        components.queryItems = [
            URLQueryItem(name: "file", value: candidate.fileURL.path),
            URLQueryItem(name: "line", value: String(candidate.source.line))
        ]
        if let url = components.url {
            NSWorkspace.shared.open(url)
        }
    }

    func addSensitiveScanRule(_ rule: SensitiveScanRuleDefinition) {
        var custom = SensitiveScanRulePreferences.customRules()
        custom.append(rule)
        SensitiveScanRulePreferences.saveCustomRules(custom)
        sensitiveScanRules = SensitiveScanRuleDefinition.defaults + custom
    }

    func removeSensitiveScanRule(_ id: String) {
        var custom = SensitiveScanRulePreferences.customRules()
        custom.removeAll { $0.id == id }
        SensitiveScanRulePreferences.saveCustomRules(custom)
        sensitiveScanRules = SensitiveScanRuleDefinition.defaults + custom
    }

    private func makeRuntime() throws -> (
        controller: AppIPCController,
        services: VaultAppServices,
        protectionKeyStore: AppProtectionKeyStore,
        sensitiveIndexStore: SensitiveInformationDocumentStore,
        legacyRecordStore: FileRecordStore
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

        let selectedScanTarget = SensitiveIndexSelectionStore.selectedScanRootURL()
        let selectedDocument = SensitiveIndexSelectionStore.selectedURL()
            ?? SensitiveInformationDocumentStore.defaultDocumentURL(scanTargetURL: selectedScanTarget)
        let recordStore = FileRecordStore(baseDirectory: root)
        let sensitiveIndexStore = SensitiveInformationDocumentStore(documentURL: selectedDocument)
        let legacyRecordStore = FileRecordStore(baseDirectory: root)
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
            let hasLegacyRecords = (try? await recordStore.recordIDs().isEmpty) == false
            if try await wrappedMasterKeyStore.loadWrappedMasterKeySet() == nil,
               hasLegacyRecords {
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
        return (controller, services, protectionKeyStore, sensitiveIndexStore, legacyRecordStore)
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

@MainActor
final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    private let terminationCoordinator = MenuBarTerminationCoordinator {
        NSApp.terminate(nil)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            await AgentSecretVaultRuntimeStore.shared.start()
        }
    }

    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func requestMenuBarTermination(
        cleanup: @escaping @MainActor () async -> Void
    ) async {
        await terminationCoordinator.requestTermination(cleanup: cleanup)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        terminationCoordinator.permitsTermination ? .terminateNow : .terminateCancel
    }
}
