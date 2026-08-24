import AppKit
import AgentSecretVaultApp
import SwiftUI
import UniformTypeIdentifiers
import VaultCore
import VaultIPC
import VaultService

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
                agentServiceStatus: runtime.agentServiceStatus,
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
                requestPermanentDelete: { reference in
                    Task {
                        await runtime.deleteRecord(reference)
                    }
                },
                requestTermination: {
                    await appDelegate.requestMenuBarTermination()
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
    @Published var agentServiceStatus: AgentServiceStatus = .notRegistered
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

    private var agentClient: VaultIPCClient?
    private let uiRevealSessionStore = RevealSessionStore(defaultTTLSeconds: 60)
    private var uiRequestObserver: NSObjectProtocol?
    private var presentedAgentSessionIDs: Set<String> = []
    private var sensitiveIndexStore: SensitiveInformationDocumentStore?
    private var started = false
    private var isStarting = false
    private var readinessTask: Task<Void, Never>?

    func start() async {
        guard !started, !isStarting else {
            return
        }
        isStarting = true
        defer { isStarting = false }

        do {
            let registration = AgentServiceRegistration.shared
            try registration.registerIfNeeded()
            agentServiceStatus = registration.status
            let client = try VaultIPCClient.defaultClient()
            agentClient = client
            startUIRequestObserver()
            sensitiveIndexStore = try makeSensitiveIndexStore()
            guard let sensitiveIndexStore else {
                throw AgentSecretVaultRuntimeError.notStarted
            }
            sensitiveIndexURL = await sensitiveIndexStore.selectedDocumentURL()
            sensitiveScanRootURL = SensitiveIndexSelectionStore.selectedScanRootURL()
            do {
                _ = try await sensitiveIndexStore.prepareSelectedDocument()
                if let documentURL = await sensitiveIndexStore.selectedDocumentURL() {
                    SensitiveIndexSelectionStore.save(documentURL)
                    persistCatalogSelection(at: documentURL)
                    sensitiveIndexURL = documentURL
                }
            } catch {
                sensitiveIndexError = "无法整理敏感信息.md"
            }

            await refreshSensitiveIndex()
            started = true

            if !(await connectToAgent(client)) {
                markAgentDisconnected()
                startReadinessMonitoring(client)
            }
        } catch {
            NSLog("SVLT runtime startup failed [AGENT_START_FAILED]")
            sensitiveIndexError = "无法启动本地服务"
            agentServiceStatus = AgentServiceRegistration.shared.status
            status = WorkbenchStatus(
                locked: true,
                ipcAvailable: false,
                activeKnowledgeBaseRoot: nil,
                pluginConnected: false
            )
        }
    }

    private func connectToAgent(_ client: VaultIPCClient) async -> Bool {
        let retryDelays: [Duration] = [
            .zero,
            .milliseconds(100),
            .milliseconds(250),
            .milliseconds(500),
            .seconds(1),
            .seconds(2),
            .seconds(2),
            .seconds(2)
        ]

        for (index, delay) in retryDelays.enumerated() {
            if index > 0 {
                do {
                    try await Task.sleep(for: delay)
                } catch {
                    return false
                }
            }

            do {
                status = try await client.workbenchStatus()
                agentServiceStatus = .running
                await refreshSavedReferences()
                await refreshSensitiveIndex()
                await presentPendingRevealSessions()
                return true
            } catch {
                continue
            }
        }

        return false
    }

    private func startReadinessMonitoring(_ client: VaultIPCClient) {
        readinessTask?.cancel()
        readinessTask = Task { @MainActor [weak self] in
            let retryDelays: [Duration] = [.seconds(2), .seconds(4), .seconds(8), .seconds(10)]
            var delayIndex = 0
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: retryDelays[delayIndex])
                } catch {
                    return
                }

                guard let self, self.started else {
                    return
                }
                if await self.connectToAgent(client) {
                    return
                }
                self.markAgentDisconnected()
                delayIndex = min(delayIndex + 1, retryDelays.count - 1)
            }
        }
    }

    private func markAgentDisconnected() {
        agentServiceStatus = AgentServiceRegistration.shared.status
        status = WorkbenchStatus(
            locked: true,
            ipcAvailable: false,
            activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
            pluginConnected: false
        )
    }

    func clearRevealSessions() async {
        RevealSessionLifecycle.clearAll()
        await uiRevealSessionStore.clearAll()
        presentedAgentSessionIDs.removeAll()
        try? await agentClient?.clearRevealSessions()
    }

    func lockVault() async {
        try? await agentClient?.lock()
        await clearRevealSessions()
    }

    func shutdown() async {
        // App termination is not Agent termination. launchd keeps the
        // independent SVLTAgent alive for MCP/Obsidian clients.
        readinessTask?.cancel()
        readinessTask = nil
        if let uiRequestObserver {
            DistributedNotificationCenter.default().removeObserver(uiRequestObserver)
            self.uiRequestObserver = nil
        }
        RevealSessionLifecycle.clearAll()
        await uiRevealSessionStore.clearAll()
        presentedAgentSessionIDs.removeAll()
        // Clear only UI reveal sessions in the independent Agent; this is
        // deliberately fire-and-forget so a dead/hung Agent can never prevent
        // the GUI from terminating.
        let client = agentClient
        Task.detached {
            try? await client?.clearRevealSessions()
        }
        agentClient = nil
        started = false
    }

    private func startUIRequestObserver() {
        guard uiRequestObserver == nil else {
            return
        }
        uiRequestObserver = DistributedNotificationCenter.default().addObserver(
            forName: AgentUIRequestNotifier.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let sessionID = notification.userInfo?["sessionID"] as? String else {
                return
            }
            Task { @MainActor [weak self] in
                await self?.presentAgentRevealSession(sessionID: sessionID)
            }
        }
    }

    private func presentPendingRevealSessions() async {
        guard let agentClient,
              let sessionIDs = try? await agentClient.pendingRevealSessionIDs()
        else {
            return
        }
        for sessionID in sessionIDs {
            await presentAgentRevealSession(sessionID: sessionID)
        }
    }

    private func presentAgentRevealSession(sessionID: String) async {
        guard let agentClient,
              presentedAgentSessionIDs.insert(sessionID).inserted
        else {
            return
        }
        do {
            let paragraph = try await agentClient.revealSessionData(sessionID: sessionID)
            let localSessionID = await uiRevealSessionStore.create(resolvedParagraph: paragraph)
            await RevealSessionPresenter().present(
                sessionID: localSessionID,
                store: uiRevealSessionStore
            )
        } catch {
            presentedAgentSessionIDs.remove(sessionID)
        }
    }

    func deleteRecord(_ reference: String) async {
        guard let agentClient else {
            return
        }
        do {
            try await agentClient.deleteRecord(reference)
            await refreshSavedReferences()
            await refreshSensitiveIndex()
        } catch {
            sensitiveScanError = "无法删除加密记录"
        }
    }

    func restoreParagraph(_ text: String) async throws -> RestoredParagraph {
        guard let agentClient else {
            throw AgentSecretVaultRuntimeError.notStarted
        }
        let request = try ParagraphRestoreBuilder.build(from: text)
        return try await agentClient.restoreReferences(
            references: request.references,
            context: request.context
        )
    }

    func refreshSavedReferences() async {
        guard let agentClient else {
            savedReferences = []
            return
        }
        do {
            savedReferences = try await agentClient.savedSecretReferences()
            if let currentStatus = try? await agentClient.workbenchStatus() {
                status = currentStatus
                agentServiceStatus = .running
            }
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
            persistCatalogSelection(at: url)
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
        guard !ids.isEmpty, let agentClient, let sensitiveIndexStore else {
            return
        }

        let selected = sensitiveScanCandidates.filter { ids.contains($0.id) }
        let groupedByFile = Dictionary(grouping: selected) {
            $0.fileURL.standardizedFileURL
        }
        var failed = false

        for fileGroup in groupedByFile.values {
            do {
                try LocalSensitiveInformationWriter.validate(fileGroup)
                var references: [String] = []
                var createdReferences: [String] = []
                for candidate in fileGroup {
                    let reference = try await agentClient.encryptText(
                        candidate.matchedValue,
                        label: candidate.title,
                        policy: policy(for: candidate)
                    )
                    references.append(reference)
                    createdReferences.append(reference)
                }

                do {
                    try LocalSensitiveInformationWriter.replace(fileGroup, references: references)
                } catch {
                    for reference in createdReferences {
                        if let id = try? SecretReference(reference).id {
                            try? await agentClient.deleteRecord("secret://\(id)")
                        }
                    }
                    throw error
                }

                let paragraphGroups = Dictionary(grouping: zip(fileGroup, references)) { pair in
                    "\(pair.0.paragraphStartUTF16):\(pair.0.paragraphEndUTF16)"
                }
                for paragraphGroup in paragraphGroups.values {
                    let first = paragraphGroup[0].0
                    let updatedParagraph = LocalSensitiveInformationWriter.replacingValues(
                        in: first.paragraph,
                        candidates: paragraphGroup.map(\.0),
                        references: paragraphGroup.map(\.1)
                    )
                    try await sensitiveIndexStore.appendParagraph(
                        updatedParagraph,
                        title: first.title,
                        reference: paragraphGroup[0].1
                    )
                }
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
        guard let agentClient else {
            return
        }
        do {
            try await agentClient.authorizeHighRisk(reason: "删除本地扫描命中值")
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

    private func makeSensitiveIndexStore() throws -> SensitiveInformationDocumentStore {
        let selectedScanTarget = SensitiveIndexSelectionStore.selectedScanRootURL()
        let selectedDocument = SensitiveIndexSelectionStore.selectedURL()
            ?? SensitiveInformationDocumentStore.defaultDocumentURL(scanTargetURL: selectedScanTarget)
        return SensitiveInformationDocumentStore(documentURL: selectedDocument)
    }

    private func persistCatalogSelection(at url: URL) {
        guard let manifestURL = try? SecretCatalogSelectionStore.defaultManifestURL() else {
            return
        }
        try? SecretCatalogSelectionStore(manifestURL: manifestURL).save(documentURL: url)
    }

    private func policy(for candidate: LocalSensitiveInformationCandidate) -> SecretPolicy {
        let highRiskCategories = Set([
            "credential", "api key", "token", "cookie", "private key", "database"
        ])
        if candidate.risk == .high,
           highRiskCategories.contains(candidate.category.lowercased()) {
            return .credential
        }
        // Scanner uncertainty defaults to read. Users can promote a record to
        // credential/externalSend through the explicit policy controls instead
        // of silently making every match a high-risk secret.
        return .read
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

@MainActor
final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    private var terminationInProgress = false

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

    func requestMenuBarTermination() async {
        NSApp.terminate(nil)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminationInProgress else {
            return .terminateLater
        }

        terminationInProgress = true
        Task { @MainActor in
            await AgentSecretVaultRuntimeStore.shared.shutdown()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
