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
                agentServiceActionInFlight: runtime.agentServiceActionInFlight,
                agentServiceActionErrorMessage: runtime.agentServiceActionErrorMessage,
                enableAgentService: {
                    await runtime.enableAgentService()
                },
                disableAgentService: {
                    await runtime.disableAgentService()
                },
                restartAgentService: {
                    await runtime.restartAgentService()
                },
                orphanScanResult: runtime.orphanScanResult,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                sensitiveIndexURL: runtime.sensitiveIndexURL,
                sensitiveIndexEntries: runtime.sensitiveIndexEntries,
                sensitiveCatalogSnapshot: runtime.sensitiveCatalogSnapshot,
                sensitiveCatalogError: runtime.sensitiveIndexError,
                sensitiveCatalogCanAdoptV2: runtime.sensitiveCatalogCanAdoptV2,
                sensitiveCatalogCanAdoptV3: runtime.sensitiveCatalogCanAdoptV3,
                catalogAgentWriteStatus: runtime.catalogAgentWriteStatus,
                catalogAgentWriteError: runtime.catalogAgentWriteError,
                pendingWriteAccessRequest: runtime.pendingWriteAccessRequest,
                pendingWriteAccessQueueCount: runtime.pendingWriteAccessRequestIDs.count,
                sensitiveScanRootURL: runtime.sensitiveScanRootURL,
                sensitiveScanCandidates: runtime.sensitiveScanCandidates,
                sensitiveScanRules: runtime.sensitiveScanRules,
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
                refreshSensitiveCatalog: {
                    await runtime.refreshSensitiveCatalog()
                },
                validateSensitiveCatalog: {
                    await runtime.validateSensitiveCatalog()
                },
                adoptExternalV2Catalog: {
                    await runtime.adoptExternalV2Catalog()
                },
                adoptExternalV3Catalog: {
                    await runtime.adoptExternalV3Catalog()
                },
                approveExternalCatalogChange: {
                    await runtime.approveExternalCatalogChange()
                },
                repairSensitiveCatalog: {
                    await runtime.repairSensitiveCatalog()
                },
                recoveryPlan: {
                    await runtime.catalogRecoveryPlan()
                },
                restoreRecovery: { plan in
                    await runtime.catalogRestoreRecovery(plan)
                },
                createCatalogIndex: { title in
                    await runtime.createCatalogIndex(title: title)
                },
                createCatalogEntry: { indexID, title, presetID in
                    await runtime.createCatalogEntry(indexID: indexID, title: title, presetID: presetID)
                },
                commitCatalogEntryEdit: { entry, secretInputs in
                    await runtime.commitCatalogEntryEdit(entry: entry, secretInputs: secretInputs)
                },
                revealCatalogField: { entryID, key in
                    try await runtime.revealCatalogField(entryID: entryID, key: key)
                },
                replaceCatalogSecret: { entryID, key, label, plaintext in
                    await runtime.replaceCatalogSecret(
                        entryID: entryID,
                        key: key,
                        label: label,
                        plaintext: plaintext
                    )
                },
                applyCatalogBatch: { mutation in
                    await runtime.applyCatalogBatch(mutation)
                },
                enableCatalogAgentWrite: { mode in
                    await runtime.enableCatalogAgentWrite(mode: mode)
                },
                revokeCatalogAgentWrite: {
                    await runtime.revokeCatalogAgentWrite()
                },
                respondToWriteAccessRequest: { id, approved in
                    await runtime.respondToCatalogWriteAccessRequest(id: id, approved: approved)
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

                    Button("密文库") {
                        navigateWorkbench(to: .secrets)
                    }
                    .keyboardShortcut("2", modifiers: [.command])

                    Button("记录维护") {
                        navigateWorkbench(to: .records)
                    }
                    .keyboardShortcut("3", modifiers: [.command])

                    Button("智能体自动化") {
                        navigateWorkbench(to: .automation)
                    }
                    .keyboardShortcut("4", modifiers: [.command])

                    Button("安全边界") {
                        navigateWorkbench(to: .security)
                    }
                    .keyboardShortcut("5", modifiers: [.command])
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
    @Published var agentServiceActionInFlight = false
    @Published var agentServiceActionErrorMessage: String?
    @Published var orphanScanResult: OrphanScanResult?
    @Published var auditEntries: [AgentAutomationAuditEntry] = []
    @Published var savedReferences: [SecretReferenceMetadata] = []
    @Published var sensitiveIndexURL: URL?
    @Published var sensitiveIndexEntries: [SensitiveInformationDocumentReference] = []
    @Published var sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    @Published var sensitiveCatalogCanAdoptV2 = false
    @Published var sensitiveCatalogCanAdoptV3 = false
    @Published var catalogAgentWriteStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled)
    @Published var catalogAgentWriteError: String?
    @Published var pendingWriteAccessRequest: CatalogAgentWriteAccessRequest?
    /// Snapshot of every still-pending agent Catalog write request, oldest
    /// first. The first entry is the one currently shown; the UI uses the
    /// count to present "待处理请求 1 / 3" style queue state.
    @Published var pendingWriteAccessRequestIDs: [UUID] = []
    @Published var sensitiveIndexError: String?
    @Published var sensitiveScanRootURL: URL?
    @Published var sensitiveScanCandidates: [LocalSensitiveInformationCandidate] = []
    @Published var sensitiveScanError: String?
    @Published var sensitiveScanRules: [SensitiveScanRuleDefinition] = SensitiveScanRuleDefinition.defaults + SensitiveScanRulePreferences.customRules()

    private var agentClient: VaultIPCClient?
    private var appControlClient: AppControlIPCClient?
    private let uiRevealSessionStore = RevealSessionStore(defaultTTLSeconds: 60)
    private var uiRequestObserver: NSObjectProtocol?
    private var writeAccessObserver: NSObjectProtocol?
    private var applicationActivationObserver: NSObjectProtocol?
    private var presentedAgentSessionIDs: Set<String> = []
    private var sensitiveIndexStore: SensitiveInformationDocumentStore?
    private var sensitiveCatalogStore: SensitiveCatalogDocumentStore?
    private var started = false
    private var isStarting = false
    private var readinessTask: Task<Void, Never>?
    private var pendingWriteAccessQueue = PendingCatalogWriteAccessQueue()

    func start() async {
        guard !started, !isStarting else {
            return
        }
        isStarting = true
        defer { isStarting = false }

        do {
            let registration = AgentServiceRegistration.shared
            try await registration.registerIfNeeded()
            agentServiceStatus = registration.status
            let client = try VaultIPCClient.defaultClient()
            agentClient = client
            appControlClient = try AppControlIPCClient.defaultClient()
            if let appControlClient {
                catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                    ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            }
            startUIRequestObserver()
            startWriteAccessObserver()
            startApplicationActivationObserver()
            sensitiveIndexStore = try makeSensitiveIndexStore()
            sensitiveCatalogStore = try makeSensitiveCatalogStore()
            guard let sensitiveIndexStore else {
                throw AgentSecretVaultRuntimeError.notStarted
            }
            sensitiveIndexURL = await sensitiveIndexStore.selectedDocumentURL().flatMap {
                FileManager.default.fileExists(atPath: $0.path) ? $0 : nil
            }
            sensitiveScanRootURL = SensitiveIndexSelectionStore.selectedScanRootURL()
            if let documentURL = await sensitiveIndexStore.selectedDocumentURL(),
               FileManager.default.fileExists(atPath: documentURL.path) {
                // A missing previously selected file is not recreated on
                // startup. The user must explicitly choose an existing
                // file or use the new-catalog entry point.
                SensitiveIndexSelectionStore.save(documentURL)
                persistCatalogSelection(at: documentURL)
                sensitiveIndexURL = documentURL
            }

            await refreshSensitiveIndex()
            await refreshSensitiveCatalog()
            await refreshPendingCatalogWriteAccessRequests()
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
        guard !AgentServiceRegistration.shared.isExplicitlyDisabled else {
            return false
        }

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
                await refreshPendingCatalogWriteAccessRequests()
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

                guard let self,
                      self.started,
                      !AgentServiceRegistration.shared.isExplicitlyDisabled
                else {
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
        if AgentServiceRegistration.shared.isExplicitlyDisabled {
            markAgentDisabled()
            return
        }
        agentServiceStatus = AgentServiceRegistration.shared.status
        status = WorkbenchStatus(
            locked: true,
            ipcAvailable: false,
            activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
            pluginConnected: false
        )
    }

    private func markAgentDisabled() {
        agentServiceStatus = .disabled
        status = WorkbenchStatus(
            locked: true,
            ipcAvailable: false,
            available: false,
            ready: false,
            activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
            pluginConnected: false
        )
    }

    private func reconnectAfterServiceAction() async {
        readinessTask?.cancel()
        readinessTask = nil

        let registration = AgentServiceRegistration.shared
        agentServiceStatus = registration.status
        guard !registration.isExplicitlyDisabled else {
            agentClient = nil
            appControlClient = nil
            markAgentDisabled()
            return
        }

        do {
            let client = try VaultIPCClient.defaultClient()
            agentClient = client
            appControlClient = try AppControlIPCClient.defaultClient()
            if let appControlClient {
                catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                    ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            }
            if !(await connectToAgent(client)) {
                markAgentDisconnected()
                startReadinessMonitoring(client)
            }
        } catch {
            agentClient = nil
            appControlClient = nil
            markAgentDisconnected()
        }
    }

    private func performAgentServiceAction(
        failureCode: String,
        failureMessage: String,
        operation: () async throws -> Void
    ) async {
        guard !agentServiceActionInFlight else { return }
        agentServiceActionInFlight = true
        agentServiceActionErrorMessage = nil
        defer { agentServiceActionInFlight = false }

        do {
            try await operation()
            await reconnectAfterServiceAction()
        } catch {
            NSLog("SVLT Agent service action failed [\(failureCode)]")
            agentServiceActionErrorMessage = failureMessage
            agentServiceStatus = AgentServiceRegistration.shared.status
        }
    }

    func enableAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_ENABLE_FAILED",
            failureMessage: "无法启用后台智能体服务，请检查本机登录项权限"
        ) {
            try AgentServiceRegistration.shared.register()
        }
    }

    func disableAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_DISABLE_FAILED",
            failureMessage: "无法停用后台智能体服务"
        ) {
            try await AgentServiceRegistration.shared.unregisterAndWait()
        }
    }

    func restartAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_RESTART_FAILED",
            failureMessage: "无法重启后台智能体服务"
        ) {
            try await AgentServiceRegistration.shared.restart()
        }
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
        if let writeAccessObserver {
            DistributedNotificationCenter.default().removeObserver(writeAccessObserver)
            self.writeAccessObserver = nil
        }
        if let applicationActivationObserver {
            NotificationCenter.default.removeObserver(applicationActivationObserver)
            self.applicationActivationObserver = nil
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

    private func startWriteAccessObserver() {
        guard writeAccessObserver == nil else { return }
        writeAccessObserver = DistributedNotificationCenter.default().addObserver(
            forName: CatalogAgentWriteAccessRequest.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let rawID = notification.userInfo?["requestID"] as? String,
                  UUID(uuidString: rawID) != nil
            else { return }
            Task { @MainActor [weak self] in
                // Re-query the ordered queue rather than replacing the
                // request currently displayed by this notification.
                await self?.refreshPendingCatalogWriteAccessRequests()
            }
        }
    }

    private func startApplicationActivationObserver() {
        guard applicationActivationObserver == nil else { return }
        applicationActivationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.refreshPendingCatalogWriteAccessRequests()
            }
        }
    }

    private func refreshPendingCatalogWriteAccessRequests() async {
        guard let agentClient else {
            pendingWriteAccessQueue.replace(with: [])
            pendingWriteAccessRequestIDs = []
            return
        }
        guard let requestIDs = try? await agentClient.pendingCatalogWriteAccessRequestIDs() else {
            // A transient IPC failure must not dismiss the request currently
            // being authenticated or make another request jump its place.
            return
        }
        pendingWriteAccessQueue.replace(with: requestIDs)
        pendingWriteAccessRequestIDs = pendingWriteAccessQueue.ids
        if requestIDs.isEmpty {
            pendingWriteAccessRequest = nil
            return
        }
        if let current = pendingWriteAccessRequest, !requestIDs.contains(current.id) {
            pendingWriteAccessRequest = nil
        }
        for requestID in requestIDs {
            await loadPendingWriteAccessRequest(id: requestID)
            if pendingWriteAccessRequest != nil {
                return
            }
            // The request vanished (expired/cancelled/consumed) while we were
            // loading it; drop it and try the next one in the same pass.
            pendingWriteAccessQueue.finish(requestID)
            pendingWriteAccessRequestIDs = pendingWriteAccessQueue.ids
        }
    }

    private func loadPendingWriteAccessRequest(id: UUID) async {
        guard let appControlClient else { return }
        if let current = pendingWriteAccessRequest, current.id != id {
            return
        }
        pendingWriteAccessRequest = try? await appControlClient.pendingCatalogWriteAccessRequest(id: id)
    }

    /// After a terminal outcome for one request (approved, denied,
    /// authentication failed/cancelled, expired), clear it and surface the
    /// next pending request on a later main-queue turn. A new alert is never
    /// presented from inside the dismissing alert's callback.
    private func scheduleNextPendingCatalogWriteAccessRefresh() {
        Task { @MainActor [weak self] in
            await Task.yield()
            try? await Task.sleep(nanoseconds: 350_000_000)
            guard let self, self.pendingWriteAccessRequest == nil else { return }
            await self.refreshPendingCatalogWriteAccessRequests()
        }
    }

    func respondToCatalogWriteAccessRequest(id: UUID, approved: Bool) async {
        guard let appControlClient else { return }
        do {
            try await appControlClient.respondToCatalogWriteAccessRequest(id: id, approved: approved)
            catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
        } catch {
            catalogAgentWriteError = approved ? "授权请求处理失败" : "已保留拒绝结果"
        }
        // Every terminal path lands here: consume exactly this one request
        // and then continue with whatever is still pending.
        pendingWriteAccessRequest = nil
        pendingWriteAccessQueue.finish(id)
        pendingWriteAccessRequestIDs = pendingWriteAccessQueue.ids
        scheduleNextPendingCatalogWriteAccessRefresh()
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

    func refreshSavedReferences() async {
        guard !AgentServiceRegistration.shared.isExplicitlyDisabled else {
            savedReferences = []
            markAgentDisabled()
            return
        }
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
        // Managed catalog entries are rendered only from the strict v3 Store.
        // The ordinary-note reader remains separate and is never a catalog
        // fallback.
        sensitiveIndexEntries = []
    }

    func refreshSensitiveCatalog() async {
        guard let sensitiveCatalogStore else {
            sensitiveCatalogSnapshot = nil
            return
        }
        guard let selectedURL = await sensitiveCatalogStore.selectedDocumentURL(),
              FileManager.default.fileExists(atPath: selectedURL.path)
        else {
            sensitiveCatalogSnapshot = nil
            sensitiveCatalogCanAdoptV2 = false
            sensitiveCatalogCanAdoptV3 = false
            return
        }

        do {
            sensitiveCatalogSnapshot = try await sensitiveCatalogStore.snapshot()
            sensitiveCatalogCanAdoptV2 = false
            sensitiveCatalogCanAdoptV3 = false
            if sensitiveCatalogSnapshot?.integrity == .verified {
                sensitiveIndexError = nil
            }
        } catch SensitiveCatalogDocumentStoreError.legacyCatalogUnsupported {
            sensitiveCatalogSnapshot = nil
            sensitiveCatalogCanAdoptV2 = false
            sensitiveCatalogCanAdoptV3 = false
            sensitiveIndexError = "当前敏感信息.md 是旧版格式。SVLT 不提供自动升级，请先备份并手动转换为 Catalog v3。"
        } catch SensitiveCatalogDocumentStoreError.externalModification {
            sensitiveCatalogSnapshot = nil
            sensitiveCatalogCanAdoptV2 = false
            sensitiveCatalogCanAdoptV3 = false
            sensitiveIndexError = "检测到目录被外部修改，已暂停使用"
        } catch SensitiveCatalogDocumentStoreError.integrityMissing {
            sensitiveCatalogSnapshot = nil
            updateCatalogAdoptionAvailability()
            sensitiveIndexError = sensitiveCatalogCanAdoptV3
                ? "检测到合法但尚未建立本机 accepted state 的 v3 文件，请验证并接纳。"
                : "检测到合法但尚未被 SVLT 接管的 v2 文件，请验证并升级为 v3。"
        } catch {
            sensitiveCatalogSnapshot = nil
            sensitiveCatalogCanAdoptV2 = false
            sensitiveCatalogCanAdoptV3 = false
            sensitiveIndexError = "敏感信息目录校验失败"
        }
    }

    private func updateCatalogAdoptionAvailability() {
        sensitiveCatalogCanAdoptV2 = false
        sensitiveCatalogCanAdoptV3 = false
        guard let url = sensitiveIndexURL,
              let data = try? Data(contentsOf: url, options: [.mappedIfSafe])
        else {
            return
        }
        switch SensitiveCatalogDocumentCodec.format(data) {
        case .managedV2:
            sensitiveCatalogCanAdoptV2 = true
        case .managedV3:
            sensitiveCatalogCanAdoptV3 = true
        case .unmanaged, .legacy:
            break
        }
    }

    func validateSensitiveCatalog() async {
        guard let agentClient else {
            sensitiveIndexError = "本机智能体服务不可用，无法验证敏感信息目录"
            return
        }

        do {
            let result = try await agentClient.validateCatalog()
            switch result.status {
            case .found:
                await refreshSensitiveCatalog()
                if sensitiveCatalogSnapshot?.integrity == .verified {
                    sensitiveIndexError = nil
                }
            case .legacyCatalogUnsupported:
                sensitiveCatalogCanAdoptV2 = false
                sensitiveCatalogCanAdoptV3 = false
                sensitiveIndexError = "当前敏感信息.md 是旧版格式。SVLT 不提供自动升级，请手动转换为 Catalog v3。"
            case .integrityMissing:
                updateCatalogAdoptionAvailability()
                sensitiveIndexError = sensitiveCatalogCanAdoptV3
                    ? "检测到合法但尚未建立本机 accepted state 的 v3 文件，请验证并接纳。"
                    : "检测到合法但尚未被 SVLT 接管的 v2 文件，请验证并升级为 v3。"
            case .externalModification:
                sensitiveCatalogCanAdoptV2 = false
                sensitiveCatalogCanAdoptV3 = false
                sensitiveIndexError = "检测到目录被外部修改，已暂停使用"
            case .pendingExternalChange:
                sensitiveCatalogCanAdoptV2 = false
                sensitiveCatalogCanAdoptV3 = false
                sensitiveIndexError = "目录存在待审批的高风险外部变更，已暂停使用"
            case .invalidCatalog:
                sensitiveCatalogCanAdoptV2 = false
                sensitiveCatalogCanAdoptV3 = false
                sensitiveIndexError = "敏感信息目录校验失败，未继续使用"
            case .unavailable, .notFound, .invalidQuery:
                sensitiveIndexError = "敏感信息目录当前不可用"
            }
        } catch {
            sensitiveIndexError = "无法验证敏感信息目录"
        }
    }

    func adoptExternalV2Catalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法接纳目录"
            return
        }
        do {
            let result = try await appControlClient.adoptCatalogExternalV2()
            guard result.status == .found else {
                sensitiveIndexError = "v2 文件校验失败，原文件保持不变"
                return
            }
            await refreshSensitiveCatalog()
        } catch VaultIPCClientError.responseFailure("LEGACY_CATALOG_UNSUPPORTED") {
            sensitiveIndexError = "当前文件仍是旧版格式，不支持自动升级；请手动转换为 Catalog v3。"
        } catch {
            sensitiveIndexError = "v2 文件升级失败，原文件保持不变"
        }
    }

    func adoptExternalV3Catalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法接纳目录"
            return
        }
        do {
            let result = try await appControlClient.adoptCatalogExternalV3()
            guard result.status == .found else {
                sensitiveIndexError = "v3 文件校验失败，原文件保持不变"
                return
            }
            await refreshSensitiveCatalog()
        } catch {
            sensitiveIndexError = "v3 文件接纳失败，原文件保持不变"
        }
    }

    func approveExternalCatalogChange() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法批准目录修改"
            return
        }
        do {
            let status = try await appControlClient.catalogStatus()
            guard let pending = status.pendingExternalChange else {
                sensitiveIndexError = "目录没有可批准的待审批修改"
                return
            }
            let result = try await appControlClient.approveCatalogExternalChange(
                expectedRevision: pending.acceptedRevision,
                expectedRawSHA256: pending.rawSHA256,
                expectedSemanticSHA256: pending.semanticSHA256
            )
            if result.status == .found {
                await refreshSensitiveCatalog()
            } else {
                sensitiveIndexError = "目录外部修改尚未被接纳"
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "批准目录外部修改")
            sensitiveIndexError = uiError.displayText
        }
    }

    func createCatalogIndex(title: String) async -> CatalogMutationUIResult {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard !trimmedTitle.isEmpty else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "分组标题不能为空"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }

        func create(expectedRevision: UInt64) async throws -> CatalogWriteResult {
            try await appControlClient.catalogCreateIndex(
                title: trimmedTitle,
                expectedRevision: expectedRevision
            )
        }

        do {
            let result = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            do {
                let retry = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
                return .success(retry)
            } catch {
                let uiError = catalogMutationUIError(for: error, operation: "新增分组")
                sensitiveIndexError = uiError.displayText
                return .failure(uiError)
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "新增分组")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    func createCatalogEntry(
        indexID: String,
        title: String,
        presetID: String
    ) async -> CatalogEntryCreationResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard let preset = SensitiveCatalogEntryPreset.all.first(where: { $0.id == presetID }) else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "条目预设无效"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "条目标题不能为空"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }

        let request = CatalogDraftRequest(
            indexID: indexID,
            title: title.trimmingCharacters(in: .whitespacesAndNewlines),
            fields: [preset.makeInitialField()]
        )

        func create(expectedRevision: UInt64) async throws -> CatalogWriteResult {
            try await appControlClient.catalogCreateEntry(request, expectedRevision: expectedRevision)
        }

        do {
            let result = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            do {
                let retry = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
                return .success(retry)
            } catch {
                let uiError = catalogMutationUIError(for: error, operation: "新增条目")
                sensitiveIndexError = uiError.displayText
                return .failure(uiError)
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "新增条目")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    private func catalogMutationUIError(for error: Error, operation: String) -> CatalogMutationUIError {
        let code: String
        if let error = error as? VaultIPCClientError {
            switch error {
            case .responseFailure(let responseCode):
                code = responseCode
            case .endpointUnavailable, .endpointOwnershipInvalid, .endpointPermissionsInvalid:
                code = "APP_CONTROL_UNAVAILABLE"
            default:
                code = "APP_CONTROL_REQUEST_FAILED"
            }
        } else {
            code = "APP_CONTROL_REQUEST_FAILED"
        }

        let message: String
        switch code {
        case "CATALOG_REVISION_CONFLICT":
            message = "目录刚被其他本机客户端更新，自动重试后仍冲突"
        case "CATALOG_UNAVAILABLE":
            message = "敏感信息目录当前不可用"
        case "CATALOG_INVALID":
            message = "目录数据无效；请检查字段 key、类型和值"
        case "CATALOG_INVALID_OPERATION":
            message = "目录中不存在对应分组或条目，或操作参数无效"
        case "CATALOG_WRITE_FAILED":
            message = "目录写入失败；原目录内容未被安全提交，请稍后重试"
        case "EXTERNAL_CATALOG_MODIFICATION":
            message = "检测到目录被外部修改，已暂停写入"
        case "PENDING_EXTERNAL_CHANGE":
            message = "目录有待审批的高风险外部修改"
        case "APP_CONTROL_UNAUTHORIZED", "INVALID_APP_CONTROL_TOKEN":
            message = "本机控制服务身份校验失败"
        case "APP_CONTROL_UNAVAILABLE":
            message = "本机控制服务不可用"
        case "CATALOG_AGENT_WRITE_NOT_ALLOWED":
            message = "智能体的安全目录编辑已关闭"
        case "CATALOG_APPROVAL_REQUIRED":
            message = "此目录变更需要本机批准"
        case "CATALOG_CLEANUP_REQUIRED":
            message = "目录保存失败；有新的加密记录待清理，请稍后执行清理或孤儿扫描"
        case "CATALOG_OPERATION_DENIED":
            message = "此目录变更被本机策略拒绝"
        case "CATALOG_AUTHORIZATION_CANCELLED":
            message = "本机批准已取消"
        case "CATALOG_AUTHORIZATION_DENIED":
            message = "本机批准被拒绝"
        case "CATALOG_AUTHORIZATION_TIMEOUT":
            message = "本机批准已超时"
        case "CATALOG_AUTHORIZATION_UNAVAILABLE":
            message = "本机批准服务不可用"
        default:
            message = "\(operation)失败"
        }
        return CatalogMutationUIError(code: code, message: message)
    }

    func commitCatalogEntryEdit(
        entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput]
    ) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogCommitEntryEdit(
                entry,
                secretInputs: secretInputs,
                expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            let error = CatalogMutationUIError(
                code: "CATALOG_REVISION_CONFLICT",
                message: "目录已被其他本机客户端更新，请刷新后重试"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_APPROVAL_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_APPROVAL_REQUIRED",
                message: "此字段安全变化需要本机批准"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch {
            let error = catalogMutationUIError(for: error, operation: "保存条目")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
    }

    func revealCatalogField(entryID: String, key: String) async throws -> String {
        guard let appControlClient else {
            throw AgentSecretVaultRuntimeError.notStarted
        }
        return try await appControlClient.catalogRevealField(entryID: entryID, key: key)
    }

    func replaceCatalogSecret(
        entryID: String,
        key: String,
        label: String,
        plaintext: String
    ) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(code: "APP_CONTROL_UNAVAILABLE", message: "本机控制服务不可用")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogSecureInput(
                entryID: entryID,
                key: key,
                label: label,
                plaintext: plaintext,
                policy: .credential
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(CatalogWriteResult(
                revision: result.revision,
                secretReference: result.reference
            ))
        } catch VaultIPCClientError.responseFailure("CATALOG_CLEANUP_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_CLEANUP_REQUIRED",
                message: "替换失败；新的加密记录未能自动清理，请稍后执行孤儿扫描"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            let error = CatalogMutationUIError(
                code: "CATALOG_REVISION_CONFLICT",
                message: "目录已被其他本机客户端更新，请刷新后重试"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_APPROVAL_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_APPROVAL_REQUIRED",
                message: "替换密码需要本机批准"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch {
            let error = catalogMutationUIError(for: error, operation: "替换密码")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
    }

    func applyCatalogBatch(_ mutation: CatalogBatchMutation) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(code: "APP_CONTROL_UNAVAILABLE", message: "本机控制服务不可用")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogApplyBatch(
                mutation,
                expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "保存批量修改")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    func enableCatalogAgentWrite(mode: CatalogAgentWriteMode) async {
        guard let appControlClient else { return }
        do {
            catalogAgentWriteStatus = try await appControlClient.setCatalogAgentWriteMode(mode: mode)
            catalogAgentWriteError = nil
        } catch {
            catalogAgentWriteError = "无法启用智能体目录编辑权限"
        }
    }

    func revokeCatalogAgentWrite() async {
        guard let appControlClient else { return }
        do {
            try await appControlClient.revokeCatalogAgentWrite()
            catalogAgentWriteStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            catalogAgentWriteError = nil
        } catch {
            catalogAgentWriteError = "无法撤销智能体目录编辑权限"
        }
    }

    func repairSensitiveCatalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法修复目录"
            return
        }
        do {
            let result = try await appControlClient.repairSensitiveCatalog()
            if result.status == .found {
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
            } else {
                sensitiveIndexError = "敏感信息目录修复未完成"
            }
        } catch {
            sensitiveIndexError = "敏感信息目录修复失败或已取消"
        }
    }

    func catalogRecoveryPlan() async -> CatalogRecoveryPlan? {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法生成恢复预览"
            return nil
        }
        do {
            let plan = try await appControlClient.catalogRecoveryPlan()
            if plan == nil {
                sensitiveIndexError = "没有可用的已验证恢复快照"
            }
            return plan
        } catch {
            sensitiveIndexError = "无法生成恢复预览"
            return nil
        }
    }

    func catalogRestoreRecovery(_ plan: CatalogRecoveryPlan) async -> Bool {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法恢复目录"
            return false
        }
        do {
            let result = try await appControlClient.catalogRestoreRecovery(plan)
            if result.status == .found {
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
                return true
            }
            sensitiveIndexError = "敏感信息目录恢复未完成"
            return false
        } catch {
            sensitiveIndexError = "敏感信息目录恢复失败、已取消或版本已变化"
            return false
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
        // Explicit directory picking: the App never silently overwrites an
        // existing 敏感信息.md, and the target file is always created through
        // the Catalog Store's journaled transaction.
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.message = "选择要新建敏感信息.md 的文件夹"
        panel.prompt = "选择位置"

        guard panel.runModal() == .OK, let directory = panel.url else {
            return
        }
        Task { await createSensitiveCatalogTemplate(in: directory) }
    }

    /// Creates a canonical empty 敏感信息.md through the Catalog Store,
    /// establishes its accepted integrity state, and selects it as the active
    /// catalog. Existing files are never overwritten.
    private func createSensitiveCatalogTemplate(in directory: URL) async {
        guard let sensitiveCatalogStore, let sensitiveIndexStore else {
            return
        }
        let target = directory.appendingPathComponent("敏感信息.md", isDirectory: false)
        if FileManager.default.fileExists(atPath: target.path) {
            presentExistingTargetDialog(for: target)
            return
        }

        let priorURL = await sensitiveIndexStore.selectedDocumentURL()
        do {
            try await sensitiveIndexStore.selectDocument(at: target)
            try await sensitiveCatalogStore.selectDocument(at: target)
            _ = try await sensitiveCatalogStore.createEmptyCatalog()
            SensitiveIndexSelectionStore.save(target)
            persistCatalogSelection(at: target)
            sensitiveIndexURL = target
            sensitiveIndexError = nil
            await refreshSensitiveIndex()
            await refreshSensitiveCatalog()
            await refreshSavedReferences()
            presentCatalogCreationSuccess()
        } catch {
            // Failure-atomic creation: restore the previous selection so no
            // half-created state is adopted.
            try? await sensitiveIndexStore.selectDocument(at: priorURL)
            try? await sensitiveCatalogStore.selectDocument(at: priorURL)
            sensitiveIndexError = "无法创建敏感信息目录"
            await refreshSensitiveIndex()
            await refreshSensitiveCatalog()
        }
    }

    @MainActor
    private func presentCatalogCreationSuccess() {
        let alert = NSAlert()
        alert.messageText = "已创建敏感信息.md"
        alert.informativeText = "已建立空白的 SVLT Catalog v3 目录，可直接在 Obsidian 中使用。"
        alert.addButton(withTitle: "好")
        alert.runModal()
    }

    /// Refuse to touch an existing target. A valid managed v3 catalog can be
    /// adopted as-is; anything else is left untouched for manual inspection.
    @MainActor
    private func presentExistingTargetDialog(for target: URL) {
        let data = (try? Data(contentsOf: target)) ?? Data()
        let report = SensitiveCatalogDocumentCodec.validateDetailed(data)
        let isValidCatalog = report.status == .found

        let alert = NSAlert()
        alert.messageText = "此位置已经存在敏感信息.md"
        if isValidCatalog {
            alert.informativeText = "该文件是有效的 SVLT 敏感信息目录。可以直接使用现有目录，SVLT 不会覆盖它。"
            alert.addButton(withTitle: "使用现有目录")
            alert.addButton(withTitle: "选择其他位置")
            alert.addButton(withTitle: "取消")
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                Task { await activateSensitiveIndex(at: target) }
            case .alertSecondButtonReturn:
                createSensitiveIndex()
            default:
                break
            }
        } else {
            alert.informativeText = "目标位置已有同名文件，但不是有效的 SVLT 敏感信息目录。为保护数据，SVLT 不会覆盖它。"
            alert.addButton(withTitle: "选择其他位置")
            alert.addButton(withTitle: "打开检查")
            alert.addButton(withTitle: "取消")
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                createSensitiveIndex()
            case .alertSecondButtonReturn:
                NSWorkspace.shared.open(target)
            default:
                break
            }
        }
    }

    private func activateSensitiveIndex(at url: URL) async {
        guard let sensitiveIndexStore else {
            return
        }
        let priorURL = await sensitiveIndexStore.selectedDocumentURL()

        do {
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw SensitiveCatalogDocumentStoreError.noSelectedDocument
            }
            try await sensitiveIndexStore.selectDocument(at: url)
            try await sensitiveCatalogStore?.selectDocument(at: url)
            SensitiveIndexSelectionStore.save(url)
            persistCatalogSelection(at: url)
            sensitiveIndexURL = url
            sensitiveIndexError = nil
            await refreshSensitiveIndex()
            await refreshSensitiveCatalog()
            await refreshSavedReferences()
        } catch {
            try? await sensitiveIndexStore.selectDocument(at: priorURL)
            try? await sensitiveCatalogStore?.selectDocument(at: priorURL)
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
        guard !ids.isEmpty, let agentClient else {
            return
        }

        let selected = sensitiveScanCandidates.filter { ids.contains($0.id) }
        let groupedByFile = Dictionary(grouping: selected) {
            $0.fileURL.standardizedFileURL
        }
        var failed = false

        for fileGroup in groupedByFile.values {
            guard let first = fileGroup.first else { continue }
            if first.fileURL.standardizedFileURL == sensitiveIndexURL?.standardizedFileURL {
                failed = true
                continue
            }

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
            } catch {
                failed = true
            }
        }

        await refreshSavedReferences()
        await scanSensitiveInformation()
        if failed {
            sensitiveScanError = "部分候选未写回：文件可能已修改，或 managed 敏感信息目录必须使用 Catalog 编辑器"
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

    private func makeSensitiveCatalogStore() throws -> SensitiveCatalogDocumentStore {
        let selectedScanTarget = SensitiveIndexSelectionStore.selectedScanRootURL()
        let selectedDocument = SensitiveIndexSelectionStore.selectedURL()
            ?? SensitiveInformationDocumentStore.defaultDocumentURL(scanTargetURL: selectedScanTarget)
        return SensitiveCatalogDocumentStore(documentURL: selectedDocument)
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
