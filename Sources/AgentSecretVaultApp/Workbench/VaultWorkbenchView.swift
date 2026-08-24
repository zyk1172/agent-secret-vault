import AppKit
import SwiftUI
import VaultCore
import VaultIPC
import VaultService

public enum VaultWorkbenchCopy {
    public static let documentationURL = URL(string: "https://github.com/zyk1172/svlt") ?? URL(fileURLWithPath: "/")

    public static let disconnected = (
        status: "Obsidian 插件未连接",
        primaryAction: "先安装并启用 Obsidian 插件。"
    )

    public static let securityBoundary =
        "临时解密只在本应用窗口显示，不会把明文返回给插件或智能体；还原写回 Obsidian 是显式操作，需要本机授权。"

    public static let simpleUsageSteps = [
        "1. 在 Obsidian 选中敏感文字，右键选择“加密选中敏感信息”。",
        "2. 选择纳入 SVLT 管理的秘密才使用 secret://；Codex、Claude、Hermes 会在出现引用时调用安全工具。用户也可以明确选择本次直接使用自己的明文。",
        "3. 需要查看整段时，在这里粘贴段落，点“解密整个段落”。"
    ]

    public static var mcpConfig: String {
        """
        {
          "mcpServers": {
            "SVLT": {
              "command": "/bin/zsh",
              "args": [
                "-lc",
                "exec node \\\"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\\\""
              ]
            }
          }
        }
        """
    }

    public static var agentPrompt: String {
        """
        SVLT 是 opt-in。看到 secret:// 或用户明确要求使用 SVLT 时，使用 SVLT；用户当前明确提供并要求使用的明文不受 SVLT 强制接管。
        不要把 SVLT 解密得到的明文交给普通 shell/curl；也不要把用户明确选择的明文自动转换成 secret://。

        \(SVLTAgentCatalogPolicy.text)
        """
    }

    public static let catalogPolicy = SVLTAgentCatalogPolicy.text
    public static let catalogSchema = SVLTAgentCatalogPolicy.schema
}

public struct CatalogMutationUIError: Error, Equatable, Sendable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    public var displayText: String { "\(message)（\(code)）" }
}

public typealias CatalogMutationUIResult = Result<CatalogWriteResult, CatalogMutationUIError>
public typealias CatalogEntryCreationError = CatalogMutationUIError
public typealias CatalogEntryCreationResult = CatalogMutationUIResult

public enum VaultWorkbenchRenderingPolicy {
    public static let usesStableRendering = true
    public static let usesRepeatingAnimations = false
    public static let usesTransientAnimations = true
    public static let usesBlurredBackgrounds = false
    public static let usesMaterialBackgrounds = false
}

public enum VaultWorkbenchMotion {
    public static let interactive = Animation.easeInOut(duration: 0.18)
}

public enum VaultWorkbenchSection: String, CaseIterable, Identifiable {
    case overview
    case paragraph
    case secrets
    case records
    case automation
    case security

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:
            return "控制台"
        case .paragraph:
            return "段落解密"
        case .secrets:
            return "敏感信息"
        case .records:
            return "本地扫描"
        case .automation:
            return "智能体自动化"
        case .security:
            return "安全边界"
        }
    }

    public var subtitle: String {
        switch self {
        case .overview:
            return "状态、快捷入口和最近动作"
        case .paragraph:
            return "一次解密段落内全部密文引用"
        case .secrets:
            return "集中索引与独立加密记录"
        case .records:
            return "本机规则候选与人工确认"
        case .automation:
            return "查看脱敏后的本机使用记录"
        case .security:
            return "哪些内容不会进入聊天"
        }
    }

    public var systemImage: String {
        switch self {
        case .overview:
            return "square.grid.2x2.fill"
        case .paragraph:
            return "text.quote"
        case .secrets:
            return "key.viewfinder"
        case .records:
            return "tray.full.fill"
        case .automation:
            return "sparkles.rectangle.stack.fill"
        case .security:
            return "lock.shield.fill"
        }
    }
}

public extension Notification.Name {
    static let vaultWorkbenchNavigate = Notification.Name("AgentSecretVaultWorkbenchNavigate")
}

public struct VaultWorkbenchView: View {
    let status: WorkbenchStatus
    let agentServiceStatus: AgentServiceStatus
    let agentServiceActionInFlight: Bool
    let agentServiceActionErrorMessage: String?
    let enableAgentService: (() async -> Void)?
    let disableAgentService: (() async -> Void)?
    let restartAgentService: (() async -> Void)?
    let orphanScanResult: OrphanScanResult?
    let auditEntries: [AgentAutomationAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let sensitiveIndexURL: URL?
    let sensitiveIndexEntries: [SensitiveInformationDocumentReference]
    let sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    let sensitiveCatalogError: String?
    let sensitiveCatalogCanAdoptV2: Bool
    let catalogAgentWriteStatus: CatalogAgentWriteAuthorizationStatus
    let catalogAgentWriteError: String?
    let sensitiveScanRootURL: URL?
    let sensitiveScanCandidates: [LocalSensitiveInformationCandidate]
    let sensitiveScanRules: [SensitiveScanRuleDefinition]
    let restoreParagraph: ((String) async throws -> RestoredParagraph)?
    let refreshSavedReferences: (() async -> Void)?
    let chooseSensitiveIndex: (() -> Void)?
    let createSensitiveIndex: (() -> Void)?
    let refreshSensitiveIndex: (() async -> Void)?
    let refreshSensitiveCatalog: (() async -> Void)?
    let validateSensitiveCatalog: (() async -> Void)?
    let adoptExternalV2Catalog: (() async -> Void)?
    let createCatalogIndex: ((String) async -> CatalogMutationUIResult)?
    let createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let updateCatalogEntry: ((SecretCatalogEntry) async -> CatalogMutationUIResult)?
    let fillCatalogSecret: ((String, String, String, String) async -> String?)?
    let enableCatalogAgentWrite: ((CatalogAgentWriteMode) async -> Void)?
    let revokeCatalogAgentWrite: (() async -> Void)?
    let chooseSensitiveScanRoot: (() -> Void)?
    let scanSensitiveInformation: (() async -> Void)?
    let encryptSensitiveCandidates: ((Set<String>) async -> Void)?
    let ignoreSensitiveCandidates: ((Set<String>) async -> Void)?
    let jumpToSensitiveCandidate: ((LocalSensitiveInformationCandidate) -> Void)?
    let deleteSensitiveCandidate: ((LocalSensitiveInformationCandidate) async -> Void)?
    let addSensitiveScanRule: ((SensitiveScanRuleDefinition) -> Void)?
    let removeSensitiveScanRule: ((String) -> Void)?
    @State private var selectedSection: VaultWorkbenchSection = .overview

    public init(
        status: WorkbenchStatus,
        agentServiceStatus: AgentServiceStatus = .unavailable,
        agentServiceActionInFlight: Bool = false,
        agentServiceActionErrorMessage: String? = nil,
        enableAgentService: (() async -> Void)? = nil,
        disableAgentService: (() async -> Void)? = nil,
        restartAgentService: (() async -> Void)? = nil,
        orphanScanResult: OrphanScanResult? = nil,
        auditEntries: [AgentAutomationAuditEntry] = [],
        savedReferences: [SecretReferenceMetadata] = [],
        sensitiveIndexURL: URL? = nil,
        sensitiveIndexEntries: [SensitiveInformationDocumentReference] = [],
        sensitiveCatalogSnapshot: SensitiveCatalogSnapshot? = nil,
        sensitiveCatalogError: String? = nil,
        sensitiveCatalogCanAdoptV2: Bool = false,
        catalogAgentWriteStatus: CatalogAgentWriteAuthorizationStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled),
        catalogAgentWriteError: String? = nil,
        sensitiveScanRootURL: URL? = nil,
        sensitiveScanCandidates: [LocalSensitiveInformationCandidate] = [],
        sensitiveScanRules: [SensitiveScanRuleDefinition] = SensitiveScanRuleDefinition.defaults,
        restoreParagraph: ((String) async throws -> RestoredParagraph)? = nil,
        refreshSavedReferences: (() async -> Void)? = nil,
        chooseSensitiveIndex: (() -> Void)? = nil,
        createSensitiveIndex: (() -> Void)? = nil,
        refreshSensitiveIndex: (() async -> Void)? = nil,
        refreshSensitiveCatalog: (() async -> Void)? = nil,
        validateSensitiveCatalog: (() async -> Void)? = nil,
        adoptExternalV2Catalog: (() async -> Void)? = nil,
        createCatalogIndex: ((String) async -> CatalogMutationUIResult)? = nil,
        createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)? = nil,
        updateCatalogEntry: ((SecretCatalogEntry) async -> CatalogMutationUIResult)? = nil,
        fillCatalogSecret: ((String, String, String, String) async -> String?)? = nil,
        enableCatalogAgentWrite: ((CatalogAgentWriteMode) async -> Void)? = nil,
        revokeCatalogAgentWrite: (() async -> Void)? = nil,
        chooseSensitiveScanRoot: (() -> Void)? = nil,
        scanSensitiveInformation: (() async -> Void)? = nil,
        encryptSensitiveCandidates: ((Set<String>) async -> Void)? = nil,
        ignoreSensitiveCandidates: ((Set<String>) async -> Void)? = nil,
        jumpToSensitiveCandidate: ((LocalSensitiveInformationCandidate) -> Void)? = nil,
        deleteSensitiveCandidate: ((LocalSensitiveInformationCandidate) async -> Void)? = nil,
        addSensitiveScanRule: ((SensitiveScanRuleDefinition) -> Void)? = nil,
        removeSensitiveScanRule: ((String) -> Void)? = nil
    ) {
        self.status = status
        self.agentServiceStatus = agentServiceStatus
        self.agentServiceActionInFlight = agentServiceActionInFlight
        self.agentServiceActionErrorMessage = agentServiceActionErrorMessage
        self.enableAgentService = enableAgentService
        self.disableAgentService = disableAgentService
        self.restartAgentService = restartAgentService
        self.orphanScanResult = orphanScanResult
        self.auditEntries = auditEntries
        self.savedReferences = savedReferences
        self.sensitiveIndexURL = sensitiveIndexURL
        self.sensitiveIndexEntries = sensitiveIndexEntries
        self.sensitiveCatalogSnapshot = sensitiveCatalogSnapshot
        self.sensitiveCatalogError = sensitiveCatalogError
        self.sensitiveCatalogCanAdoptV2 = sensitiveCatalogCanAdoptV2
        self.catalogAgentWriteStatus = catalogAgentWriteStatus
        self.catalogAgentWriteError = catalogAgentWriteError
        self.sensitiveScanRootURL = sensitiveScanRootURL
        self.sensitiveScanCandidates = sensitiveScanCandidates
        self.sensitiveScanRules = sensitiveScanRules
        self.restoreParagraph = restoreParagraph
        self.refreshSavedReferences = refreshSavedReferences
        self.chooseSensitiveIndex = chooseSensitiveIndex
        self.createSensitiveIndex = createSensitiveIndex
        self.refreshSensitiveIndex = refreshSensitiveIndex
        self.refreshSensitiveCatalog = refreshSensitiveCatalog
        self.validateSensitiveCatalog = validateSensitiveCatalog
        self.adoptExternalV2Catalog = adoptExternalV2Catalog
        self.createCatalogIndex = createCatalogIndex
        self.createCatalogEntry = createCatalogEntry
        self.updateCatalogEntry = updateCatalogEntry
        self.fillCatalogSecret = fillCatalogSecret
        self.enableCatalogAgentWrite = enableCatalogAgentWrite
        self.revokeCatalogAgentWrite = revokeCatalogAgentWrite
        self.chooseSensitiveScanRoot = chooseSensitiveScanRoot
        self.scanSensitiveInformation = scanSensitiveInformation
        self.encryptSensitiveCandidates = encryptSensitiveCandidates
        self.ignoreSensitiveCandidates = ignoreSensitiveCandidates
        self.jumpToSensitiveCandidate = jumpToSensitiveCandidate
        self.deleteSensitiveCandidate = deleteSensitiveCandidate
        self.addSensitiveScanRule = addSensitiveScanRule
        self.removeSensitiveScanRule = removeSensitiveScanRule
    }

    public var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            ZStack {
                WorkbenchBackground()
                selectedContent
                    .id(selectedSection)
                    .transaction { transaction in
                        transaction.animation = nil
                    }
            }
        }
        .navigationTitle(selectedSection.title)
        .frame(minWidth: 1080, minHeight: 720)
        .onReceive(NotificationCenter.default.publisher(for: .vaultWorkbenchNavigate)) { notification in
            guard
                let rawValue = notification.userInfo?["section"] as? String,
                let section = VaultWorkbenchSection(rawValue: rawValue)
            else {
                return
            }
            selectSection(section)
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 18) {
            sidebarHeader

            List(selection: $selectedSection) {
                Section("菜单") {
                    ForEach(VaultWorkbenchSection.allCases) { section in
                        Label(section.title, systemImage: section.systemImage)
                            .tag(section)
                    }
                }
            }
            .listStyle(.sidebar)

            SidebarStatusStrip(status: status)
                .padding(.horizontal, 14)
                .padding(.bottom, 8)
            AgentServiceStatusView(
                status: agentServiceStatus,
                actionInFlight: agentServiceActionInFlight,
                actionErrorMessage: agentServiceActionErrorMessage,
                enableAgent: enableAgentService,
                disableAgent: disableAgentService,
                restartAgent: restartAgentService
            )
                .padding(.horizontal, 14)
                .padding(.bottom, 14)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationSplitViewColumnWidth(min: 220, ideal: 250, max: 300)
    }

    private var sidebarHeader: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 42, height: 42)
                .background(
                    LinearGradient(colors: [.blue, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing),
                    in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                )

            VStack(alignment: .leading, spacing: 6) {
                Text("知识库密文保险箱")
                    .font(.headline.weight(.semibold))
                Text("本机解密，智能体只拿引用")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.top, 18)
    }

    @ViewBuilder
    private var selectedContent: some View {
        switch selectedSection {
        case .overview:
            WorkbenchPage(title: "控制台", subtitle: "状态、常用动作和最近记录", systemImage: selectedSection.systemImage, compact: true) {
                overviewPage
            }
        case .paragraph:
            WorkbenchPage(title: "段落解密", subtitle: "把包含 secret:// 的整段内容粘贴进来，一次还原其中全部密文。", systemImage: selectedSection.systemImage) {
                if let restoreParagraph {
                    ParagraphRestoreView(restoreParagraph: restoreParagraph)
                } else {
                    ContentUnavailableView("段落解密暂不可用", systemImage: "lock.trianglebadge.exclamationmark", description: Text("本机服务启动完成后会启用这个功能。"))
                        .frame(maxWidth: .infinity, minHeight: 240)
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                }
            }
        case .secrets:
            WorkbenchPage(title: "敏感信息", subtitle: "Index → Entry → Field 结构化目录；Markdown 只作为人类可读表现。", systemImage: selectedSection.systemImage) {
                VStack(spacing: 14) {
                    SensitiveCatalogEditorCard(
                        snapshot: sensitiveCatalogSnapshot,
                        errorMessage: sensitiveCatalogError,
                        canAdoptExternalV2: sensitiveCatalogCanAdoptV2,
                        adoptExternalV2: adoptExternalV2Catalog,
                        refresh: refreshSensitiveCatalog,
                        createIndex: createCatalogIndex,
                        createEntry: createCatalogEntry,
                        updateEntry: updateCatalogEntry,
                        fillSecret: fillCatalogSecret,
                        enableAgentWrite: enableCatalogAgentWrite,
                        revokeAgentWrite: revokeCatalogAgentWrite
                    )
                    SensitiveIndexLibraryCard(
                        indexURL: sensitiveIndexURL,
                        entries: sensitiveIndexEntries,
                        chooseIndex: chooseSensitiveIndex,
                        createIndex: createSensitiveIndex,
                        refresh: refreshSensitiveIndex
                    )
                }
            }
        case .records:
            WorkbenchPage(title: "本地扫描", subtitle: "按本机规则找出候选；不会自动加密或写回。", systemImage: selectedSection.systemImage) {
                LocalSensitiveScanCard(
                    scanRootURL: sensitiveScanRootURL,
                    candidates: sensitiveScanCandidates,
                    rules: sensitiveScanRules,
                    chooseRoot: chooseSensitiveScanRoot,
                    rescan: scanSensitiveInformation,
                    encrypt: encryptSensitiveCandidates,
                    ignore: ignoreSensitiveCandidates,
                    jump: jumpToSensitiveCandidate,
                    delete: deleteSensitiveCandidate,
                    addRule: addSensitiveScanRule,
                    removeRule: removeSensitiveScanRule
                )
            }
        case .automation:
            WorkbenchPage(title: "智能体自动化", subtitle: "只显示脱敏审计。密码、token、Authorization header 不会进入这里。", systemImage: selectedSection.systemImage) {
                VStack(spacing: 14) {
                    SensitiveCatalogPolicyCard(
                        validate: validateSensitiveCatalog,
                        writeStatus: catalogAgentWriteStatus,
                        writeError: catalogAgentWriteError,
                        enableAgentWrite: enableCatalogAgentWrite,
                        revokeAgentWrite: revokeCatalogAgentWrite
                    )
                    AgentAutomationAuditCard(entries: auditEntries)
                }
            }
        case .security:
            WorkbenchPage(title: "安全边界", subtitle: "明确哪些动作允许、哪些动作必须由本机授权。", systemImage: selectedSection.systemImage) {
                SecurityBoundaryPanel()
            }
        }
    }

    private var overviewPage: some View {
        VStack(alignment: .leading, spacing: 12) {
            OverviewStatusStrip(status: status)

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 12),
                GridItem(.flexible(), spacing: 12),
                GridItem(.flexible(), spacing: 12),
                GridItem(.flexible(), spacing: 12)
            ], spacing: 12) {
                QuickMenuCard(
                    title: "GitHub 文档",
                    detail: "安装、Obsidian 插件、MCP 配置和完整教程放在仓库文档里，App 内只保留日常操作。",
                    systemImage: "arrow.up.right.square.fill",
                    tint: .blue,
                    actionTitle: "打开 GitHub",
                    compact: true
                ) {
                    NSWorkspace.shared.open(VaultWorkbenchCopy.documentationURL)
                }
                QuickMenuCard(
                    title: "段落解密",
                    detail: "一段话里有多个 secret:// 时，在这里一次性解密显示。",
                    systemImage: "text.quote",
                    tint: .purple,
                    actionTitle: "打开解密",
                    compact: true
                ) {
                    selectSection(.paragraph)
                }
                QuickMenuCard(
                    title: "密文库",
                    detail: "查看本机已保存的 secret:// 引用，复制后可直接给 agent 或笔记使用。",
                    systemImage: "key.viewfinder",
                    tint: .green,
                    actionTitle: "打开密文库",
                    compact: true
                ) {
                    selectSection(.secrets)
                }
                QuickMenuCard(
                    title: "记录维护",
                    detail: "检查笔记引用和本机记录是否匹配，避免孤立密文或失效引用。",
                    systemImage: "tray.full.fill",
                    tint: .orange,
                    actionTitle: "查看维护",
                    compact: true
                ) {
                    selectSection(.records)
                }
            }

            CompactAuditPreviewCard(entries: Array(auditEntries.prefix(2)))
        }
    }

    private func selectSection(_ section: VaultWorkbenchSection) {
        withAnimation(VaultWorkbenchMotion.interactive) {
            selectedSection = section
        }
    }
}

private struct WorkbenchBackground: View {
    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor)
            LinearGradient(
                colors: [
                    Color.blue.opacity(0.08),
                    Color.purple.opacity(0.04),
                    Color.clear
                ],
                startPoint: .topTrailing,
                endPoint: .bottomLeading
            )
        }
        .ignoresSafeArea()
    }
}

private struct WorkbenchPage<Content: View>: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let compact: Bool
    @ViewBuilder let content: Content

    init(
        title: String,
        subtitle: String,
        systemImage: String,
        compact: Bool = false,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.compact = compact
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: compact ? 12 : 20) {
                HStack(alignment: .center, spacing: 16) {
                    Image(systemName: systemImage)
                        .font(.system(size: compact ? 20 : 28, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: compact ? 40 : 54, height: compact ? 40 : 54)
                        .background(
                            LinearGradient(colors: [.blue, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing),
                            in: RoundedRectangle(cornerRadius: compact ? 13 : 18, style: .continuous)
                        )

                    VStack(alignment: .leading, spacing: 5) {
                        Text(title)
                            .font(compact ? .title.weight(.bold) : .largeTitle.weight(.bold))
                        Text(subtitle)
                            .font(compact ? .callout : .title3)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(.top, compact ? 0 : 4)

                content
            }
            .padding(compact ? 22 : 30)
        }
        .scrollIndicators(.automatic)
    }
}

private struct OverviewStatusStrip: View {
    let status: WorkbenchStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                OverviewMetricTile(
                    title: "插件",
                    value: status.pluginConnected ? "已连接" : "未连接",
                    systemImage: status.pluginConnected ? "checkmark.seal.fill" : "exclamationmark.triangle.fill",
                    tint: status.pluginConnected ? .green : .orange
                )
                OverviewMetricTile(
                    title: "策略引擎",
                    value: status.approvalPending ? "待审批" : (status.ready ? "已就绪" : "不可用"),
                    systemImage: status.approvalPending ? "person.badge.key.fill" : (status.ready ? "checkmark.shield.fill" : "exclamationmark.shield.fill"),
                    tint: status.approvalPending ? .orange : (status.ready ? .blue : .red)
                )
                OverviewMetricTile(
                    title: "本机通道",
                    value: status.ipcAvailable ? "可用" : "未就绪",
                    systemImage: status.ipcAvailable ? "bolt.horizontal.circle.fill" : "bolt.slash.circle.fill",
                    tint: status.ipcAvailable ? .green : .orange
                )
            }

            HStack(spacing: 10) {
                Label("知识库位置", systemImage: "folder")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(status.activeKnowledgeBaseRoot ?? "尚未选择")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.blue.opacity(0.18))
        )
    }
}

private struct OverviewMetricTile: View {
    let title: String
    let value: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 12) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 22, weight: .bold, design: .rounded))
            }
            Spacer()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct QuickMenuCard: View {
    let title: String
    let detail: String
    let systemImage: String
    let tint: Color
    let actionTitle: String
    var compact = false
    let action: () -> Void
    @State private var isHovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 8 : 14) {
            Image(systemName: systemImage)
                .font(.system(size: compact ? 18 : 24, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: compact ? 34 : 46, height: compact ? 34 : 46)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: compact ? 10 : 14, style: .continuous))

            Text(title)
                .font(compact ? .headline.weight(.semibold) : .title3.weight(.semibold))
            Text(detail)
                .font(compact ? .caption : .callout)
                .foregroundStyle(.secondary)
                .lineLimit(compact ? 2 : 3)

            Spacer(minLength: 0)

            Button(actionTitle, action: action)
                .buttonStyle(.borderedProminent)
        }
        .padding(compact ? 14 : 20)
        .frame(maxWidth: .infinity, minHeight: compact ? 146 : 210, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: compact ? 18 : 22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: compact ? 18 : 22, style: .continuous)
                .stroke(isHovering ? tint.opacity(0.35) : Color.secondary.opacity(0.12))
        )
        .scaleEffect(isHovering ? 1.015 : 1)
        .onHover { isHovering = $0 }
        .animation(VaultWorkbenchMotion.interactive, value: isHovering)
    }
}

private struct CompactAuditPreviewCard: View {
    let entries: [AgentAutomationAuditEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("最近自动化", systemImage: "sparkles.rectangle.stack")
                    .font(.headline.weight(.semibold))
                Spacer()
                Text(entries.isEmpty ? "暂无记录" : "最近 \(entries.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            if entries.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "clock.badge.questionmark")
                        .foregroundStyle(.secondary)
                    Text("连接 MCP 后，解密显示、段落还原、本地导出等脱敏记录会出现在这里。")
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 6) {
                    ForEach(entries) { entry in
                        HStack(spacing: 8) {
                            Image(systemName: iconName(for: entry.action))
                                .foregroundStyle(.blue)
                                .frame(width: 18)
                            Text(entry.action)
                                .font(.callout.weight(.semibold))
                                .lineLimit(1)
                            Text(entry.target)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            Spacer()
                            Text(entry.result)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 10)
                        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func iconName(for action: String) -> String {
        if action.contains("文件") {
            return "doc.badge.gearshape"
        }
        if action.contains("显示") {
            return "eye"
        }
        if action.contains("扫描") {
            return "magnifyingglass"
        }
        if action.contains("连接") {
            return "cable.connector"
        }
        return "bolt.horizontal.circle"
    }
}

private struct SidebarStatusStrip: View {
    let status: WorkbenchStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(status.ipcAvailable ? "本机通道可用" : "本机通道未就绪", systemImage: status.ipcAvailable ? "bolt.horizontal.circle.fill" : "bolt.slash.circle.fill")
                .foregroundStyle(status.ipcAvailable ? .green : .orange)
            Label(status.approvalPending ? "等待本机审批" : (status.ready ? "策略引擎已就绪" : "策略引擎不可用"), systemImage: status.approvalPending ? "person.badge.key.fill" : (status.ready ? "checkmark.shield.fill" : "exclamationmark.shield.fill"))
                .foregroundStyle(status.approvalPending ? Color.orange : (status.ready ? Color.blue : Color.red))
        }
        .font(.caption.weight(.medium))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private struct SensitiveIndexLibraryCard: View {
    let indexURL: URL?
    let entries: [SensitiveInformationDocumentReference]
    let chooseIndex: (() -> Void)?
    let createIndex: (() -> Void)?
    let refresh: (() async -> Void)?
    @State private var copiedReference: String?
    @State private var isRefreshing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Label("目录文件选择", systemImage: "doc.badge.lock")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("\(entries.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                if let refresh, indexURL != nil {
                    Button {
                        Task {
                            isRefreshing = true
                            await refresh()
                            isRefreshing = false
                        }
                    } label: {
                        Label("刷新", systemImage: "arrow.clockwise")
                    }
                    .disabled(isRefreshing)
                }
            }

            if let indexURL {
                HStack(spacing: 8) {
                    Image(systemName: "folder")
                        .foregroundStyle(.secondary)
                    Text(indexURL.path)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("更换文件") { chooseIndex?() }
                        .buttonStyle(.bordered)
                }
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

                if entries.isEmpty {
                    ContentUnavailableView(
                        "由结构化目录管理",
                        systemImage: "doc.text",
                        description: Text("v2 Index/Entry 内容由上方结构化编辑器显示；旧版目录不支持自动升级，请手动转换后再由 SVLT 接管。")
                    )
                    .frame(maxWidth: .infinity, minHeight: 170)
                } else {
                    VStack(spacing: 8) {
                        ForEach(entries) { entry in
                            SensitiveIndexRow(entry: entry, copiedReference: copiedReference) { reference in
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(reference, forType: .string)
                                withAnimation(VaultWorkbenchMotion.interactive) {
                                    copiedReference = reference
                                }
                            }
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "选择敏感信息.md",
                    systemImage: "folder.badge.questionmark",
                    description: Text("此文件是加密记录唯一来源。可选择现有索引，或在任意路径新建。")
                )
                .frame(maxWidth: .infinity, minHeight: 170)

                HStack {
                    Button("选择文件") { chooseIndex?() }
                        .buttonStyle(.bordered)
                    Button("新建索引") { createIndex?() }
                        .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct SensitiveCatalogEditorCard: View {
    let snapshot: SensitiveCatalogSnapshot?
    let errorMessage: String?
    let canAdoptExternalV2: Bool
    let adoptExternalV2: (() async -> Void)?
    let refresh: (() async -> Void)?
    let createIndex: ((String) async -> CatalogMutationUIResult)?
    let createEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let updateEntry: ((SecretCatalogEntry) async -> CatalogMutationUIResult)?
    let fillSecret: ((String, String, String, String) async -> String?)?
    let enableAgentWrite: ((CatalogAgentWriteMode) async -> Void)?
    let revokeAgentWrite: (() async -> Void)?

    @State private var newIndexTitle = ""
    @State private var addingEntryToIndexID: String?
    @State private var newEntryTitle = ""
    @State private var selectedPresetID = SensitiveCatalogEntryPreset.all.first?.id ?? "credential"
    @State private var isWorking = false
    @State private var createIndexError: CatalogMutationUIError?
    @State private var createEntryError: CatalogEntryCreationError?
    @State private var newlyCreatedEntryID: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Label("结构化目录", systemImage: "list.bullet.indent")
                    .font(.title3.weight(.semibold))
                Spacer()
                if let refresh {
                    Button {
                        Task {
                            isWorking = true
                            await refresh()
                            isWorking = false
                        }
                    } label: {
                        Label("验证并刷新", systemImage: "checkmark.shield")
                    }
                    .disabled(isWorking)
                }
            }

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            }

            if snapshot == nil, canAdoptExternalV2, let adoptExternalV2 {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.blue)
                        Text("接管外部 v2 文件")
                            .font(.headline)
                        Spacer()
                        Button("验证并接管 v2 文件") {
                            Task {
                                isWorking = true
                                await adoptExternalV2()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 将严格解析当前 v2 文件，先备份，再 canonicalize 并建立完整性记录。旧版文件不支持自动升级，接管失败时原文件保持不变。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            } else if snapshot == nil, errorMessage?.contains("旧版格式") == true {
                Label("旧版目录不支持自动升级。请先备份文件，再手动转换为 Catalog v2。", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let snapshot {
                HStack(spacing: 8) {
                    Text("revision \(snapshot.revision)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Label("完整性已验证", systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                    Spacer()
                    Text("Index \(snapshot.document.indexes.count) · Entry \(snapshot.document.entries.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 8) {
                    TextField("新增一级索引，例如 QNAP", text: $newIndexTitle)
                        .textFieldStyle(.roundedBorder)
                    Button("新增一级索引") {
                        let title = newIndexTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !title.isEmpty else { return }
                        Task {
                            isWorking = true
                            let result = await createIndex?(title)
                            switch result {
                            case .success:
                                newIndexTitle = ""
                                createIndexError = nil
                            case .failure(let error):
                                createIndexError = error
                            case nil:
                                createIndexError = CatalogMutationUIError(
                                    code: "APP_CONTROL_UNAVAILABLE",
                                    message: "App-control 不可用，无法新增一级索引"
                                )
                            }
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || createIndex == nil)
                }
                if let createIndexError {
                    Label(createIndexError.displayText, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.leading, 4)
                }

                if snapshot.document.indexes.isEmpty {
                    ContentUnavailableView(
                        "还没有一级索引",
                        systemImage: "folder.badge.plus",
                        description: Text("先创建 QNAP、Komga 或其他服务的一级索引。")
                    )
                    .frame(maxWidth: .infinity, minHeight: 120)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(snapshot.document.indexes, id: \.id) { index in
                            let entries = snapshot.document.entries.filter { $0.indexId == index.id }
                            VStack(alignment: .leading, spacing: 8) {
                                HStack(spacing: 8) {
                                    Image(systemName: "folder.fill")
                                        .foregroundStyle(.blue)
                                    Text(index.title)
                                        .font(.headline)
                                    if !index.aliases.isEmpty {
                                        Text(index.aliases.joined(separator: "、"))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Button("新增 Entry") {
                                        addingEntryToIndexID = index.id
                                        newEntryTitle = ""
                                        createEntryError = nil
                                        newlyCreatedEntryID = nil
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                }

                                if addingEntryToIndexID == index.id {
                                    HStack(spacing: 8) {
                                        TextField("子索引标题，例如管理后台登录", text: $newEntryTitle)
                                            .textFieldStyle(.roundedBorder)
                                        Picker("预设", selection: $selectedPresetID) {
                                            ForEach(SensitiveCatalogEntryPreset.all) { preset in
                                                Text(preset.title).tag(preset.id)
                                            }
                                        }
                                        .frame(width: 150)
                                        .help("预设只决定创建后的第一个字段，其余字段可在编辑器中按需添加")
                                        Button("创建") {
                                            let title = newEntryTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                                            guard !title.isEmpty else { return }
                                            Task {
                                                isWorking = true
                                                createEntryError = nil
                                                let result = await createEntry?(index.id, title, selectedPresetID)
                                                switch result {
                                                case .success(let writeResult):
                                                    newlyCreatedEntryID = writeResult.entry?.id
                                                    addingEntryToIndexID = nil
                                                    newEntryTitle = ""
                                                case .failure(let error):
                                                    createEntryError = error
                                                case nil:
                                                    createEntryError = CatalogEntryCreationError(
                                                        code: "APP_CONTROL_UNAVAILABLE",
                                                        message: "App-control 不可用，无法新增 Entry"
                                                    )
                                                }
                                                isWorking = false
                                            }
                                        }
                                        .buttonStyle(.borderedProminent)
                                        .disabled(isWorking || createEntry == nil)
                                    Button("取消") {
                                        addingEntryToIndexID = nil
                                        createEntryError = nil
                                    }
                                        .buttonStyle(.bordered)
                                    }
                                    if let createEntryError {
                                        Label(createEntryError.displayText, systemImage: "exclamationmark.triangle.fill")
                                            .font(.caption)
                                            .foregroundStyle(.orange)
                                            .padding(.leading, 4)
                                    }
                                }

                                if entries.isEmpty {
                                    Text("暂无 Entry")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .padding(.leading, 28)
                                } else {
                                    ForEach(entries, id: \.id) { entry in
                                        SensitiveCatalogEntryRow(
                                            entry: entry,
                                            autoEdit: newlyCreatedEntryID == entry.id,
                                            updateEntry: updateEntry,
                                            fillSecret: fillSecret
                                        )
                                    }
                                }
                            }
                            .padding(12)
                            .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        }
                    }
                }
            } else if errorMessage == nil {
                Text("选择或新建敏感信息.md 后，SVLT 会在这里显示 Index → Entry → Field 树。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct SensitiveCatalogEntryRow: View {
    let entry: SecretCatalogEntry
    let autoEdit: Bool
    let updateEntry: ((SecretCatalogEntry) async -> CatalogMutationUIResult)?
    let fillSecret: ((String, String, String, String) async -> String?)?

    @State private var editing = false
    @State private var draftTitle: String
    @State private var draftAliases: String
    @State private var draftTags: String
    @State private var draftEndpoints: String
    @State private var draftNotes: String
    @State private var draftFields: [SecretCatalogFieldValue]
    @State private var pendingSecretInputs: [String: String] = [:]
    @State private var isSaving = false
    @State private var editorError: String?
    @State private var expanded: Bool

    init(
        entry: SecretCatalogEntry,
        autoEdit: Bool = false,
        updateEntry: ((SecretCatalogEntry) async -> CatalogMutationUIResult)?,
        fillSecret: ((String, String, String, String) async -> String?)?
    ) {
        self.entry = entry
        self.autoEdit = autoEdit
        self.updateEntry = updateEntry
        self.fillSecret = fillSecret
        _draftTitle = State(initialValue: entry.title)
        _draftAliases = State(initialValue: entry.aliases.joined(separator: ", "))
        _draftTags = State(initialValue: entry.tags.joined(separator: ", "))
        _draftEndpoints = State(initialValue: entry.endpoints.map(Self.endpointLine).joined(separator: "\n"))
        _draftNotes = State(initialValue: entry.notes ?? "")
        _draftFields = State(initialValue: entry.fields)
        _editing = State(initialValue: autoEdit)
        _expanded = State(initialValue: autoEdit)
    }

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 10) {
                if editing {
                    editorBody
                } else {
                    displayBody
                }
            }
            .padding(.top, 6)
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "key.horizontal")
                    .foregroundStyle(.green)
                Text(entry.title)
                    .font(.callout.weight(.semibold))
                if !entry.aliases.isEmpty {
                    Text(entry.aliases.joined(separator: "、"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(entry.id)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                Button(editing ? "取消" : "编辑") {
                    if editing {
                        load(entry)
                        editing = false
                    } else {
                        // Existing entries start collapsed.  Entering edit
                        // mode must reveal the editor; newly-created entries
                        // already use autoEdit and are expanded in init.
                        editing = true
                        // The button is inside the DisclosureGroup label. The
                        // group handles its own tap after the button action,
                        // so defer the expansion until that label event has
                        // finished; otherwise it immediately collapses again.
                        DispatchQueue.main.async {
                            expanded = true
                        }
                    }
                    editorError = nil
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private var displayBody: some View {
        VStack(alignment: .leading, spacing: 7) {
            ForEach(entry.fields, id: \.key) { field in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: field.type.isSecret ? "lock.fill" : "circle.fill")
                        .font(.caption2)
                        .foregroundStyle(field.type.isSecret ? .orange : .secondary)
                        .frame(width: 14)
                    Text(field.label)
                        .font(.caption.weight(.semibold))
                    Text(displayValue(field))
                        .font(.system(.caption, design: field.type.isSecret ? .monospaced : .default))
                        .foregroundStyle(field.type.isSecret ? .orange : .secondary)
                        .textSelection(.enabled)
                    Spacer()
                    if !field.agentVisible {
                        Text("Agent 隐藏")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    } else if field.searchable {
                        Text("可搜索")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            if let notes = entry.notes, !notes.isEmpty {
                Text(notes)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var editorBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Entry 标题", text: $draftTitle)
                .textFieldStyle(.roundedBorder)
            HStack(spacing: 8) {
                TextField("别名（逗号分隔）", text: $draftAliases)
                    .textFieldStyle(.roundedBorder)
                TextField("标签（逗号分隔）", text: $draftTags)
                    .textFieldStyle(.roundedBorder)
            }
            TextField("Endpoints：type|host|port，每行一个", text: $draftEndpoints, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
            TextEditor(text: $draftNotes)
                .font(.body)
                .frame(minHeight: 56, maxHeight: 100)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))

            HStack {
                Text("Fields")
                    .font(.headline)
                Spacer()
                Button("新增自定义字段") {
                    var number = draftFields.count + 1
                    var key = "field\(number)"
                    while draftFields.contains(where: { $0.key == key }) {
                        number += 1
                        key = "field\(number)"
                    }
                    draftFields.append(SecretCatalogFieldValue(key: key, label: "新字段", type: .text))
                }
                .buttonStyle(.bordered)
            }

            ForEach(draftFields, id: \.key) { field in
                SensitiveCatalogFieldEditorRow(
                    field: field,
                    entryID: entry.id,
                    fillSecret: fillSecret,
                    secretInput: Binding(
                        get: { pendingSecretInputs[field.key] ?? "" },
                        set: { value in
                            if value.isEmpty {
                                pendingSecretInputs.removeValue(forKey: field.key)
                            } else {
                                pendingSecretInputs[field.key] = value
                            }
                        }
                    ),
                    onUpdate: { updatedField in
                        if updatedField.key != field.key,
                           let pending = pendingSecretInputs.removeValue(forKey: field.key) {
                            pendingSecretInputs[updatedField.key] = pending
                        }
                        guard updatedField.key == field.key || !draftFields.contains(where: { $0.key == updatedField.key }) else {
                            editorError = "字段 key 已存在，请使用唯一名称"
                            return
                        }
                        guard let currentIndex = draftFields.firstIndex(where: { $0.key == field.key }) else { return }
                        draftFields[currentIndex] = updatedField
                    },
                    onDelete: {
                        pendingSecretInputs.removeValue(forKey: field.key)
                        guard let currentIndex = draftFields.firstIndex(where: { $0.key == field.key }) else { return }
                        draftFields.remove(at: currentIndex)
                    },
                    onMoveUp: {
                        guard let currentIndex = draftFields.firstIndex(where: { $0.key == field.key }), currentIndex > 0 else { return }
                        draftFields.swapAt(currentIndex, currentIndex - 1)
                    },
                    onMoveDown: {
                        guard let currentIndex = draftFields.firstIndex(where: { $0.key == field.key }), currentIndex + 1 < draftFields.count else { return }
                        draftFields.swapAt(currentIndex, currentIndex + 1)
                    }
                )
            }

            if let editorError {
                Text(editorError)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button(isSaving ? "保存中…" : "保存 Entry") {
                    saveEntry()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSaving || updateEntry == nil)
            }
        }
    }

    private func saveEntry() {
        let title = draftTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else {
            editorError = "Entry 标题不能为空"
            return
        }
        guard let endpoints = Self.parseEndpoints(draftEndpoints) else {
            editorError = "Endpoint 格式应为 type|host|port"
            return
        }
        let updated = SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: title,
            type: entry.type,
            aliases: Self.csv(draftAliases),
            endpoints: endpoints,
            fields: draftFields,
            notes: draftNotes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : draftNotes,
            tags: Self.csv(draftTags),
            schema: entry.schema
        )
        guard pendingSecretInputs.values.allSatisfy(\.isEmpty) else {
            editorError = "请先点击对应字段的“填写秘密”；未提交的输入不会写入目录"
            return
        }
        do {
            try SecretCatalogDocument(
                indexes: [SecretCatalogIndex(id: entry.indexId, title: "validation")],
                entries: [updated]
            ).validate()
        } catch {
            editorError = "字段数据无效，请检查字段 key、类型和值"
            return
        }
        Task {
            isSaving = true
            let result = await updateEntry?(updated)
            isSaving = false
            switch result {
            case .success:
                editing = false
                editorError = nil
                pendingSecretInputs.removeAll()
            case .failure(let error):
                editorError = error.displayText
            case nil:
                editorError = CatalogMutationUIError(
                    code: "APP_CONTROL_UNAVAILABLE",
                    message: "App-control 不可用，无法保存 Entry"
                ).displayText
            }
        }
    }

    private func load(_ value: SecretCatalogEntry) {
        draftTitle = value.title
        draftAliases = value.aliases.joined(separator: ", ")
        draftTags = value.tags.joined(separator: ", ")
        draftEndpoints = value.endpoints.map(Self.endpointLine).joined(separator: "\n")
        draftNotes = value.notes ?? ""
        draftFields = value.fields
        pendingSecretInputs.removeAll()
    }

    private func displayValue(_ field: SecretCatalogFieldValue) -> String {
        if field.type.isSecret { return field.secretRef ?? "待填写（仅在 SVLT 安全表单输入）" }
        guard field.agentVisible else { return "已隐藏" }
        guard let value = field.value else { return "未填写" }
        switch value {
        case .string(let value): return value
        case .number(let value): return String(value)
        case .boolean(let value): return value ? "是" : "否"
        case .list(let value): return value.joined(separator: ", ")
        }
    }

    private static func csv(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    private static func endpointLine(_ endpoint: CatalogEndpoint) -> String {
        let port = endpoint.port.map(String.init) ?? ""
        return "\(endpoint.type)|\(endpoint.host)|\(port)"
    }

    private static func parseEndpoints(_ value: String) -> [CatalogEndpoint]? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        var endpoints: [CatalogEndpoint] = []
        for line in trimmed.split(whereSeparator: \.isNewline).map(String.init) {
            let parts = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard parts.count >= 2 else { return nil }
            let type = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let host = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !type.isEmpty, !host.isEmpty else { return nil }
            let portText = parts.dropFirst(2).joined(separator: "|").trimmingCharacters(in: .whitespacesAndNewlines)
            guard portText.isEmpty || (Int(portText).map { (0...65_535).contains($0) } ?? false) else { return nil }
            endpoints.append(CatalogEndpoint(type: type, host: host, port: portText.isEmpty ? nil : Int(portText)))
        }
        return endpoints
    }
}

private struct SensitiveCatalogFieldEditorRow: View {
    let field: SecretCatalogFieldValue
    let entryID: String
    let fillSecret: ((String, String, String, String) async -> String?)?
    @Binding var secretInput: String
    let onUpdate: (SecretCatalogFieldValue) -> Void
    let onDelete: () -> Void
    let onMoveUp: () -> Void
    let onMoveDown: () -> Void

    @State private var draftKey: String
    @State private var draftLabel: String
    @State private var draftType: SecretCatalogFieldType
    @State private var draftText: String
    @State private var draftList: String
    @State private var draftBoolean: Bool
    @State private var draftAgentVisible: Bool
    @State private var draftSearchable: Bool
    @State private var isSavingSecret = false
    @State private var errorMessage: String?

    init(
        field: SecretCatalogFieldValue,
        entryID: String,
        fillSecret: ((String, String, String, String) async -> String?)?,
        secretInput: Binding<String>,
        onUpdate: @escaping (SecretCatalogFieldValue) -> Void,
        onDelete: @escaping () -> Void,
        onMoveUp: @escaping () -> Void,
        onMoveDown: @escaping () -> Void
    ) {
        self.field = field
        self.entryID = entryID
        self.fillSecret = fillSecret
        self._secretInput = secretInput
        self.onUpdate = onUpdate
        self.onDelete = onDelete
        self.onMoveUp = onMoveUp
        self.onMoveDown = onMoveDown
        _draftKey = State(initialValue: field.key)
        _draftLabel = State(initialValue: field.label)
        _draftType = State(initialValue: field.type)
        _draftText = State(initialValue: Self.stringValue(field.value))
        _draftList = State(initialValue: Self.listValue(field.value))
        _draftBoolean = State(initialValue: Self.boolValue(field.value))
        _draftAgentVisible = State(initialValue: field.agentVisible)
        _draftSearchable = State(initialValue: field.searchable)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 7) {
                TextField("key", text: $draftKey)
                    .textFieldStyle(.roundedBorder)
                TextField("字段标签", text: $draftLabel)
                    .textFieldStyle(.roundedBorder)
                Picker("类型", selection: $draftType) {
                    ForEach(SecretCatalogFieldType.allCases, id: \.self) { type in
                        Text(Self.typeName(type)).tag(type)
                    }
                }
                .frame(width: 135)
                Button(action: onMoveUp) { Image(systemName: "chevron.up") }
                    .buttonStyle(.borderless)
                Button(action: onMoveDown) { Image(systemName: "chevron.down") }
                    .buttonStyle(.borderless)
                Button(role: .destructive, action: onDelete) { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
            }

            if draftType.isSecret {
                HStack(spacing: 8) {
                    if let secretRef = field.secretRef {
                        Text(secretRef)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                        Text("已绑定；替换需要本机批准")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    } else {
                        SecureField("在 SVLT 安全表单中输入", text: $secretInput)
                            .textFieldStyle(.roundedBorder)
                        Button(isSavingSecret ? "保存中…" : "填写秘密") {
                            let plaintext = secretInput
                            Task {
                                isSavingSecret = true
                                if let fillSecret,
                                   let secretRef = await fillSecret(entryID, draftKey, draftLabel, plaintext) {
                                    // Keep the newly generated opaque reference in this
                                    // field's draft state. Saving another Entry metadata
                                    // change afterwards must not drop the secret just filled.
                                    onUpdate(SecretCatalogFieldValue(
                                        key: draftKey,
                                        label: draftLabel,
                                        type: .secret,
                                        agentVisible: draftAgentVisible,
                                        searchable: draftSearchable,
                                        secretRef: secretRef
                                    ))
                                }
                                secretInput = ""
                                isSavingSecret = false
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(secretInput.isEmpty || isSavingSecret || fillSecret == nil || draftKey.isEmpty)
                        Text("先点“填写秘密”，再保存 Entry")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                valueEditor
            }

            HStack(spacing: 12) {
                Toggle("Agent 可查看", isOn: $draftAgentVisible)
                Toggle("可搜索", isOn: $draftSearchable)
                Spacer()
                Button("应用字段") {
                    applyField()
                }
                .buttonStyle(.bordered)
            }
            if let errorMessage {
                Text(errorMessage)
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
        .padding(9)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    @ViewBuilder
    private var valueEditor: some View {
        switch draftType {
        case .multiline:
            TextEditor(text: $draftText)
                .frame(minHeight: 50, maxHeight: 90)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))
        case .boolean:
            Toggle("值", isOn: $draftBoolean)
        case .list:
            TextField("列表值（逗号分隔）", text: $draftList)
                .textFieldStyle(.roundedBorder)
        default:
            TextField(Self.typeName(draftType), text: $draftText)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func applyField() {
        let key = draftKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = draftLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty, !label.isEmpty else {
            errorMessage = "key 和字段标签不能为空"
            return
        }
        let value: SecretCatalogValue?
        switch draftType {
        case .boolean:
            value = .boolean(draftBoolean)
        case .list:
            value = .list(draftList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
        case .port:
            if draftText.isEmpty {
                value = nil
            } else {
                guard let port = Int(draftText), (0...65_535).contains(port) else {
                    errorMessage = "端口必须是 0 到 65535 的数字"
                    return
                }
                value = .number(Double(port))
            }
        case .number:
            guard draftText.isEmpty || Double(draftText) != nil else {
                errorMessage = "数字字段格式不正确"
                return
            }
            value = draftText.isEmpty ? nil : .number(Double(draftText) ?? 0)
        case .url:
            guard draftText.isEmpty || Self.isValidURL(draftText) else {
                errorMessage = "URL 格式不正确"
                return
            }
            value = draftText.isEmpty ? nil : .string(draftText)
        case .date:
            guard draftText.isEmpty || Self.isValidDate(draftText) else {
                errorMessage = "日期应为 YYYY-MM-DD 或 ISO 8601 格式"
                return
            }
            value = draftText.isEmpty ? nil : .string(draftText)
        case .secret:
            value = nil
        default:
            value = draftText.isEmpty ? nil : .string(draftText)
        }
        onUpdate(SecretCatalogFieldValue(
            key: key,
            label: label,
            type: draftType,
            agentVisible: draftAgentVisible,
            searchable: draftSearchable,
            value: draftType.isSecret ? nil : value,
            secretRef: draftType.isSecret ? field.secretRef : nil
        ))
        errorMessage = nil
    }

    private static func stringValue(_ value: SecretCatalogValue?) -> String {
        guard let value else { return "" }
        if case .string(let value) = value { return value }
        if case .number(let value) = value { return String(value) }
        return ""
    }

    private static func listValue(_ value: SecretCatalogValue?) -> String {
        if case .list(let value) = value { return value.joined(separator: ", ") }
        return ""
    }

    private static func boolValue(_ value: SecretCatalogValue?) -> Bool {
        if case .boolean(let value) = value { return value }
        return false
    }

    private static func isValidURL(_ value: String) -> Bool {
        guard let url = URL(string: value),
              let scheme = url.scheme,
              !scheme.isEmpty,
              let host = url.host,
              !host.isEmpty
        else {
            return false
        }
        return true
    }

    private static func isValidDate(_ value: String) -> Bool {
        if ISO8601DateFormatter().date(from: value) != nil {
            return true
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.date(from: value) != nil
    }

    private static func typeName(_ type: SecretCatalogFieldType) -> String {
        switch type {
        case .text: return "文本"
        case .multiline: return "多行文本"
        case .url: return "URL"
        case .host: return "Host"
        case .port: return "端口"
        case .number: return "数字"
        case .boolean: return "布尔"
        case .date: return "日期"
        case .list: return "列表"
        case .secret: return "秘密"
        }
    }
}

private struct SensitiveIndexRow: View {
    let entry: SensitiveInformationDocumentReference
    let copiedReference: String?
    let copyReference: (String) -> Void

    private var reference: String { entry.reference }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("REF")
                .font(.system(.caption, design: .monospaced).weight(.semibold))
                .foregroundStyle(.blue)
                .frame(width: 48, alignment: .leading)

            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(entry.title)
                        .font(.headline)
                    Text("引用")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(entry.source.filePath):\(entry.source.line)")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }

                Text(reference)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .foregroundStyle(.secondary)

                HStack {
                    Text("独立加密载荷")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Spacer()
                    Button(copiedReference == reference ? "已复制" : "复制引用") {
                        copyReference(reference)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(12)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private struct LocalSensitiveScanCard: View {
    let scanRootURL: URL?
    let candidates: [LocalSensitiveInformationCandidate]
    let rules: [SensitiveScanRuleDefinition]
    let chooseRoot: (() -> Void)?
    let rescan: (() async -> Void)?
    let encrypt: ((Set<String>) async -> Void)?
    let ignore: ((Set<String>) async -> Void)?
    let jump: ((LocalSensitiveInformationCandidate) -> Void)?
    let delete: ((LocalSensitiveInformationCandidate) async -> Void)?
    let addRule: ((SensitiveScanRuleDefinition) -> Void)?
    let removeRule: ((String) -> Void)?
    @State private var selectedIDs: Set<String> = []
    @State private var isWorking = false
    @State private var candidatePendingDeletion: LocalSensitiveInformationCandidate?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("本机规则候选", systemImage: "magnifyingglass")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("\(candidates.count) 项")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Button("选择 Markdown") { chooseRoot?() }
                    .buttonStyle(.bordered)
                if scanRootURL != nil {
                    Button("重新扫描") {
                        Task {
                            isWorking = true
                            await rescan?()
                            selectedIDs = []
                            isWorking = false
                        }
                    }
                    .buttonStyle(.bordered)
                    .disabled(isWorking)
                }
            }

            if let scanRootURL {
                Text(scanRootURL.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            } else {
                Text("可选择一个 .md 文件或文件夹。本机只生成候选，不会自动加密。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if candidates.isEmpty {
                ContentUnavailableView(
                    scanRootURL == nil ? "尚未选择 Markdown" : "没有候选",
                    systemImage: scanRootURL == nil ? "doc.badge.questionmark" : "checkmark.shield",
                    description: Text(scanRootURL == nil ? "选择文件或文件夹后显示可人工确认的候选。" : "已跳过含 secret:// 的段落和已忽略的候选。")
                )
                .frame(maxWidth: .infinity, minHeight: 170)
            } else {
                HStack {
                    Button(selectedIDs.count == candidates.count ? "取消全选" : "全选") {
                        selectedIDs = selectedIDs.count == candidates.count ? [] : Set(candidates.map(\.id))
                    }
                    .buttonStyle(.bordered)
                    Spacer()
                    Button("加密所选 \(selectedIDs.count) 项") {
                        let ids = selectedIDs
                        Task {
                            isWorking = true
                            await encrypt?(ids)
                            selectedIDs = []
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(selectedIDs.isEmpty || isWorking)
                }

                VStack(spacing: 10) {
                    ForEach(candidates) { candidate in
                        LocalSensitiveCandidateRow(
                            candidate: candidate,
                            selected: selectedIDs.contains(candidate.id)
                        ) { enabled in
                            if enabled {
                                selectedIDs.insert(candidate.id)
                            } else {
                                selectedIDs.remove(candidate.id)
                            }
                        } onIgnore: {
                            Task { await ignore?([candidate.id]) }
                        } onJump: {
                            jump?(candidate)
                        } onDelete: {
                            candidatePendingDeletion = candidate
                        }
                    }
                }
            }

            SensitiveRuleEditor(
                rules: rules,
                addRule: addRule,
                removeRule: removeRule
            )
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .alert("删除命中值？", isPresented: Binding(
            get: { candidatePendingDeletion != nil },
            set: { if !$0 { candidatePendingDeletion = nil } }
        ), presenting: candidatePendingDeletion) { candidate in
            Button("删除命中值", role: .destructive) {
                Task {
                    isWorking = true
                    await delete?(candidate)
                    isWorking = false
                    candidatePendingDeletion = nil
                }
            }
            Button("取消", role: .cancel) { candidatePendingDeletion = nil }
        } message: { candidate in
            Text("只删除 \(candidate.source.filePath) 第 \(candidate.source.line) 行的敏感值；不会删除整段正文或加密记录。")
        }
    }
}

private struct LocalSensitiveCandidateRow: View {
    let candidate: LocalSensitiveInformationCandidate
    let selected: Bool
    let setSelected: (Bool) -> Void
    let onIgnore: () -> Void
    let onJump: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Toggle("", isOn: Binding(get: { selected }, set: setSelected))
                .labelsHidden()
                .toggleStyle(.checkbox)

            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Text(candidate.title)
                        .font(.headline)
                    Text(candidate.rule)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(candidate.risk == .high ? .red : .orange)
                    Spacer()
                    Text("\(candidate.source.filePath):\(candidate.source.line)")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                highlightedParagraph
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

                Text("普通笔记中的命中值会被替换为 secret:// 引用；managed 敏感信息.md 不会由本地扫描直接写入。")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack(spacing: 8) {
                    Button("跳转") { onJump() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    Button("忽略") { onIgnore() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    Button("删除命中值", role: .destructive) { onDelete() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }
        }
        .padding(12)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private var highlightedParagraph: Text {
        guard let range = candidate.paragraph.range(of: candidate.matchedValue) else {
            return Text(candidate.paragraph)
        }
        return Text(candidate.paragraph[..<range.lowerBound])
            + Text(candidate.paragraph[range]).foregroundColor(.red)
            + Text(candidate.paragraph[range.upperBound...])
    }
}

private struct SensitiveRuleEditor: View {
    let rules: [SensitiveScanRuleDefinition]
    let addRule: ((SensitiveScanRuleDefinition) -> Void)?
    let removeRule: ((String) -> Void)?
    @State private var name = ""
    @State private var labels = ""
    @State private var category = "Custom"
    @State private var risk: SensitiveCandidateRisk = .medium

    private var customRules: [SensitiveScanRuleDefinition] {
        let defaultIDs = Set(SensitiveScanRuleDefinition.defaults.map(\.id))
        return rules.filter { !defaultIDs.contains($0.id) }
    }

    var body: some View {
        DisclosureGroup("识别规则（\(rules.count) 条）") {
            VStack(alignment: .leading, spacing: 12) {
                Text("默认规则已覆盖中英文名称、: / ：/ =、任意空格和常见引号或 Markdown 包裹。新增规则按“名称 + 冒号 + 明文”匹配。")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                ForEach(SensitiveScanRuleDefinition.defaults) { rule in
                    Text("\(rule.name)：\(rule.labels.joined(separator: "、"))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Divider()
                Text("新增规则")
                    .font(.headline)
                TextField("规则名称，例如 NAS 凭据", text: $name)
                TextField("名称或别名，用逗号分隔，例如 nas 密码,NAS Password", text: $labels)
                HStack {
                    TextField("分类", text: $category)
                    Picker("风险", selection: $risk) {
                        Text("高").tag(SensitiveCandidateRisk.high)
                        Text("中").tag(SensitiveCandidateRisk.medium)
                    }
                    .frame(width: 120)
                    Button("添加规则") {
                        let aliases = labels.split(whereSeparator: { $0 == "," || $0 == "，" || $0 == "\n" })
                            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                            .filter { !$0.isEmpty }
                        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !aliases.isEmpty else {
                            return
                        }
                        addRule?(SensitiveScanRuleDefinition(name: name, labels: aliases, category: category, risk: risk))
                        name = ""
                        labels = ""
                        category = "Custom"
                        risk = .medium
                    }
                    .buttonStyle(.borderedProminent)
                }

                if !customRules.isEmpty {
                    Divider()
                    ForEach(customRules) { rule in
                        HStack {
                            Text("\(rule.name)：\(rule.labels.joined(separator: "、"))")
                                .font(.caption)
                            Spacer()
                            Button("删除", role: .destructive) { removeRule?(rule.id) }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                    }
                }
            }
            .padding(.top, 10)
        }
    }
}

private struct SavedSecretReferencesCard: View {
    let references: [SecretReferenceMetadata]
    let refresh: (() async -> Void)?
    @State private var copiedReference: String?
    @State private var isRefreshing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                Label("已保存密文", systemImage: "key.viewfinder")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("共 \(references.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                if let refresh {
                    Button {
                        Task {
                            isRefreshing = true
                            await refresh()
                            isRefreshing = false
                        }
                    } label: {
                        Label("刷新", systemImage: "arrow.clockwise")
                    }
                    .disabled(isRefreshing)
                }
            }

            Text("这里保存使用过的敏感信息段落模板，只展示段落上下文和 secret:// 引用，不展示明文。复制后可直接交给 agent 或贴回笔记。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if references.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "tray")
                        .foregroundStyle(.secondary)
                    Text("还没有保存的密文。通过 Obsidian 插件加密敏感信息后，引用会出现在这里。")
                        .foregroundStyle(.secondary)
                }
                .font(.callout)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            } else {
                VStack(spacing: 10) {
                    ForEach(references, id: \.reference) { reference in
                        SavedSecretReferenceRow(
                            metadata: reference,
                            isCopied: copiedReference == reference.reference
                        ) { text in
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(text, forType: .string)
                            withAnimation(VaultWorkbenchMotion.interactive) {
                                copiedReference = reference.reference
                            }
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

private struct SavedSecretReferenceRow: View {
    let metadata: SecretReferenceMetadata
    let isCopied: Bool
    let copyText: (String) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.doc.fill")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(policyColor)
                .frame(width: 34, height: 34)
                .background(policyColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Text(SavedReferenceDisplay.title(for: metadata))
                        .font(.headline)
                        .lineLimit(1)
                    Text(policyLabel)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(policyColor)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(policyColor.opacity(0.10), in: Capsule())
                    Spacer()
                    Text(metadata.updatedAt.formatted(date: .numeric, time: .shortened))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                Text(SavedReferenceDisplay.text(for: metadata))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

                HStack {
                    Text("只复制段落上下文和密文引用，不复制明文。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        copyText(SavedReferenceDisplay.text(for: metadata))
                    } label: {
                        Label(isCopied ? "已复制" : "复制可用段落", systemImage: isCopied ? "checkmark" : "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(14)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

}

enum SavedReferenceDisplay {
    static let paragraphReferenceMarker = "[[ASV_REFERENCE]]"

    static func title(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return "未命名密文"
        }
        return label.contains(paragraphReferenceMarker) ? "可用段落" : label
    }

    static func text(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return metadata.reference
        }
        if label.contains(paragraphReferenceMarker) {
            return label.replacingOccurrences(of: paragraphReferenceMarker, with: metadata.reference)
        }
        return "\(label)：\(metadata.reference)"
    }

}

private extension SavedSecretReferenceRow {
    var policyLabel: String {
        switch metadata.policy {
        case .read:
            return "读取"
        case .externalSend:
            return "外发"
        case .credential:
            return "凭据"
        }
    }

    private var policyColor: Color {
        switch metadata.policy {
        case .read:
            return .blue
        case .externalSend:
            return .orange
        case .credential:
            return .purple
        }
    }
}

private struct SecurityBoundaryPanel: View {
    private let rows = [
        ("聊天里保留什么", "只保留 secret:// 引用和非敏感上下文。"),
        ("明文在哪里出现", "只在本机授权后的 App 窗口、MCP 内部 runner 或用户明确导出的本地文件中短暂出现。"),
        ("智能体不能拿什么", "不能拿到密码、token、Authorization header、cookie、解密后的字段值。"),
        ("高风险动作", "删除、改密码、公开网络发送、数据库写入等必须使用更窄的 allowlist 工具和本机授权。")
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(VaultWorkbenchCopy.securityBoundary)
                .font(.title3.weight(.semibold))
                .lineSpacing(4)

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 16),
                GridItem(.flexible(), spacing: 16)
            ], spacing: 16) {
                ForEach(rows, id: \.0) { row in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(row.0)
                            .font(.headline)
                        Text(row.1)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
                    .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                }
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}

private struct AgentAutomationAuditCard: View {
    let entries: [AgentAutomationAuditEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                Label("Agent 自动化", systemImage: "sparkles.rectangle.stack")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("最近 \(entries.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            Text("App 只负责本机授权和解密；SSH、HTTP、文件写入等动作由 MCP 工具执行。这里仅显示脱敏审计，不保存明文。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if entries.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "clock.badge.questionmark")
                        .foregroundStyle(.secondary)
                    Text("还没有 Agent 使用记录。连接 MCP 后，解密显示、段落还原、本地导出等动作会出现在这里。")
                        .foregroundStyle(.secondary)
                }
                .font(.callout)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            } else {
                VStack(spacing: 10) {
                    ForEach(entries.prefix(6)) { entry in
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: iconName(for: entry.action))
                                .foregroundStyle(.blue)
                                .frame(width: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(entry.action)
                                        .font(.headline)
                                    Spacer()
                                    Text(entry.result)
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                }
                                Text(entry.target)
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                                Text("\(entry.referenceCount) 个 secret:// 引用 · \(entry.occurredAt.formatted(date: .omitted, time: .standard))")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .padding(14)
                        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    private func iconName(for action: String) -> String {
        if action.contains("文件") {
            return "doc.badge.gearshape"
        }
        if action.contains("显示") {
            return "eye"
        }
        if action.contains("扫描") {
            return "magnifyingglass"
        }
        if action.contains("连接") {
            return "cable.connector"
        }
        return "bolt.horizontal.circle"
    }
}

private struct SensitiveCatalogPolicyCard: View {
    let validate: (() async -> Void)?
    let writeStatus: CatalogAgentWriteAuthorizationStatus
    let writeError: String?
    let enableAgentWrite: ((CatalogAgentWriteMode) async -> Void)?
    let revokeAgentWrite: (() async -> Void)?
    @State private var schemaExpanded = false
    @State private var copied = false
    @State private var selectedWriteMode: CatalogAgentWriteMode = .safe

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center) {
                Label("敏感信息目录规范", systemImage: "book.closed.fill")
                    .font(.title3.weight(.semibold))
                Spacer()
                Button(copied ? "已复制" : "复制 Agent 规范") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(VaultWorkbenchCopy.catalogPolicy, forType: .string)
                    copied = true
                }
                .buttonStyle(.bordered)
                Button("验证目录") {
                    Task { await validate?() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(validate == nil)
            }

            Text("SVLT 是 opt-in：它只管理用户选择纳入的秘密。managed 敏感信息.md 只能由 SVLT Catalog Store 写入；Obsidian、MCP 和其他 Agent 不得直接拼接或覆盖 Markdown/JSON。用户明确选择本次直接使用明文时，SVLT 不会强制接管。")
                .font(.callout)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                Text("Agent 目录编辑权限")
                    .font(.headline)
                HStack(spacing: 8) {
                    Picker("权限", selection: $selectedWriteMode) {
                        Text(CatalogAgentWriteMode.disabled.displayName).tag(CatalogAgentWriteMode.disabled)
                        Text(CatalogAgentWriteMode.safe.displayName).tag(CatalogAgentWriteMode.safe)
                    }
                    .frame(width: 190)
                    Button("允许安全目录编辑") {
                        Task { await enableAgentWrite?(selectedWriteMode) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(enableAgentWrite == nil)
                    Button("立即撤销") {
                        Task { await revokeAgentWrite?() }
                    }
                    .buttonStyle(.bordered)
                    .disabled(revokeAgentWrite == nil || writeStatus.mode == .disabled)
                }
                if writeStatus.mode == .disabled {
                    Text("当前：禁止 Agent 修改")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if writeStatus.mode == .safe {
                    Text("当前：允许安全目录编辑；绑定、替换、删除 Secret 或改变秘密目标仍需本机批准")
                        .font(.caption)
                        .foregroundStyle(.green)
                } else {
                    let expiry = writeStatus.expiresAt.map(Self.expiryText) ?? "未知"
                    Text("当前：\(writeStatus.mode.displayName) · 到期 \(expiry)")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if let writeError {
                    Text(writeError)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            DisclosureGroup("查看 Schema", isExpanded: $schemaExpanded) {
                ScrollView {
                    Text(VaultWorkbenchCopy.catalogSchema)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
                .frame(maxHeight: 220)
                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    private static func expiryText(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}
