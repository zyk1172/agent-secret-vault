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
        "2. 笔记里只留下 secret:// 引用；Codex、Claude、Hermes 自动识别并调用安全工具。",
        "3. 需要查看整段时，在这里粘贴段落，点“解密整个段落”。"
    ]

    public static var mcpConfig: String {
        """
        {
          "mcpServers": {
            "svlt": {
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
        看到 secret:// 就自动使用 svlt；不要让我粘贴明文。

        \(SVLTAgentCatalogPolicy.text)
        """
    }

    public static let catalogPolicy = SVLTAgentCatalogPolicy.text
    public static let catalogSchema = SVLTAgentCatalogPolicy.schema
}

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
    let orphanScanResult: OrphanScanResult?
    let auditEntries: [AgentAutomationAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let sensitiveIndexURL: URL?
    let sensitiveIndexEntries: [SensitiveInformationDocumentReference]
    let sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    let sensitiveCatalogError: String?
    let sensitiveMigrationPreview: SecretCatalogMigrationPreview?
    let sensitiveMigrationError: String?
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
    let createCatalogIndex: ((String) async -> Void)?
    let createCatalogEntry: ((String, String, String) async -> Void)?
    let fillCatalogSecret: ((String, String, String, String) async -> Void)?
    let prepareSensitiveMigration: (() async -> Void)?
    let confirmSensitiveMigration: (() async -> Void)?
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
        orphanScanResult: OrphanScanResult? = nil,
        auditEntries: [AgentAutomationAuditEntry] = [],
        savedReferences: [SecretReferenceMetadata] = [],
        sensitiveIndexURL: URL? = nil,
        sensitiveIndexEntries: [SensitiveInformationDocumentReference] = [],
        sensitiveCatalogSnapshot: SensitiveCatalogSnapshot? = nil,
        sensitiveCatalogError: String? = nil,
        sensitiveMigrationPreview: SecretCatalogMigrationPreview? = nil,
        sensitiveMigrationError: String? = nil,
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
        createCatalogIndex: ((String) async -> Void)? = nil,
        createCatalogEntry: ((String, String, String) async -> Void)? = nil,
        fillCatalogSecret: ((String, String, String, String) async -> Void)? = nil,
        prepareSensitiveMigration: (() async -> Void)? = nil,
        confirmSensitiveMigration: (() async -> Void)? = nil,
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
        self.orphanScanResult = orphanScanResult
        self.auditEntries = auditEntries
        self.savedReferences = savedReferences
        self.sensitiveIndexURL = sensitiveIndexURL
        self.sensitiveIndexEntries = sensitiveIndexEntries
        self.sensitiveCatalogSnapshot = sensitiveCatalogSnapshot
        self.sensitiveCatalogError = sensitiveCatalogError
        self.sensitiveMigrationPreview = sensitiveMigrationPreview
        self.sensitiveMigrationError = sensitiveMigrationError
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
        self.createCatalogIndex = createCatalogIndex
        self.createCatalogEntry = createCatalogEntry
        self.fillCatalogSecret = fillCatalogSecret
        self.prepareSensitiveMigration = prepareSensitiveMigration
        self.confirmSensitiveMigration = confirmSensitiveMigration
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
            AgentServiceStatusView(status: agentServiceStatus)
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
                        migrationPreview: sensitiveMigrationPreview,
                        migrationError: sensitiveMigrationError,
                        refresh: refreshSensitiveCatalog,
                        createIndex: createCatalogIndex,
                        createEntry: createCatalogEntry,
                        fillSecret: fillCatalogSecret,
                        prepareMigration: prepareSensitiveMigration,
                        confirmMigration: confirmSensitiveMigration
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
                    SensitiveCatalogPolicyCard(validate: validateSensitiveCatalog)
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
                        description: Text("v2 Index/Entry 内容由上方结构化编辑器显示；旧格式只通过迁移预览读取。")
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
    let migrationPreview: SecretCatalogMigrationPreview?
    let migrationError: String?
    let refresh: (() async -> Void)?
    let createIndex: ((String) async -> Void)?
    let createEntry: ((String, String, String) async -> Void)?
    let fillSecret: ((String, String, String, String) async -> Void)?
    let prepareMigration: (() async -> Void)?
    let confirmMigration: (() async -> Void)?

    @State private var newIndexTitle = ""
    @State private var addingEntryToIndexID: String?
    @State private var newEntryTitle = ""
    @State private var selectedPresetID = SensitiveCatalogEntryPreset.all.first?.id ?? "credential"
    @State private var isWorking = false

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

            if let errorMessage, snapshot == nil {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            }

            if snapshot == nil, let prepareMigration {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .foregroundStyle(.orange)
                        Text("旧格式迁移")
                            .font(.headline)
                        Spacer()
                        Button("生成迁移预览") {
                            Task {
                                isWorking = true
                                await prepareMigration()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 不会猜测未标注的用户名/密码，也不会直接覆盖旧文件。确认后会先生成时间戳备份，并校验 secret:// 引用集合。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let migrationError {
                        Text(migrationError)
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if let migrationPreview {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("预览：Index \(migrationPreview.document.indexes.count) · Entry \(migrationPreview.document.entries.count) · 引用 \(migrationPreview.referencesBefore.count)")
                                .font(.caption.weight(.semibold))
                            if migrationPreview.ambiguousReferences.isEmpty && migrationPreview.plaintextSensitiveFields.isEmpty {
                                Label("没有待确认字段，可以迁移", systemImage: "checkmark.circle")
                                    .font(.caption)
                                    .foregroundStyle(.green)
                            } else {
                                Label("存在待确认项，已禁止自动迁移", systemImage: "exclamationmark.triangle")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                ForEach(migrationPreview.ambiguousReferences, id: \.reference) { ambiguity in
                                    Text("未识别：\(ambiguity.reference) · 可选 \(ambiguity.suggestedKeys.joined(separator: " / "))")
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                                if !migrationPreview.plaintextSensitiveFields.isEmpty {
                                    Text("发现旧文档中的敏感字段明文；请在 SVLT 安全表单重新填写。")
                                        .font(.caption2)
                                        .foregroundStyle(.orange)
                                }
                            }
                            HStack {
                                Spacer()
                                Button("确认迁移并备份") {
                                    Task {
                                        isWorking = true
                                        await confirmMigration?()
                                        isWorking = false
                                    }
                                }
                                .buttonStyle(.borderedProminent)
                                .disabled(isWorking || migrationPreview.requiresUserResolution || confirmMigration == nil)
                            }
                        }
                        .padding(10)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                }
                .padding(10)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
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
                            await createIndex?(title)
                            newIndexTitle = ""
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || createIndex == nil)
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
                                        Button("创建") {
                                            let title = newEntryTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                                            guard !title.isEmpty else { return }
                                            Task {
                                                isWorking = true
                                                await createEntry?(index.id, title, selectedPresetID)
                                                addingEntryToIndexID = nil
                                                newEntryTitle = ""
                                                isWorking = false
                                            }
                                        }
                                        .buttonStyle(.borderedProminent)
                                        Button("取消") { addingEntryToIndexID = nil }
                                            .buttonStyle(.bordered)
                                    }
                                }

                                if entries.isEmpty {
                                    Text("暂无 Entry")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .padding(.leading, 28)
                                } else {
                                    ForEach(entries, id: \.id) { entry in
                                        SensitiveCatalogEntryRow(entry: entry, fillSecret: fillSecret)
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
    let fillSecret: ((String, String, String, String) async -> Void)?
    @State private var secretInput = ""
    @State private var isSavingSecret = false

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(entry.fields, id: \.key) { field in
                    fieldRow(field)
                }
                if let notes = entry.notes, !notes.isEmpty {
                    Text(notes)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, 3)
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
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private func fieldDisplayValue(_ field: SecretCatalogFieldValue) -> String {
        if field.type.isSecret {
            return field.secretRef ?? "未填写（请在 SVLT 安全表单中输入）"
        }
        guard field.agentVisible else { return "已隐藏" }
        guard let value = field.value else { return "未填写" }
        switch value {
        case .string(let string):
            return string
        case .number(let number):
            return String(number)
        case .boolean(let boolean):
            return boolean ? "是" : "否"
        case .list(let list):
            return list.joined(separator: ", ")
        }
    }

    @ViewBuilder
    private func fieldRow(_ field: SecretCatalogFieldValue) -> some View {
        if field.type.isSecret, field.secretRef == nil {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .frame(width: 14)
                    Text(field.label)
                        .font(.caption.weight(.semibold))
                    Text("待填写")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                HStack(spacing: 8) {
                    SecureField("在 SVLT 安全表单中输入", text: $secretInput)
                        .textFieldStyle(.roundedBorder)
                    Button(isSavingSecret ? "保存中…" : "保存") {
                        let plaintext = secretInput
                        Task {
                            isSavingSecret = true
                            await fillSecret?(entry.id, field.key, field.label, plaintext)
                            secretInput = ""
                            isSavingSecret = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(secretInput.isEmpty || isSavingSecret || fillSecret == nil)
                }
            }
        } else {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: field.type.isSecret ? "lock.fill" : "circle.fill")
                    .font(.caption2)
                    .foregroundStyle(field.type.isSecret ? .orange : .secondary)
                    .frame(width: 14)
                Text(field.label)
                    .font(.caption.weight(.semibold))
                Text(fieldDisplayValue(field))
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
    @State private var schemaExpanded = false
    @State private var copied = false

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

            Text("managed 敏感信息.md 只能由 SVLT Catalog Store 写入。Obsidian、MCP 和其他 Agent 不得直接拼接或覆盖 Markdown/JSON。")
                .font(.callout)
                .foregroundStyle(.secondary)

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
}
