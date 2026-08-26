import AppKit
import SwiftUI
import VaultCore
import VaultIPC
import VaultService

/// Ordered, single-consumer state for MCP Catalog approval requests. The App
/// presents only `currentID`; completing it removes exactly that ID and leaves
/// later requests in FIFO order.
public struct PendingCatalogWriteAccessQueue: Equatable, Sendable {
    public private(set) var ids: [UUID] = []

    public init() {}

    public mutating func replace(with ids: [UUID]) {
        self.ids = ids
    }

    public mutating func finish(_ id: UUID) {
        ids.removeAll { $0 == id }
    }

    public var currentID: UUID? { ids.first }
    public var count: Int { ids.count }
}

public enum VaultWorkbenchCopy {
    public static let documentationURL = URL(string: "https://github.com/zyk1172/svlt") ?? URL(fileURLWithPath: "/")

    public static let disconnected = (
        status: "Obsidian 插件未连接",
        primaryAction: "先安装并启用 Obsidian 插件。"
    )

    public static let securityBoundary =
        "目录中的密码默认只显示为“已加密”；点击单个字段的“解密”后，明文只在本应用内短暂显示，并且每次都需要本机授权。"

    public static let simpleUsageSteps = [
        "1. 在“敏感信息”中打开分组和条目；普通字段直接显示，密码字段默认只显示“已加密”。",
        "2. 需要查看密码时，在具体字段点击“解密”，完成本机身份认证后明文短暂显示。",
        "3. 需要修改目录时，在 App 中编辑；Agent 每笔修改都会重新申请一次本机授权。"
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
        凭据来源标签：SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL。

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

public enum VaultWorkbenchSection: String, CaseIterable, Identifiable, Sendable {
    case overview
    case secrets
    case automation
    case security

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:
            return "控制台"
        case .secrets:
            return "敏感信息"
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
        case .secrets:
            return "分组目录与独立加密记录"
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
        case .secrets:
            return "key.viewfinder"
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
    let auditEntries: [CatalogSecurityAuditEntry]
    let auditError: String?
    let savedReferences: [SecretReferenceMetadata]
    let sensitiveIndexURL: URL?
    let sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    let sensitiveCatalogError: String?
    let sensitiveCatalogCanAdoptV2: Bool
    let sensitiveCatalogCanAdoptV3: Bool
    let catalogAgentWriteStatus: CatalogAgentWriteAuthorizationStatus
    let catalogAgentWriteError: String?
    let pendingWriteAccessRequest: CatalogAgentWriteAccessRequest?
    /// Total number of still-pending agent Catalog write requests. When this
    /// exceeds one the alert title shows the queue position so the user knows
    /// more requests follow.
    var pendingWriteAccessQueueCount: Int = 0
    let refreshSavedReferences: (() async -> Void)?
    let chooseSensitiveIndex: (() -> Void)?
    let refreshSensitiveCatalog: (() async -> Void)?
    let validateSensitiveCatalog: (() async -> Void)?
    let adoptExternalV2Catalog: (() async -> Void)?
    let adoptExternalV3Catalog: (() async -> Void)?
    let approveExternalCatalogChange: (() async -> Void)?
    let formatRepairPlan: CatalogFormatRepairPlan?
    let checkSensitiveCatalogFormat: (() async -> Void)?
    let repairSensitiveCatalogFormat: (() async -> Void)?
    let createCatalogIndex: ((String) async -> CatalogMutationUIResult)?
    let createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitCatalogEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyCatalogBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?
    let enableCatalogAgentWrite: ((CatalogAgentWriteMode) async -> Void)?
    let revokeCatalogAgentWrite: (() async -> Void)?
    let respondToWriteAccessRequest: ((UUID, Bool) async -> Void)?
    let showSensitiveCatalogTemplate: (() async -> Void)?
    @State private var selectedSection: VaultWorkbenchSection = .overview
    @State private var writeAccessRequest: CatalogAgentWriteAccessRequest?

    public init(
        status: WorkbenchStatus,
        agentServiceStatus: AgentServiceStatus = .unavailable,
        agentServiceActionInFlight: Bool = false,
        agentServiceActionErrorMessage: String? = nil,
        enableAgentService: (() async -> Void)? = nil,
        disableAgentService: (() async -> Void)? = nil,
        restartAgentService: (() async -> Void)? = nil,
        auditEntries: [CatalogSecurityAuditEntry] = [],
        auditError: String? = nil,
        savedReferences: [SecretReferenceMetadata] = [],
        sensitiveIndexURL: URL? = nil,
        sensitiveCatalogSnapshot: SensitiveCatalogSnapshot? = nil,
        sensitiveCatalogError: String? = nil,
        sensitiveCatalogCanAdoptV2: Bool = false,
        sensitiveCatalogCanAdoptV3: Bool = false,
        catalogAgentWriteStatus: CatalogAgentWriteAuthorizationStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled),
        catalogAgentWriteError: String? = nil,
        pendingWriteAccessRequest: CatalogAgentWriteAccessRequest? = nil,
        pendingWriteAccessQueueCount: Int = 0,
        refreshSavedReferences: (() async -> Void)? = nil,
        chooseSensitiveIndex: (() -> Void)? = nil,
        refreshSensitiveCatalog: (() async -> Void)? = nil,
        validateSensitiveCatalog: (() async -> Void)? = nil,
        adoptExternalV2Catalog: (() async -> Void)? = nil,
        adoptExternalV3Catalog: (() async -> Void)? = nil,
        approveExternalCatalogChange: (() async -> Void)? = nil,
        formatRepairPlan: CatalogFormatRepairPlan? = nil,
        checkSensitiveCatalogFormat: (() async -> Void)? = nil,
        repairSensitiveCatalogFormat: (() async -> Void)? = nil,
        createCatalogIndex: ((String) async -> CatalogMutationUIResult)? = nil,
        createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)? = nil,
        commitCatalogEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)? = nil,
        revealCatalogField: ((String, String) async throws -> String)? = nil,
        replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)? = nil,
        applyCatalogBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)? = nil,
        enableCatalogAgentWrite: ((CatalogAgentWriteMode) async -> Void)? = nil,
        revokeCatalogAgentWrite: (() async -> Void)? = nil,
        respondToWriteAccessRequest: ((UUID, Bool) async -> Void)? = nil,
        showSensitiveCatalogTemplate: (() async -> Void)? = nil
    ) {
        self.status = status
        self.agentServiceStatus = agentServiceStatus
        self.agentServiceActionInFlight = agentServiceActionInFlight
        self.agentServiceActionErrorMessage = agentServiceActionErrorMessage
        self.enableAgentService = enableAgentService
        self.disableAgentService = disableAgentService
        self.restartAgentService = restartAgentService
        self.auditEntries = auditEntries
        self.auditError = auditError
        self.savedReferences = savedReferences
        self.sensitiveIndexURL = sensitiveIndexURL
        self.sensitiveCatalogSnapshot = sensitiveCatalogSnapshot
        self.sensitiveCatalogError = sensitiveCatalogError
        self.sensitiveCatalogCanAdoptV2 = sensitiveCatalogCanAdoptV2
        self.sensitiveCatalogCanAdoptV3 = sensitiveCatalogCanAdoptV3
        self.catalogAgentWriteStatus = catalogAgentWriteStatus
        self.catalogAgentWriteError = catalogAgentWriteError
        self.pendingWriteAccessRequest = pendingWriteAccessRequest
        self.pendingWriteAccessQueueCount = pendingWriteAccessQueueCount
        self.refreshSavedReferences = refreshSavedReferences
        self.chooseSensitiveIndex = chooseSensitiveIndex
        self.refreshSensitiveCatalog = refreshSensitiveCatalog
        self.validateSensitiveCatalog = validateSensitiveCatalog
        self.adoptExternalV2Catalog = adoptExternalV2Catalog
        self.adoptExternalV3Catalog = adoptExternalV3Catalog
        self.approveExternalCatalogChange = approveExternalCatalogChange
        self.formatRepairPlan = formatRepairPlan
        self.checkSensitiveCatalogFormat = checkSensitiveCatalogFormat
        self.repairSensitiveCatalogFormat = repairSensitiveCatalogFormat
        self.createCatalogIndex = createCatalogIndex
        self.createCatalogEntry = createCatalogEntry
        self.commitCatalogEntryEdit = commitCatalogEntryEdit
        self.revealCatalogField = revealCatalogField
        self.replaceCatalogSecret = replaceCatalogSecret
        self.applyCatalogBatch = applyCatalogBatch
        self.enableCatalogAgentWrite = enableCatalogAgentWrite
        self.revokeCatalogAgentWrite = revokeCatalogAgentWrite
        self.respondToWriteAccessRequest = respondToWriteAccessRequest
        self.showSensitiveCatalogTemplate = showSensitiveCatalogTemplate
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
        .onChange(of: pendingWriteAccessRequest) { request in
            writeAccessRequest = request
        }
        .alert(item: $writeAccessRequest) { request in
            let queueSuffix = pendingWriteAccessQueueCount > 1
                ? "（待处理请求 1 / \(pendingWriteAccessQueueCount)）"
                : ""
            return Alert(
                title: Text("\(request.displayName) 请求修改敏感信息目录\(queueSuffix)"),
                message: Text("""
                    操作：\(request.intent.map { $0.operation.displayName } ?? "目录修改")
                    原因类别：\(request.reasonCategory.displayName)
                    目标版本：\(request.intent.map { String($0.acceptedRevision) } ?? "未知")
                    请求将在短时间内失效，授权仅消费一次。每一笔操作都需要单独验证。
                    """),
                primaryButton: .default(Text("验证并授权")) {
                    Task { await respondToWriteAccessRequest?(request.id, true) }
                },
                secondaryButton: .cancel(Text("拒绝")) {
                    Task { await respondToWriteAccessRequest?(request.id, false) }
                }
            )
        }
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
        case .secrets:
            WorkbenchPage(title: "敏感信息", subtitle: "分组卡片 → 条目 → 字段；Markdown 保留为可正常编辑的 Obsidian 文件。", systemImage: selectedSection.systemImage) {
                VStack(spacing: 14) {
                    if sensitiveIndexURL != nil || sensitiveCatalogSnapshot != nil || sensitiveCatalogError != nil {
                        SensitiveCatalogEditorCard(
                            snapshot: sensitiveCatalogSnapshot,
                        errorMessage: sensitiveCatalogError,
                        canAdoptExternalV2: sensitiveCatalogCanAdoptV2,
                        adoptExternalV2: adoptExternalV2Catalog,
                        canAdoptExternalV3: sensitiveCatalogCanAdoptV3,
                        adoptExternalV3: adoptExternalV3Catalog,
                        approveExternalChange: approveExternalCatalogChange,
                        refresh: refreshSensitiveCatalog,
                        createIndex: createCatalogIndex,
                        createEntry: createCatalogEntry,
                        commitEntryEdit: commitCatalogEntryEdit,
                        revealCatalogField: revealCatalogField,
                            replaceCatalogSecret: replaceCatalogSecret,
                            applyBatch: applyCatalogBatch
                        )
                        CatalogFormatCheckCard(
                            plan: formatRepairPlan,
                            check: checkSensitiveCatalogFormat,
                            repair: repairSensitiveCatalogFormat
                        )
                    }
                    SensitiveIndexLibraryCard(
                        indexURL: sensitiveIndexURL,
                        chooseIndex: chooseSensitiveIndex
                    )
                }
            }
        case .automation:
            WorkbenchPage(title: "智能体自动化", subtitle: "只显示脱敏审计。密码、token、Authorization header 不会进入这里。", systemImage: selectedSection.systemImage) {
                VStack(spacing: 14) {
                    AgentAutomationAuditCard(entries: auditEntries, errorMessage: auditError)
                }
            }
        case .security:
            WorkbenchPage(title: "安全边界", subtitle: "明确哪些动作允许、哪些动作必须由本机授权。", systemImage: selectedSection.systemImage) {
                SecurityBoundaryPanel(showTemplate: showSensitiveCatalogTemplate)
            }
        }
    }

    private var overviewPage: some View {
        VStack(alignment: .leading, spacing: 12) {
            OverviewStatusStrip(status: status)

            LazyVGrid(columns: [
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
                    title: "密文库",
                    detail: "查看本机已保存的 secret:// 引用，复制后可直接给 agent 或笔记使用。",
                    systemImage: "key.viewfinder",
                    tint: .green,
                    actionTitle: "打开密文库",
                    compact: true
                ) {
                    selectSection(.secrets)
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
    let entries: [CatalogSecurityAuditEntry]

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
                            Image(systemName: iconName(for: entry.operation))
                                .foregroundStyle(.blue)
                                .frame(width: 18)
                            Text(entry.operation.displayName)
                                .font(.callout.weight(.semibold))
                                .lineLimit(1)
                            Text(entry.target)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            Spacer()
                            Text(entry.result.displayName)
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

    private func iconName(for operation: AuditOperation) -> String {
        switch operation {
        case .reveal:
            return "eye"
        case .catalogMutation, .formatCheck, .formatRepair:
            return "doc.badge.gearshape"
        case .authorization:
            return "person.badge.key"
        case .credentialUse:
            return "key.fill"
        case .secureExecute:
            return "cable.connector"
        default:
            return "bolt.horizontal.circle"
        }
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
    let chooseIndex: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Label("目录文件选择", systemImage: "doc.badge.lock")
                    .font(.title3.weight(.semibold))
                Spacer()
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
                    Button("更换文件…") { chooseIndex?() }
                        .buttonStyle(.bordered)
                }
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

                Text("分组、条目和字段由结构化编辑器管理。普通笔记扫描已移出产品界面。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ContentUnavailableView {
                    Label("尚未设置敏感信息目录", systemImage: "folder.badge.questionmark")
                } description: {
                    Text("SVLT 使用合法的 Obsidian Markdown 管理账号、密码和其他敏感信息。")
                }
                .frame(maxWidth: .infinity, minHeight: 170)

                Button("选择现有敏感信息.md") { chooseIndex?() }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity, alignment: .center)

                Text("需要查看空白模板时，请前往“安全边界”页面；模板副本不会接管或修改用户目录。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct CatalogFormatCheckCard: View {
    let plan: CatalogFormatRepairPlan?
    let check: (() async -> Void)?
    let repair: (() async -> Void)?
    @State private var isWorking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("格式检查", systemImage: "checkmark.shield")
                    .font(.headline.weight(.semibold))
                Spacer()
                Button("检查格式") {
                    Task {
                        isWorking = true
                        await check?()
                        isWorking = false
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isWorking || check == nil)
            }

            if let plan {
                if plan.diagnostics.isEmpty {
                    Label("格式正常", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Label(
                        plan.unrepairableDiagnostics.isEmpty ? "发现可修复格式问题" : "发现不能自动修复的问题",
                        systemImage: plan.unrepairableDiagnostics.isEmpty ? "exclamationmark.triangle" : "xmark.octagon"
                    )
                    .foregroundStyle(plan.unrepairableDiagnostics.isEmpty ? .orange : .red)

                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(plan.diagnostics) { diagnostic in
                            VStack(alignment: .leading, spacing: 3) {
                                Text("第 \(diagnostic.line) 行\(diagnostic.column.map { "、第 \($0) 列" } ?? "") · \(diagnostic.code)")
                                    .font(.caption.weight(.semibold))
                                Text(diagnostic.message)
                                    .font(.callout)
                                if let hint = diagnostic.hint {
                                    Text(hint)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(9)
                            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        }
                    }

                    if plan.canRepair, let repair {
                        Button("修复格式") {
                            Task {
                                isWorking = true
                                await repair()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isWorking)
                    } else if !plan.unrepairableDiagnostics.isEmpty {
                        Text("当前问题不会自动覆盖，请按上面的精确诊断处理。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("检查当前选中的敏感信息.md；检查结果只包含安全诊断，不显示正文或密文引用。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct CatalogDeletionRequest: Identifiable {
    enum Kind {
        case indexes
        case entries
    }

    let id: String
    let kind: Kind
    let ids: [String]
    let itemCount: Int
    let entryCount: Int
    let secretFieldCount: Int
}

private struct SensitiveCatalogEditorCard: View {
    let snapshot: SensitiveCatalogSnapshot?
    let errorMessage: String?
    let canAdoptExternalV2: Bool
    let adoptExternalV2: (() async -> Void)?
    let canAdoptExternalV3: Bool
    let adoptExternalV3: (() async -> Void)?
    let approveExternalChange: (() async -> Void)?
    let refresh: (() async -> Void)?
    let createIndex: ((String) async -> CatalogMutationUIResult)?
    let createEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?

    @State private var newIndexTitle = ""
    @State private var isWorking = false
    @State private var createIndexError: CatalogMutationUIError?
    @State private var selectedIndexID: String?
    @State private var selectedIndexIDs: Set<String> = []
    @State private var isSelectingIndexes = false
    @State private var pendingIndexDeletion: CatalogDeletionRequest?
    @State private var deletionError: CatalogMutationUIError?

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
                if errorMessage.contains("待审批"), let approveExternalChange {
                        Button("批准并接纳外部修改") {
                        Task { await approveExternalChange() }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }

            if snapshot == nil, canAdoptExternalV2, let adoptExternalV2 {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.blue)
                        Text("升级外部 v2 文件")
                            .font(.headline)
                        Spacer()
                        Button("备份、验证并升级") {
                            Task {
                                isWorking = true
                                await adoptExternalV2()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 将严格解析当前 v2 文件，先备份，再转换为 Obsidian 兼容的 v3；失败时原文件保持不变。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            } else if snapshot == nil, canAdoptExternalV3, let adoptExternalV3 {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.blue)
                        Text("接纳外部 v3 文件")
                            .font(.headline)
                        Spacer()
                        Button("验证并接纳") {
                            Task {
                                isWorking = true
                                await adoptExternalV3()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 将重新解析并校验当前 v3 文件，只建立本机 accepted state，不改写 Markdown。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            } else if snapshot == nil, errorMessage?.contains("旧版格式") == true {
                Label("旧版目录不支持自动升级。请先备份文件，再手动转换为 Catalog v3。", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let snapshot {
                HStack(spacing: 8) {
                    Text("版本 \(snapshot.revision)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Label("完整性已验证", systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                    Spacer()
                    Text("分组 \(snapshot.document.indexes.count) · 条目 \(snapshot.document.entries.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 8) {
                    TextField("新增分组，例如 QNAP", text: $newIndexTitle)
                        .textFieldStyle(.roundedBorder)
                    Button("新增分组") {
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
                                    message: "本机控制服务不可用，无法新增分组"
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
                        "还没有分组",
                        systemImage: "folder.badge.plus",
                        description: Text("先创建一个分组；条目和字段会在分组弹窗中管理。")
                    )
                    .frame(maxWidth: .infinity, minHeight: 120)
                } else {
                    HStack(spacing: 8) {
                        if isSelectingIndexes {
                            Button(selectedIndexIDs.count == snapshot.document.indexes.count ? "取消全选" : "全选") {
                                if selectedIndexIDs.count == snapshot.document.indexes.count {
                                    selectedIndexIDs.removeAll()
                                } else {
                                    selectedIndexIDs = Set(snapshot.document.indexes.map(\.id))
                                }
                            }
                            .buttonStyle(.bordered)
                            Button("删除选中", role: .destructive) {
                                prepareIndexDeletion(snapshot: snapshot)
                            }
                            .buttonStyle(.bordered)
                            .disabled(isWorking || selectedIndexIDs.isEmpty || applyBatch == nil)
                            Text("已选 \(selectedIndexIDs.count)")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                            Button("完成") {
                                isSelectingIndexes = false
                                selectedIndexIDs.removeAll()
                            }
                            .buttonStyle(.borderedProminent)
                        } else {
                            Button("选择") {
                                isSelectingIndexes = true
                                selectedIndexIDs.removeAll()
                            }
                            .buttonStyle(.bordered)
                        }
                        Spacer()
                    }
                    if let deletionError {
                        Label(deletionError.displayText, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }

                    let columns = Array(
                        repeating: GridItem(
                            .flexible(minimum: 0, maximum: .infinity),
                            spacing: 6,
                            alignment: .topLeading
                        ),
                        count: 3
                    )
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 6) {
                        ForEach(snapshot.document.indexes, id: \.id) { index in
                            let entries = snapshot.document.entries.filter { $0.indexId == index.id }
                            let secretFieldCount = entries.flatMap(\.fields).filter { $0.type.isSecret }.count
                            let isSelected = selectedIndexIDs.contains(index.id)
                            VStack(alignment: .leading, spacing: 12) {
                                HStack(alignment: .center, spacing: 10) {
                                    if isSelectingIndexes {
                                        Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                                            .font(.title3)
                                            .foregroundStyle(isSelected ? .blue : .secondary)
                                            .accessibilityLabel(isSelected ? "已选择" : "未选择")
                                    }
                                    Image(systemName: "folder.fill")
                                        .font(.title2)
                                        .foregroundStyle(.blue)
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(index.title)
                                            .font(.headline)
                                            .lineLimit(2)
                                        if !index.aliases.isEmpty {
                                            Text(index.aliases.joined(separator: "、"))
                                                .font(.callout)
                                                .foregroundStyle(.secondary)
                                                .lineLimit(2)
                                        }
                                    }
                                    Spacer()
                                }

                                HStack(spacing: 12) {
                                    Label("条目 " + String(entries.count), systemImage: "list.bullet")
                                    Label("密码字段 " + String(secretFieldCount), systemImage: "lock.fill")
                                }
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(16)
                            .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
                            .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                            .overlay(
                                RoundedRectangle(cornerRadius: 14, style: .continuous)
                                    .stroke(isSelected ? Color.blue.opacity(0.65) : Color.secondary.opacity(0.12), lineWidth: isSelected ? 2 : 1)
                            )
                            .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                            .onTapGesture {
                                if isSelectingIndexes {
                                    if isSelected { selectedIndexIDs.remove(index.id) }
                                    else { selectedIndexIDs.insert(index.id) }
                                } else {
                                    selectedIndexID = index.id
                                }
                            }
                        }
                    }
                }
            } else if errorMessage == nil {
                    Text("选择现有敏感信息.md 后，SVLT 会在这里显示分组、条目和字段。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .sheet(isPresented: Binding(
            get: { selectedIndexID != nil },
            set: { if !$0 { selectedIndexID = nil } }
        )) {
            if let selectedIndexID,
               let currentSnapshot = snapshot,
               let index = currentSnapshot.document.indexes.first(where: { $0.id == selectedIndexID }) {
                SensitiveCatalogGroupSheet(
                    index: index,
                    entries: currentSnapshot.document.entries.filter { $0.indexId == index.id },
                    createEntry: createEntry,
                    commitEntryEdit: commitEntryEdit,
                    revealCatalogField: revealCatalogField,
                    replaceCatalogSecret: replaceCatalogSecret,
                    applyBatch: applyBatch,
                )
                .frame(minWidth: 760, idealWidth: 900)
            } else {
                ContentUnavailableView("分组已不存在", systemImage: "folder.badge.questionmark")
                    .frame(minWidth: 520, minHeight: 300)
            }
        }
        .alert(item: $pendingIndexDeletion) { request in
            Alert(
                title: Text("删除 \(request.itemCount) 个分组？"),
                message: Text("其中包含 \(request.entryCount) 个条目、\(request.secretFieldCount) 个密码字段。此操作会删除目录引用。"),
                primaryButton: .destructive(Text("删除")) {
                    deleteIndexes(request.ids)
                },
                secondaryButton: .cancel(Text("取消"))
            )
        }
    }

    private func prepareIndexDeletion(snapshot: SensitiveCatalogSnapshot) {
        let ids = selectedIndexIDs.sorted()
        guard !ids.isEmpty else { return }
        let selectedEntries = snapshot.document.entries.filter { ids.contains($0.indexId) }
        pendingIndexDeletion = CatalogDeletionRequest(
            id: ids.joined(separator: ","),
            kind: .indexes,
            ids: ids,
            itemCount: ids.count,
            entryCount: selectedEntries.count,
            secretFieldCount: selectedEntries.flatMap(\.fields).filter { $0.type.isSecret }.count
        )
    }

    private func deleteIndexes(_ ids: [String]) {
        Task {
            isWorking = true
            deletionError = nil
            guard let applyBatch else {
                deletionError = CatalogMutationUIError(
                    code: "APP_CONTROL_UNAVAILABLE",
                    message: "本机控制服务不可用，无法删除分组"
                )
                pendingIndexDeletion = nil
                isWorking = false
                return
            }
            let result = await applyBatch(CatalogBatchMutation(operations: ids.map { .deleteIndex(id: $0) }))
            switch result {
            case .success:
                selectedIndexIDs.subtract(ids)
            case let .failure(error):
                deletionError = error
            }
            pendingIndexDeletion = nil
            isWorking = false
        }
    }
}

private struct SensitiveCatalogGroupSheet: View {
    let index: SecretCatalogIndex
    let entries: [SecretCatalogEntry]
    let createEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?

    @Environment(\.dismiss) private var dismiss
    @State private var isAdding = false
    @State private var newEntryTitle = ""
    @State private var selectedPresetID = SensitiveCatalogEntryPreset.all.first?.id ?? "credential"
    @State private var selectedEntryIDs: Set<String> = []
    @State private var isSelectingEntries = false
    @State private var pendingEntryDeletion: CatalogDeletionRequest?
    @State private var newlyCreatedEntryID: String?
    @State private var isWorking = false
    @State private var createError: CatalogEntryCreationError?
    @State private var deletionError: CatalogMutationUIError?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "folder.fill")
                    .font(.title2)
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text(index.title)
                        .font(.title2.weight(.semibold))
                    Text("条目 " + String(entries.count) + " · 密码字段 " + String(entries.flatMap { $0.fields }.filter { $0.type.isSecret }.count))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }

            HStack(spacing: 8) {
                if isSelectingEntries {
                    Button(selectedEntryIDs.count == entries.count ? "取消全选" : "全选") {
                        if selectedEntryIDs.count == entries.count {
                            selectedEntryIDs.removeAll()
                        } else {
                            selectedEntryIDs = Set(entries.map(\.id))
                        }
                    }
                    .buttonStyle(.bordered)
                    Button("删除选中", role: .destructive) {
                        prepareEntryDeletion()
                    }
                    .buttonStyle(.bordered)
                    .disabled(isWorking || selectedEntryIDs.isEmpty || applyBatch == nil)
                    Text("已选 \(selectedEntryIDs.count)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Button("完成") {
                        isSelectingEntries = false
                        selectedEntryIDs.removeAll()
                    }
                    .buttonStyle(.borderedProminent)
                } else {
                    Button("新增条目") {
                        isAdding = true
                        createError = nil
                    }
                    .buttonStyle(.borderedProminent)
                    Button("选择") {
                        isSelectingEntries = true
                        selectedEntryIDs.removeAll()
                    }
                    .buttonStyle(.bordered)
                }
                Spacer()
            }

            if let deletionError {
                Label(deletionError.displayText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            if isAdding {
                HStack(spacing: 8) {
                    TextField("条目标题，例如管理后台登录", text: $newEntryTitle)
                        .textFieldStyle(.roundedBorder)
                    Picker("初始字段", selection: $selectedPresetID) {
                        ForEach(SensitiveCatalogEntryPreset.all) { preset in
                            Text(preset.title).tag(preset.id)
                        }
                    }
                    .frame(width: 160)
                    .help("预设只创建一个初始字段，其余字段可按需添加")
                    Button("创建") {
                        let title = newEntryTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !title.isEmpty else { return }
                        Task {
                            isWorking = true
                            createError = nil
                            let result = await createEntry?(index.id, title, selectedPresetID)
                            switch result {
                            case .success(let writeResult):
                                newlyCreatedEntryID = writeResult.entry?.id
                                isAdding = false
                                newEntryTitle = ""
                            case .failure(let error):
                                createError = error
                            case nil:
                                createError = CatalogEntryCreationError(
                                    code: "APP_CONTROL_UNAVAILABLE",
                                    message: "本机控制服务不可用，无法新增条目"
                                )
                            }
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || createEntry == nil)
                    Button("取消") {
                        isAdding = false
                        createError = nil
                    }
                    .buttonStyle(.bordered)
                }
                if let createError {
                    Label(createError.displayText, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            if entries.isEmpty {
                ContentUnavailableView(
                    "暂无条目",
                    systemImage: "list.bullet.rectangle",
                    description: Text("在这个分组中新增一个条目即可开始填写字段。")
                )
                .frame(maxWidth: .infinity, minHeight: 220)
            } else {
                ScrollView {
                    let columns = Array(
                        repeating: GridItem(.flexible(minimum: 0, maximum: .infinity), spacing: 8, alignment: .topLeading),
                        count: 3
                    )
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 8) {
                        ForEach(entries, id: \.id) { entry in
                            SensitiveCatalogEntryRow(
                                entry: entry,
                                autoEdit: newlyCreatedEntryID == entry.id,
                                isSelecting: isSelectingEntries,
                                isSelected: selectedEntryIDs.contains(entry.id),
                                toggleSelection: {
                                    if selectedEntryIDs.contains(entry.id) { selectedEntryIDs.remove(entry.id) }
                                    else { selectedEntryIDs.insert(entry.id) }
                                },
                                commitEntryEdit: commitEntryEdit,
                                revealCatalogField: revealCatalogField,
                                replaceCatalogSecret: replaceCatalogSecret,
                                applyBatch: applyBatch,
                                requestDelete: { prepareEntryDeletion(for: entry) }
                            )
                        }
                    }
                }
                .frame(maxHeight: 520)
            }
        }
        .padding(22)
        .background(Color(nsColor: .windowBackgroundColor))
        .alert(item: $pendingEntryDeletion) { request in
            Alert(
                title: Text("删除 \(request.itemCount) 个条目？"),
                message: Text("其中包含 \(request.secretFieldCount) 个密码字段。此操作会删除目录引用。"),
                primaryButton: .destructive(Text("删除")) {
                    deleteEntries(request.ids)
                },
                secondaryButton: .cancel(Text("取消"))
            )
        }
    }

    private func prepareEntryDeletion(for entry: SecretCatalogEntry? = nil) {
        let ids = (entry.map { [$0.id] } ?? selectedEntryIDs.sorted())
        guard !ids.isEmpty else { return }
        let selectedEntries = entries.filter { ids.contains($0.id) }
        pendingEntryDeletion = CatalogDeletionRequest(
            id: ids.joined(separator: ","),
            kind: .entries,
            ids: ids,
            itemCount: ids.count,
            entryCount: 0,
            secretFieldCount: selectedEntries.flatMap(\.fields).filter { $0.type.isSecret }.count
        )
    }

    private func deleteEntries(_ ids: [String]) {
        Task {
            isWorking = true
            deletionError = nil
            guard let applyBatch else {
                deletionError = CatalogMutationUIError(
                    code: "APP_CONTROL_UNAVAILABLE",
                    message: "本机控制服务不可用，无法删除条目"
                )
                pendingEntryDeletion = nil
                isWorking = false
                return
            }
            let result = await applyBatch(CatalogBatchMutation(operations: ids.map { .deleteEntry(id: $0) }))
            switch result {
            case .success:
                selectedEntryIDs.subtract(ids)
            case let .failure(error):
                deletionError = error
            }
            pendingEntryDeletion = nil
            isWorking = false
        }
    }
}

private struct SensitiveCatalogEntryRow: View {
    let entry: SecretCatalogEntry
    let autoEdit: Bool
    let isSelecting: Bool
    let isSelected: Bool
    let toggleSelection: () -> Void
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?
    let requestDelete: () -> Void

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
    @State private var showingDetails: Bool
    @State private var revealedPlaintexts: [String: String] = [:]
    @State private var revealingKeys: Set<String> = []
    @State private var revealError: String?
    @Environment(\.scenePhase) private var scenePhase

    init(
        entry: SecretCatalogEntry,
        autoEdit: Bool = false,
        isSelecting: Bool = false,
        isSelected: Bool = false,
        toggleSelection: @escaping () -> Void = {},
        commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?,
        revealCatalogField: ((String, String) async throws -> String)?,
        replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?,
        applyBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?,
        requestDelete: @escaping () -> Void = {}
    ) {
        self.entry = entry
        self.autoEdit = autoEdit
        self.isSelecting = isSelecting
        self.isSelected = isSelected
        self.toggleSelection = toggleSelection
        self.commitEntryEdit = commitEntryEdit
        self.revealCatalogField = revealCatalogField
        self.replaceCatalogSecret = replaceCatalogSecret
        self.applyBatch = applyBatch
        self.requestDelete = requestDelete
        _draftTitle = State(initialValue: entry.title)
        _draftAliases = State(initialValue: entry.aliases.joined(separator: ", "))
        _draftTags = State(initialValue: entry.tags.joined(separator: ", "))
        _draftEndpoints = State(initialValue: entry.endpoints.map(Self.endpointLine).joined(separator: "\n"))
        _draftNotes = State(initialValue: entry.notes ?? "")
        _draftFields = State(initialValue: entry.fields)
        _editing = State(initialValue: autoEdit)
        _showingDetails = State(initialValue: autoEdit)
    }

    var body: some View {
        Group {
            if isSelecting {
                HStack(alignment: .center, spacing: 8) {
                    Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                        .font(.title3)
                        .foregroundStyle(isSelected ? .blue : .secondary)
                        .accessibilityLabel(isSelected ? "已选择" : "未选择")
                    entrySummary
                }
                .contentShape(Rectangle())
                .onTapGesture(perform: toggleSelection)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    Button {
                        showingDetails = true
                    } label: {
                        VStack(alignment: .leading, spacing: 10) {
                            entrySummary
                            HStack(spacing: 10) {
                                Label("字段 \(entry.fields.count)", systemImage: "list.bullet")
                                Label("密码 \(entry.fields.filter { $0.type.isSecret }.count)", systemImage: "lock.fill")
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                    }
                    .buttonStyle(.plain)

                    Divider()

                    HStack(spacing: 8) {
                        entryAdvancedMenu
                        Spacer()
                        Button("编辑") {
                            load(entry)
                            editing = true
                            showingDetails = true
                            editorError = nil
                        }
                        .buttonStyle(.bordered)
                        Button("删除", role: .destructive, action: requestDelete)
                            .buttonStyle(.bordered)
                            .disabled(applyBatch == nil)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 132, alignment: .topLeading)
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .sheet(isPresented: $showingDetails, onDismiss: clearSensitiveOutput) {
            entryDetails
                .frame(minWidth: 760, idealWidth: 900, minHeight: 520)
        }
        .onDisappear {
            clearSensitiveOutput()
        }
        .onChange(of: showingDetails) { _, isPresented in
            if !isPresented { clearSensitiveOutput() }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .inactive || phase == .background { clearSensitiveOutput() }
        }
    }

    private var entryDetails: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.title)
                                .font(.title2.weight(.semibold))
                            Text("条目详情 · 字段 \(entry.fields.count)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    if editing {
                        editorBody
                    } else {
                        displayBody
                    }
                    if let revealError {
                        Label(revealError, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                .padding(22)
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") {
                        showingDetails = false
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    if editing {
                        Button("取消编辑") {
                            load(entry)
                            editing = false
                            editorError = nil
                        }
                    } else {
                        Button("编辑") {
                            load(entry)
                            editing = true
                            editorError = nil
                        }
                    }
                }
            }
        }
    }

    private var entrySummary: some View {
        HStack(alignment: .center, spacing: 8) {
            Image(systemName: "key.horizontal")
                .foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title)
                    .font(.headline.weight(.semibold))
                if !entry.aliases.isEmpty {
                    Text(entry.aliases.joined(separator: "、"))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var entryAdvancedMenu: some View {
        Menu {
            Text(entry.id)
                .font(.system(.caption, design: .monospaced))
            Button("复制 Entry ID") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(entry.id, forType: .string)
            }
        } label: {
            Label("更多", systemImage: "ellipsis")
        }
        .menuStyle(.borderlessButton)
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
                        .font(.body.weight(.semibold))
                    if field.type.isSecret {
                        secretFieldValue(field)
                    } else {
                        Text(displayValue(field))
                            .font(.system(.body, design: .default))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    if !field.agentVisible {
                        Text("智能体隐藏")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    } else if field.searchable {
                        Text("可搜索")
                            .font(.caption)
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

    @ViewBuilder
    private func secretFieldValue(_ field: SecretCatalogFieldValue) -> some View {
        if let plaintext = revealedPlaintexts[field.key] {
            HStack(spacing: 6) {
                Text(plaintext)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.orange)
                Button("隐藏") {
                    revealedPlaintexts.removeValue(forKey: field.key)
                }
                .buttonStyle(.borderless)
            }
        } else if field.secretRef != nil {
            HStack(spacing: 6) {
                Text("已加密")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.orange)
                Button(revealingKeys.contains(field.key) ? "验证中…" : "解密") {
                    reveal(field)
                }
                .buttonStyle(.bordered)
                .disabled(revealCatalogField == nil || revealingKeys.contains(field.key))
            }
        } else {
            HStack(spacing: 6) {
                Text("未填写")
                    .foregroundStyle(.secondary)
                Button("填写密码") {
                    editing = true
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func reveal(_ field: SecretCatalogFieldValue) {
        guard field.secretRef != nil, let revealCatalogField else { return }
        let fieldKey = field.key
        revealingKeys.insert(fieldKey)
        revealError = nil
        Task { @MainActor in
            defer { revealingKeys.remove(fieldKey) }
            do {
                let plaintext = try await revealCatalogField(entry.id, fieldKey)
                guard showingDetails, scenePhase == .active else { return }
                revealedPlaintexts[fieldKey] = plaintext
                Task { @MainActor in
                    try? await Task.sleep(for: .seconds(45))
                    guard !Task.isCancelled, showingDetails, scenePhase == .active else { return }
                    revealedPlaintexts.removeValue(forKey: fieldKey)
                }
            } catch is CancellationError {
                return
            } catch {
                revealError = "字段解密失败或本机授权未完成"
            }
        }
    }

    private func clearSensitiveOutput() {
        revealedPlaintexts.removeAll()
        revealingKeys.removeAll()
        revealError = nil
    }

    private var editorBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("条目标题", text: $draftTitle)
                .textFieldStyle(.roundedBorder)
            HStack(spacing: 8) {
                TextField("别名（逗号分隔）", text: $draftAliases)
                    .textFieldStyle(.roundedBorder)
                TextField("标签（逗号分隔）", text: $draftTags)
                    .textFieldStyle(.roundedBorder)
            }
            TextField("服务地址：type|host|port，每行一个", text: $draftEndpoints, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
            TextEditor(text: $draftNotes)
                .font(.body)
                .frame(minHeight: 56, maxHeight: 100)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))

            HStack {
                Text("字段")
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
                    replaceSecret: replaceCatalogSecret,
                    entryID: entry.id,
                    onReplacementSuccess: { newReference in
                        pendingSecretInputs.removeValue(forKey: field.key)
                        guard let currentIndex = draftFields.firstIndex(where: { $0.key == field.key }) else { return }
                        let currentField = draftFields[currentIndex]
                        draftFields[currentIndex] = SecretCatalogFieldValue(
                            key: currentField.key,
                            label: currentField.label,
                            type: currentField.type,
                            agentVisible: currentField.agentVisible,
                            searchable: currentField.searchable,
                            value: nil,
                            secretRef: newReference
                        )
                        editorError = nil
                    },
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
                Button(isSaving ? "保存中…" : "保存条目") {
                    saveEntry()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSaving || commitEntryEdit == nil)
            }
        }
    }

    private func saveEntry() {
        let title = draftTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else {
            editorError = "条目标题不能为空"
            return
        }
        guard let endpoints = Self.parseEndpoints(draftEndpoints) else {
            editorError = "服务地址格式应为 type|host|port"
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
            let secretInputs = draftFields.compactMap { field -> CatalogSecretInput? in
                guard field.type.isSecret,
                      field.secretRef == nil,
                      let plaintext = pendingSecretInputs[field.key],
                      !plaintext.isEmpty
                else { return nil }
                return CatalogSecretInput(key: field.key, label: field.label, plaintext: plaintext)
            }
            let result = await commitEntryEdit?(updated, secretInputs)
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
                    message: "本机控制服务不可用，无法保存条目"
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
        if field.type.isSecret { return field.secretRef ?? "未绑定（保存时设置）" }
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
    @Binding var secretInput: String
    let replaceSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let entryID: String
    let onReplacementSuccess: (String) -> Void
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
    @State private var showsSecret = true
    @State private var isReplacingSecret = false
    @State private var isSubmittingReplacement = false
    @State private var errorMessage: String?

    init(
        field: SecretCatalogFieldValue,
        secretInput: Binding<String>,
        replaceSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?,
        entryID: String,
        onReplacementSuccess: @escaping (String) -> Void = { _ in },
        onUpdate: @escaping (SecretCatalogFieldValue) -> Void,
        onDelete: @escaping () -> Void,
        onMoveUp: @escaping () -> Void,
        onMoveDown: @escaping () -> Void
    ) {
        self.field = field
        self._secretInput = secretInput
        self.replaceSecret = replaceSecret
        self.entryID = entryID
        self.onReplacementSuccess = onReplacementSuccess
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
                Picker("类型", selection: Binding(
                    get: { draftType },
                    set: { value in
                        if value != .secret { secretInput = "" }
                        draftType = value
                    }
                )) {
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
                        if isReplacingSecret {
                            if showsSecret {
                                TextField("输入新密码", text: $secretInput)
                                    .textFieldStyle(.roundedBorder)
                            } else {
                                SecureField("输入新密码", text: $secretInput)
                                    .textFieldStyle(.roundedBorder)
                            }
                            Button(showsSecret ? "隐藏" : "显示") {
                                showsSecret.toggle()
                            }
                            .buttonStyle(.borderless)
                            Button("取消") {
                                secretInput = ""
                                isReplacingSecret = false
                                errorMessage = nil
                            }
                            .buttonStyle(.borderless)
                            Button(isSubmittingReplacement ? "提交中…" : "提交替换") {
                                submitSecretReplacement()
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isSubmittingReplacement || secretInput.isEmpty || replaceSecret == nil)
                        } else {
                            Text("已绑定")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                            Button("替换密码") {
                                secretInput = ""
                                errorMessage = nil
                                isReplacingSecret = true
                            }
                            .buttonStyle(.bordered)
                            .disabled(replaceSecret == nil)
                        }
                    } else {
                        if showsSecret {
                            TextField("输入密码", text: $secretInput)
                                .textFieldStyle(.roundedBorder)
                        } else {
                            SecureField("输入密码", text: $secretInput)
                                .textFieldStyle(.roundedBorder)
                        }
                        Button(showsSecret ? "隐藏" : "显示") {
                            showsSecret.toggle()
                        }
                        .buttonStyle(.borderless)
                        Text("应用字段后，保存条目时一次提交；密码不会写入 Markdown")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                valueEditor
            }

            HStack(spacing: 12) {
                Toggle("智能体可查看", isOn: $draftAgentVisible)
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
        .onDisappear {
            secretInput = ""
            isReplacingSecret = false
        }
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

    private func submitSecretReplacement() {
        guard let replaceSecret, !secretInput.isEmpty else { return }
        let plaintext = secretInput
        isSubmittingReplacement = true
        Task {
            let result = await replaceSecret(entryID, field.key, field.label, plaintext)
            secretInput = ""
            isSubmittingReplacement = false
            switch result {
            case .success(let writeResult):
                guard let newReference = writeResult.secretReference else {
                    errorMessage = "替换成功但未收到新的安全引用，请刷新目录"
                    return
                }
                isReplacingSecret = false
                errorMessage = nil
                onReplacementSuccess(newReference)
            case .failure(let error):
                errorMessage = error.displayText
            }
        }
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
        case .host: return "主机"
        case .port: return "端口"
        case .number: return "数字"
        case .boolean: return "布尔"
        case .date: return "日期"
        case .list: return "列表"
        case .secret: return "密码"
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
    let showTemplate: (() async -> Void)?

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

            HStack(spacing: 12) {
                Image(systemName: "doc.text")
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("敏感信息模板")
                        .font(.headline)
                    Text("打开 SVLT 随应用安装的只读模板副本；不会选择、接管或修改用户目录。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("查看敏感信息模板") {
                    Task { await showTemplate?() }
                }
                .buttonStyle(.bordered)
                .disabled(showTemplate == nil)
            }
            .padding(14)
            .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

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
    let entries: [CatalogSecurityAuditEntry]
    let errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                Label("智能体自动化", systemImage: "sparkles.rectangle.stack")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("最近 \(entries.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }

            Text("App 只负责本机授权和解密；SSH、HTTP、文件写入等动作由 MCP 工具执行。这里仅显示脱敏审计，不保存明文。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }

            if entries.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "clock.badge.questionmark")
                        .foregroundStyle(.secondary)
                    Text("还没有智能体使用记录。连接 MCP 后，解密显示、段落还原、本地导出等动作会出现在这里。")
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
                            Image(systemName: iconName(for: entry.operation))
                                .foregroundStyle(.blue)
                                .frame(width: 24)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(entry.operation.displayName)
                                        .font(.headline)
                                    Spacer()
                                    Text(entry.result.displayName)
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                }
                                Text(entry.target)
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                                Text("\(entry.source.displayName) · \(entry.authorizationOutcome.displayName) · \(entry.referenceCount) 个引用 · \(entry.timestamp.formatted(date: .omitted, time: .standard))")
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

    private func iconName(for operation: AuditOperation) -> String {
        switch operation {
        case .reveal:
            return "eye"
        case .catalogMutation, .formatCheck, .formatRepair:
            return "doc.badge.gearshape"
        case .authorization:
            return "person.badge.key"
        case .credentialUse:
            return "key.fill"
        case .secureExecute:
            return "cable.connector"
        default:
            return "bolt.horizontal.circle"
        }
    }
}
