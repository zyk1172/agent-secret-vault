import AppKit
import SwiftUI
import VaultCore
import VaultIPC

public enum VaultWorkbenchCopy {
    public static let documentationURL = URL(string: "https://github.com/zyk1172/agent-secret-vault")!

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
            "agent-secret-vault": {
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

    public static let agentPrompt = """
    看到 secret:// 就自动使用 agent-secret-vault；不要让我粘贴明文。
    """
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
            return "密文库"
        case .records:
            return "记录维护"
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
            return "保存用过的 secret:// 引用，下次直接复制使用"
        case .records:
            return "扫描孤立引用和本机记录"
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
    let orphanScanResult: OrphanScanResult?
    let auditEntries: [AgentAutomationAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let restoreParagraph: ((String) async throws -> RestoredParagraph)?
    let refreshSavedReferences: (() async -> Void)?
    @State private var selectedSection: VaultWorkbenchSection = .overview

    public init(
        status: WorkbenchStatus,
        orphanScanResult: OrphanScanResult? = nil,
        auditEntries: [AgentAutomationAuditEntry] = [],
        savedReferences: [SecretReferenceMetadata] = [],
        restoreParagraph: ((String) async throws -> RestoredParagraph)? = nil,
        refreshSavedReferences: (() async -> Void)? = nil
    ) {
        self.status = status
        self.orphanScanResult = orphanScanResult
        self.auditEntries = auditEntries
        self.savedReferences = savedReferences
        self.restoreParagraph = restoreParagraph
        self.refreshSavedReferences = refreshSavedReferences
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
            WorkbenchPage(title: "密文库", subtitle: "保存使用过的敏感信息引用，只展示密文，不展示明文。", systemImage: selectedSection.systemImage) {
                SavedSecretReferencesCard(references: savedReferences, refresh: refreshSavedReferences)
            }
        case .records:
            WorkbenchPage(title: "记录维护", subtitle: "检查笔记引用和本机加密记录是否一致。", systemImage: selectedSection.systemImage) {
                OrphanReviewView(result: orphanScanResult) { _ in }
            }
        case .automation:
            WorkbenchPage(title: "智能体自动化", subtitle: "只显示脱敏审计。密码、token、Authorization header 不会进入这里。", systemImage: selectedSection.systemImage) {
                AgentAutomationAuditCard(entries: auditEntries)
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
                    title: "保险箱",
                    value: status.locked ? "已锁定" : "已解锁",
                    systemImage: status.locked ? "lock.fill" : "lock.open.fill",
                    tint: status.locked ? .gray : .blue
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
            Label(status.locked ? "保险箱已锁定" : "保险箱已解锁", systemImage: status.locked ? "lock.fill" : "lock.open.fill")
                .foregroundStyle(status.locked ? Color.secondary : Color.blue)
        }
        .font(.caption.weight(.medium))
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
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
