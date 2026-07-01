import SwiftUI
import VaultIPC

public enum VaultWorkbenchCopy {
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

public enum VaultWorkbenchSection: String, CaseIterable, Identifiable {
    case overview
    case tutorial
    case paragraph
    case records
    case automation
    case security

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:
            return "控制台"
        case .tutorial:
            return "使用教程"
        case .paragraph:
            return "段落解密"
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
        case .tutorial:
            return "安装、加密、解密和智能体配置"
        case .paragraph:
            return "一次解密段落内全部密文引用"
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
        case .tutorial:
            return "book.closed.fill"
        case .paragraph:
            return "text.quote"
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
    let restoreParagraph: ((String) async throws -> String)?
    @State private var selectedSection: VaultWorkbenchSection = .overview
    @State private var animateAccent = false

    public init(
        status: WorkbenchStatus,
        orphanScanResult: OrphanScanResult? = nil,
        auditEntries: [AgentAutomationAuditEntry] = [],
        restoreParagraph: ((String) async throws -> String)? = nil
    ) {
        self.status = status
        self.orphanScanResult = orphanScanResult
        self.auditEntries = auditEntries
        self.restoreParagraph = restoreParagraph
    }

    public var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            ZStack {
                WorkbenchBackground(animate: animateAccent)
                selectedContent
                    .id(selectedSection)
                    .transition(.asymmetric(
                        insertion: .move(edge: .trailing).combined(with: .opacity),
                        removal: .move(edge: .leading).combined(with: .opacity)
                    ))
            }
            .animation(.spring(response: 0.34, dampingFraction: 0.86), value: selectedSection)
        }
        .navigationTitle(selectedSection.title)
        .frame(minWidth: 1080, minHeight: 720)
        .onAppear {
            animateAccent = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .vaultWorkbenchNavigate)) { notification in
            guard
                let rawValue = notification.userInfo?["section"] as? String,
                let section = VaultWorkbenchSection(rawValue: rawValue)
            else {
                return
            }
            selectedSection = section
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
        .background(.bar)
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
            WorkbenchPage(title: "控制台", subtitle: "常用功能和当前连接状态放在这里，不需要从头滚到底。", systemImage: selectedSection.systemImage) {
                overviewPage
            }
        case .tutorial:
            WorkbenchPage(title: "使用教程", subtitle: "安装、Obsidian 右键加密、段落解密和智能体配置集中到这一页。", systemImage: selectedSection.systemImage) {
                SetupGuideView(status: status)
            }
        case .paragraph:
            WorkbenchPage(title: "段落解密", subtitle: "把包含 secret:// 的整段内容粘贴进来，一次还原其中全部密文。", systemImage: selectedSection.systemImage) {
                if let restoreParagraph {
                    ParagraphRestoreView(restoreParagraph: restoreParagraph)
                } else {
                    ContentUnavailableView("段落解密暂不可用", systemImage: "lock.trianglebadge.exclamationmark", description: Text("本机服务启动完成后会启用这个功能。"))
                        .frame(maxWidth: .infinity, minHeight: 240)
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                }
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
        VStack(alignment: .leading, spacing: 18) {
            HeroCard(
                title: "让智能体使用密文引用",
                subtitle: "Codex、Claude、Hermes 在聊天里只处理 secret://；真正的解密、填充和本机使用都在这台 Mac 上完成。",
                animate: animateAccent
            )

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 16),
                GridItem(.flexible(), spacing: 16)
            ], spacing: 16) {
                ConnectionStatusCard(status: status)
                QuickMenuCard(
                    title: "开始使用",
                    detail: "打开教程页，按步骤完成 Obsidian 插件、右键加密和 MCP 配置。",
                    systemImage: "book.closed.fill",
                    tint: .blue,
                    actionTitle: "查看教程"
                ) {
                    selectedSection = .tutorial
                }
                QuickMenuCard(
                    title: "段落解密",
                    detail: "一段话里有多个 secret:// 时，在这里一次性解密显示。",
                    systemImage: "text.quote",
                    tint: .purple,
                    actionTitle: "打开解密"
                ) {
                    selectedSection = .paragraph
                }
                QuickMenuCard(
                    title: "记录维护",
                    detail: "检查笔记引用和本机记录是否匹配，避免孤立密文或失效引用。",
                    systemImage: "tray.full.fill",
                    tint: .orange,
                    actionTitle: "查看维护"
                ) {
                    selectedSection = .records
                }
            }

            AgentAutomationAuditCard(entries: Array(auditEntries.prefix(3)))
        }
    }
}

private struct WorkbenchBackground: View {
    let animate: Bool

    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor)
            Circle()
                .fill(.blue.opacity(0.16))
                .frame(width: 360, height: 360)
                .blur(radius: 80)
                .offset(x: animate ? 280 : 210, y: animate ? -250 : -190)
                .animation(.easeInOut(duration: 5.5).repeatForever(autoreverses: true), value: animate)
            Circle()
                .fill(.purple.opacity(0.10))
                .frame(width: 320, height: 320)
                .blur(radius: 90)
                .offset(x: animate ? -280 : -220, y: animate ? 260 : 210)
                .animation(.easeInOut(duration: 6.4).repeatForever(autoreverses: true), value: animate)
        }
        .ignoresSafeArea()
    }
}

private struct WorkbenchPage<Content: View>: View {
    let title: String
    let subtitle: String
    let systemImage: String
    @ViewBuilder let content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .center, spacing: 16) {
                    Image(systemName: systemImage)
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 54, height: 54)
                        .background(
                            LinearGradient(colors: [.blue, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing),
                            in: RoundedRectangle(cornerRadius: 18, style: .continuous)
                        )

                    VStack(alignment: .leading, spacing: 5) {
                        Text(title)
                            .font(.largeTitle.weight(.bold))
                        Text(subtitle)
                            .font(.title3)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(.top, 4)

                content
            }
            .padding(30)
        }
        .scrollIndicators(.automatic)
    }
}

private struct HeroCard: View {
    let title: String
    let subtitle: String
    let animate: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 22) {
            VStack(alignment: .leading, spacing: 12) {
                Text(title)
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                Text(subtitle)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .lineSpacing(4)
                HStack(spacing: 10) {
                    Label("密文引用", systemImage: "link")
                    Label("本机授权", systemImage: "touchid")
                    Label("脱敏审计", systemImage: "checkmark.shield")
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            }

            Spacer()

            ZStack {
                RoundedRectangle(cornerRadius: 28, style: .continuous)
                    .fill(.blue.opacity(0.12))
                    .frame(width: 150, height: 150)
                    .rotationEffect(.degrees(animate ? 8 : -8))
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 70, weight: .semibold))
                    .foregroundStyle(
                        LinearGradient(colors: [.blue, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing)
                    )
                    .scaleEffect(animate ? 1.06 : 0.96)
            }
            .animation(.easeInOut(duration: 3.8).repeatForever(autoreverses: true), value: animate)
        }
        .padding(28)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 28, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .stroke(.white.opacity(0.20))
        )
    }
}

private struct QuickMenuCard: View {
    let title: String
    let detail: String
    let systemImage: String
    let tint: Color
    let actionTitle: String
    let action: () -> Void
    @State private var isHovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: systemImage)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 46, height: 46)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

            Text(title)
                .font(.title3.weight(.semibold))
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(3)

            Spacer(minLength: 0)

            Button(actionTitle, action: action)
                .buttonStyle(.borderedProminent)
        }
        .padding(20)
        .frame(maxWidth: .infinity, minHeight: 210, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .stroke(isHovering ? tint.opacity(0.35) : .white.opacity(0.12))
        )
        .scaleEffect(isHovering ? 1.015 : 1)
        .animation(.spring(response: 0.24, dampingFraction: 0.82), value: isHovering)
        .onHover { isHovering = $0 }
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
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
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
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
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
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
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
