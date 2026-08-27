import AppKit
import SwiftUI
import VaultCore
import VaultService

public struct MenuBarVaultPanel: View {
    public static let statusItemSymbol = MenuBarPresentation.statusItemSymbol
    public static let supportedSections = VaultWorkbenchSection.allCases

    let status: WorkbenchStatus
    let auditEntries: [CatalogSecurityAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let refreshSavedReferences: () async -> Void
    let clearRevealSessions: () async -> Void
    let requestTermination: () async -> Void

    @Environment(\.openWindow) private var openWindow
    @State private var selectedSection: VaultWorkbenchSection = .overview
    @State private var copiedReference: String?
    @State private var isRefreshing = false

    public init(
        status: WorkbenchStatus,
        auditEntries: [CatalogSecurityAuditEntry],
        savedReferences: [SecretReferenceMetadata],
        refreshSavedReferences: @escaping () async -> Void,
        clearRevealSessions: @escaping () async -> Void,
        requestTermination: @escaping () async -> Void
    ) {
        self.status = status
        self.auditEntries = auditEntries
        self.savedReferences = savedReferences
        self.refreshSavedReferences = refreshSavedReferences
        self.clearRevealSessions = clearRevealSessions
        self.requestTermination = requestTermination
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: Self.statusItemSymbol)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text(selectedSection.title)
                        .font(.headline)
                    Text(headerSubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(14)
            .background(
                LinearGradient(
                    colors: [Color.blue.opacity(0.16), Color.indigo.opacity(0.06)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: 16, style: .continuous)
            )

            HStack(spacing: 4) {
                ForEach(Self.supportedSections) { section in
                    Button {
                        selectedSection = section
                    } label: {
                        Image(systemName: section.systemImage)
                            .frame(width: 30, height: 28)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(selectedSection == section ? Color.accentColor : Color.secondary)
                    .background(
                        selectedSection == section ? Color.accentColor.opacity(0.12) : .clear,
                        in: RoundedRectangle(cornerRadius: 6, style: .continuous)
                    )
                    .accessibilityLabel(section.title)
                    .accessibilityValue(selectedSection == section ? "已选中" : "未选中")
                    .help(section.title)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 12)
            .padding(.bottom, 10)

            Divider()
            ScrollView { compactContent.padding(14) }
            Divider()

            HStack {
                Button("打开主窗口") {
                    openMainWindow()
                }
                Spacer()
                Button("锁定") { clearSensitiveState() }
                Button("退出") {
                    clearSensitiveState()
                    Task { await requestTermination() }
                }
            }
            .buttonStyle(.borderless)
            .padding(12)
        }
        .frame(width: MenuBarPresentation.panelSize.width, height: MenuBarPresentation.panelSize.height)
        .onDisappear { clearSensitiveState() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            clearSensitiveState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            clearSensitiveState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
            clearSensitiveState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
            clearSensitiveState()
        }
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .background(
            LinearGradient(
                colors: [Color.blue.opacity(0.08), Color.purple.opacity(0.05)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 18, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.white.opacity(0.18), lineWidth: 1)
                .allowsHitTesting(false)
        }
    }

    @ViewBuilder
    private var compactContent: some View {
        switch selectedSection {
        case .overview:
            overview
        case .secrets:
            savedReferencesView
        case .automation:
            auditView(entries: Array(auditEntries.prefix(6)))
        case .tutorial:
            tutorialView
        case .faq:
            faqView
        }
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                statusValue("本机通道", status.ipcAvailable)
                statusValue("策略引擎", status.ready && !status.approvalPending)
                statusValue("插件", status.pluginConnected)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("当前目录")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(status.activeKnowledgeBaseRoot ?? "尚未选择")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }

            Text("快捷入口")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                shortcut(.secrets)
                shortcut(.automation)
                shortcut(.tutorial)
            }

            Text("最近安全活动")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            auditView(entries: Array(auditEntries.prefix(2)))
        }
    }

    private func statusValue(_ title: String, _ available: Bool) -> some View {
        let tint = available ? Color.green : Color.secondary

        return VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(available ? "可用" : "未就绪")
                .font(.callout.weight(.semibold))
                .foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(
            LinearGradient(
                colors: [tint.opacity(0.13), Color(nsColor: .controlBackgroundColor).opacity(0.78)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(tint.opacity(0.12), lineWidth: 1)
                .allowsHitTesting(false)
        }
    }

    private func shortcut(_ section: VaultWorkbenchSection) -> some View {
        Button {
            selectedSection = section
        } label: {
            Label(section.title, systemImage: section.systemImage)
                .font(.caption.weight(.medium))
                .frame(maxWidth: .infinity, minHeight: 42)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
        .background(
            LinearGradient(
                colors: [Color(nsColor: .controlBackgroundColor).opacity(0.82), Color.blue.opacity(0.07)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(Color.secondary.opacity(0.12), lineWidth: 1)
                .allowsHitTesting(false)
        }
    }

    private var tutorialView: some View {
        VStack(alignment: .leading, spacing: 10) {
            compactSectionHeader("使用教程", systemImage: VaultWorkbenchSection.tutorial.systemImage)
            compactInfoRow(
                title: "开始使用",
                systemImage: "1.circle.fill",
                text: "选择敏感信息目录后，在分组中创建条目。"
            )
            compactInfoRow(
                title: "查看密码",
                systemImage: "2.circle.fill",
                text: "密码默认显示为已加密；解密前需要本机授权。"
            )
            compactInfoRow(
                title: "交给智能体",
                systemImage: "3.circle.fill",
                text: "只传递 secret:// 引用和允许展示的元数据，明文留在本机。"
            )
            compactInfoRow(
                title: "批准目录修改",
                systemImage: "4.circle.fill",
                text: "每次修改单独授权，使用后立即消费。"
            )
        }
    }

    private var faqView: some View {
        VStack(alignment: .leading, spacing: 10) {
            compactSectionHeader("常见问题", systemImage: VaultWorkbenchSection.faq.systemImage)
            compactInfoRow(
                title: "为什么看不到密码？",
                systemImage: "questionmark.circle.fill",
                text: "这是默认行为。完成本机授权后，密码才会短暂显示。"
            )
            compactInfoRow(
                title: "可以在 Obsidian 里编辑吗？",
                systemImage: "questionmark.circle.fill",
                text: "可以。SVLT 会负责校验、授权和本机密文记录。"
            )
            compactInfoRow(
                title: "智能体会看到什么？",
                systemImage: "questionmark.circle.fill",
                text: "智能体只能看到 secret:// 引用和允许展示的元数据。"
            )
        }
    }

    private func compactSectionHeader(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.headline.weight(.semibold))
            .foregroundStyle(.primary)
    }

    private func compactInfoRow(title: String, systemImage: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: systemImage)
                .foregroundStyle(.blue)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            Color(nsColor: .controlBackgroundColor).opacity(0.72),
            in: RoundedRectangle(cornerRadius: 9, style: .continuous)
        )
    }

    private var headerSubtitle: String {
        switch selectedSection {
        case .overview:
            return statusSummary
        case .secrets:
            return "分组目录与独立加密记录"
        case .automation:
            return "查看脱敏后的本机使用记录"
        case .tutorial:
            return "安全使用与本机授权说明"
        case .faq:
            return "常见问题与使用说明"
        }
    }

    private var savedReferencesView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("已保存密文")
                    .font(.headline)
                Spacer()
                Button {
                    Task {
                        isRefreshing = true
                        await refreshSavedReferences()
                        isRefreshing = false
                    }
                } label: {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
                .disabled(isRefreshing)
            }

            if savedReferences.isEmpty {
                Text("还没有保存的密文。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(savedReferences, id: \.reference) { metadata in
                    VStack(alignment: .leading, spacing: 7) {
                        Text(SavedReferenceDisplay.title(for: metadata))
                            .font(.callout.weight(.semibold))
                        Text(SavedReferenceDisplay.text(for: metadata))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(3)
                        HStack {
                            Spacer()
                            Button(copiedReference == metadata.reference ? "已复制" : "复制") {
                                copy(SavedReferenceDisplay.text(for: metadata), for: metadata.reference)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .padding(10)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
        }
    }

    private func auditView(entries: [CatalogSecurityAuditEntry]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if entries.isEmpty {
                Text("还没有持久化安全活动。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(entries) { entry in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(entry.operation.displayName)
                                .font(.callout.weight(.semibold))
                            Spacer()
                            Text(entry.result.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(entry.target)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                        Text("\(entry.source.displayName) · \(entry.authorizationOutcome.displayName) · \(entry.timestamp.formatted(date: .omitted, time: .standard))")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(9)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
        }
    }

    private var statusSummary: String {
        if !status.ipcAvailable { return "本机通道未就绪" }
        if status.approvalPending { return "等待本机审批" }
        if !status.ready { return "策略引擎不可用" }
        return status.pluginConnected ? "本机通道和插件可用" : "等待 Obsidian 插件连接"
    }

    private func copy(_ text: String, for reference: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copiedReference = reference
    }

    private func clearSensitiveState() {
        Task { await clearRevealSessions() }
    }

    private func openMainWindow() {
        let section = selectedSection
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: MenuBarPresentation.mainWindowID)
        DispatchQueue.main.async {
            NotificationCenter.default.post(
                name: .vaultWorkbenchNavigate,
                object: nil,
                userInfo: ["section": section.rawValue]
            )
        }
    }
}
