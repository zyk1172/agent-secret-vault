import AppKit
import SwiftUI
import VaultIPC

public struct MenuBarVaultPanel: View {
    public static let statusItemSymbol = MenuBarPresentation.statusItemSymbol
    public static let supportedSections = VaultWorkbenchSection.allCases
    let status: WorkbenchStatus
    let orphanScanResult: OrphanScanResult?
    let auditEntries: [AgentAutomationAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let restoreParagraph: (String) async throws -> String
    let refreshSavedReferences: () async -> Void
    let clearRevealSessions: () async -> Void
    let requestTermination: () async -> Void
    @Environment(\.openWindow) private var openWindow
    @State private var selectedSection: VaultWorkbenchSection = .overview
    @State private var restoreState = MenuBarParagraphRestoreState()
    @State private var copiedReference: String?
    @State private var isRefreshing = false

    public init(status: WorkbenchStatus, orphanScanResult: OrphanScanResult?, auditEntries: [AgentAutomationAuditEntry], savedReferences: [SecretReferenceMetadata], restoreParagraph: @escaping (String) async throws -> String, refreshSavedReferences: @escaping () async -> Void, clearRevealSessions: @escaping () async -> Void, requestTermination: @escaping () async -> Void) {
        self.status = status; self.orphanScanResult = orphanScanResult; self.auditEntries = auditEntries; self.savedReferences = savedReferences
        self.restoreParagraph = restoreParagraph; self.refreshSavedReferences = refreshSavedReferences; self.clearRevealSessions = clearRevealSessions; self.requestTermination = requestTermination
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: Self.statusItemSymbol).font(.title3.weight(.semibold)).foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 2) { Text(selectedSection.title).font(.headline); Text(statusSummary).font(.caption).foregroundStyle(.secondary) }
                Spacer()
            }.padding(14)
            HStack(spacing: 4) {
                ForEach(Self.supportedSections) { section in
                    Button { selectedSection = section } label: { Image(systemName: section.systemImage).frame(width: 30, height: 28).contentShape(Rectangle()) }
                        .buttonStyle(.plain).foregroundStyle(selectedSection == section ? Color.accentColor : Color.secondary)
                        .background(selectedSection == section ? Color.accentColor.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .accessibilityLabel(section.title).help(section.title)
                }
            }.frame(maxWidth: .infinity).padding(.horizontal, 12).padding(.bottom, 10)
            Divider()
            ScrollView { compactContent.padding(14) }
            Divider()
            HStack {
                Button("打开主窗口") { NSApp.activate(ignoringOtherApps: true); openWindow(id: MenuBarPresentation.mainWindowID) }
                Spacer()
                Button("退出") { Task { await requestTermination() } }
            }.buttonStyle(.borderless).padding(12)
        }
        .frame(width: MenuBarPresentation.panelSize.width, height: MenuBarPresentation.panelSize.height)
        .onDisappear { clearSensitiveState() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in clearSensitiveState() }
    }

    @ViewBuilder private var compactContent: some View {
        switch selectedSection {
        case .overview: overview
        case .paragraph: MenuBarParagraphRestoreView(state: restoreState, restoreParagraph: restoreParagraph)
        case .secrets: savedReferencesView
        case .records: recordsView
        case .automation: auditView(entries: Array(auditEntries.prefix(6)))
        case .security: securityView
        }
    }
    private var overview: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) { statusValue("本机通道", status.ipcAvailable); statusValue("保险箱", !status.locked); statusValue("插件", status.pluginConnected) }
            Text("快捷入口").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            HStack(spacing: 8) { shortcut(.paragraph); shortcut(.secrets); shortcut(.records) }
            Text("最近动作").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            auditView(entries: Array(auditEntries.prefix(2)))
        }
    }
    private func statusValue(_ title: String, _ available: Bool) -> some View { VStack(alignment: .leading, spacing: 4) { Text(title).font(.caption).foregroundStyle(.secondary); Text(available ? "可用" : "未就绪").font(.callout.weight(.semibold)).foregroundStyle(available ? Color.green : Color.secondary) }.frame(maxWidth: .infinity, alignment: .leading).padding(10).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous)) }
    private func shortcut(_ section: VaultWorkbenchSection) -> some View { Button { selectedSection = section } label: { Label(section.title, systemImage: section.systemImage).font(.caption.weight(.medium)).frame(maxWidth: .infinity, minHeight: 42) }.buttonStyle(.bordered) }
    private var savedReferencesView: some View { VStack(alignment: .leading, spacing: 12) {
        HStack { Text("已保存密文").font(.headline); Spacer(); Button { Task { isRefreshing = true; await refreshSavedReferences(); isRefreshing = false } } label: { Label("刷新", systemImage: "arrow.clockwise") }.disabled(isRefreshing) }
        if savedReferences.isEmpty { Text("还没有保存的密文。").font(.callout).foregroundStyle(.secondary) } else { ForEach(savedReferences, id: \.reference) { metadata in VStack(alignment: .leading, spacing: 7) { Text(SavedReferenceDisplay.title(for: metadata)).font(.callout.weight(.semibold)); Text(SavedReferenceDisplay.text(for: metadata)).font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(3); HStack { Spacer(); Button(copiedReference == metadata.reference ? "已复制" : "复制") { copy(SavedReferenceDisplay.text(for: metadata), for: metadata.reference) }.buttonStyle(.bordered) } }.padding(10).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous)) } }
    } }
    private var recordsView: some View { let missing = orphanScanResult?.missingRecords.count ?? 0; let unreferenced = orphanScanResult?.unreferencedRecords.count ?? 0; return VStack(alignment: .leading, spacing: 12) { Text("记录维护").font(.headline); HStack(spacing: 8) { countValue("缺少本机记录", missing); countValue("未被笔记引用", unreferenced) }; Text(orphanScanResult == nil ? "尚未扫描。请先在 Obsidian 插件中发起扫描。" : "这里不会直接删除；删除前必须单独完成本机高风险授权。").font(.callout).foregroundStyle(.secondary) } }
    private func countValue(_ title: String, _ count: Int) -> some View { VStack(alignment: .leading, spacing: 4) { Text(title).font(.caption).foregroundStyle(.secondary); Text("\(count)").font(.title3.weight(.semibold)) }.frame(maxWidth: .infinity, alignment: .leading).padding(10).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous)) }
    private func auditView(entries: [AgentAutomationAuditEntry]) -> some View { VStack(alignment: .leading, spacing: 8) { if entries.isEmpty { Text("还没有脱敏后的本机使用记录。").font(.callout).foregroundStyle(.secondary) } else { ForEach(entries) { entry in VStack(alignment: .leading, spacing: 3) { HStack { Text(entry.action).font(.callout.weight(.semibold)); Spacer(); Text(entry.result).font(.caption).foregroundStyle(.secondary) }; Text(entry.target).font(.caption).foregroundStyle(.secondary).lineLimit(2) }.padding(9).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous)) } } } }
    private var securityView: some View { VStack(alignment: .leading, spacing: 10) { Text("安全边界").font(.headline); fact("聊天中允许", "secret:// 引用和非敏感上下文"); fact("明文位置", "仅在本机授权后的窗口短暂显示"); fact("智能体禁止", "密码、token 和 Authorization header"); fact("高风险动作", "删除和外发都需要本机授权") } }
    private func fact(_ title: String, _ detail: String) -> some View { VStack(alignment: .leading, spacing: 2) { Text(title).font(.caption.weight(.semibold)); Text(detail).font(.caption).foregroundStyle(.secondary) } }
    private var statusSummary: String { !status.ipcAvailable ? "本机通道未就绪" : (status.locked ? "保险箱已锁定" : (status.pluginConnected ? "本机通道和插件可用" : "等待 Obsidian 插件连接")) }
    private func copy(_ text: String, for reference: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string); copiedReference = reference }
    private func clearSensitiveState() { restoreState.clearSensitiveOutput(); Task { await clearRevealSessions() } }
}
