import SwiftUI

public struct VaultDashboardView: View {
    @Bindable private var secureViewerModel: SecureViewerModel
    @State private var selectedSection: DashboardSection = .overview

    public init(secureViewerModel: SecureViewerModel) {
        self.secureViewerModel = secureViewerModel
    }

    public var body: some View {
        NavigationSplitView {
            List(DashboardSection.allCases, selection: $selectedSection) { section in
                Label(section.title, systemImage: section.symbolName)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 230)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Agent Secret Vault")
                        .font(.headline)
                    Text("Local-only secret bridge")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
        } detail: {
            detailView
        }
        .frame(minWidth: 920, minHeight: 620)
    }

    @ViewBuilder
    private var detailView: some View {
        switch selectedSection {
        case .overview:
            OverviewGuideView()
        case .encryptText:
            WorkflowInfoView(
                title: "Encrypt Text · 加密文本",
                systemImage: "text.badge.lock",
                englishBody: "Select sensitive text in your knowledge base and replace it with a secret:// reference.",
                chineseBody: "在知识库中选择敏感文本，并把它替换为 secret:// 引用。"
            )
        case .revealSecret:
            SecureViewerView(model: secureViewerModel)
        case .agentSend:
            WorkflowInfoView(
                title: "Agent Send · Agent 发送",
                systemImage: "paperplane",
                englishBody: "External-send actions require fresh authorization and sanitized outputs.",
                chineseBody: "对外发送需要重新授权，并且返回内容会经过脱敏处理。"
            )
        case .orphanReview:
            WorkflowInfoView(
                title: "Orphan Review · 孤立记录检查",
                systemImage: "tray.full",
                englishBody: "Run an orphan scan before reviewing encrypted records. Scanning only finds candidates; deletion still requires separate highest-risk authorization.",
                chineseBody: "先运行孤立记录扫描，再查看候选加密记录。扫描只会找出候选项；删除仍然需要单独完成最高风险级别授权。"
            )
        case .securityModel:
            SecurityModelSummaryView()
        }
    }
}

public enum DashboardSection: String, CaseIterable, Identifiable {
    case overview
    case encryptText
    case revealSecret
    case agentSend
    case orphanReview
    case securityModel

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: "Overview"
        case .encryptText: "Encrypt Text"
        case .revealSecret: "Reveal Secret"
        case .agentSend: "Agent Send"
        case .orphanReview: "Orphan Review"
        case .securityModel: "Security Model"
        }
    }

    public var symbolName: String {
        switch self {
        case .overview: "rectangle.grid.2x2"
        case .encryptText: "text.badge.lock"
        case .revealSecret: "eye"
        case .agentSend: "paperplane"
        case .orphanReview: "tray.full"
        case .securityModel: "shield.lefthalf.filled"
        }
    }
}

private struct WorkflowInfoView: View {
    let title: String
    let systemImage: String
    let englishBody: String
    let chineseBody: String

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(title, systemImage: systemImage)
                .font(.largeTitle.weight(.bold))
            Text(englishBody)
                .foregroundStyle(.secondary)
            Text(chineseBody)
                .foregroundStyle(.secondary)
            Text("This section documents the safe workflow for the first UI release.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct SecurityModelSummaryView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Security Model · 安全模型")
                    .font(.largeTitle.weight(.bold))
                ForEach(VaultUICopy.securityBoundaries) { boundary in
                    SecurityBoundaryCard(boundary: boundary)
                }
            }
            .padding(28)
        }
    }
}
