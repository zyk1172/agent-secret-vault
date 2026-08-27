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
                    Text("知识库密文保险箱")
                        .font(.headline)
                    Text("明文只在本机处理")
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
                title: "加密文本",
                systemImage: "text.badge.lock",
                description: "在知识库中选择敏感文本，并把它替换为 secret:// 引用。"
            )
        case .revealSecret:
            SecureViewerView(model: secureViewerModel)
        case .agentSend:
            WorkflowInfoView(
                title: "智能体发送",
                systemImage: "paperplane",
                description: "对外发送需要重新授权，并且返回内容会经过脱敏处理。"
            )
        case .tutorial:
            OverviewGuideView()
        }
    }
}

public enum DashboardSection: String, CaseIterable, Identifiable {
    case overview
    case encryptText
    case revealSecret
    case agentSend
    case tutorial

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: "总览"
        case .encryptText: "加密文本"
        case .revealSecret: "查看明文"
        case .agentSend: "智能体发送"
        case .tutorial: "使用教程"
        }
    }

    public var symbolName: String {
        switch self {
        case .overview: "rectangle.grid.2x2"
        case .encryptText: "text.badge.lock"
        case .revealSecret: "eye"
        case .agentSend: "paperplane"
        case .tutorial: "book.closed.fill"
        }
    }
}

private struct WorkflowInfoView: View {
    let title: String
    let systemImage: String
    let description: String

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(title, systemImage: systemImage)
                .font(.largeTitle.weight(.bold))
            Text(description)
                .foregroundStyle(.secondary)
            Text("这是说明页，不会直接执行加密操作。")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
