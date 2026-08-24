import SwiftUI

public struct AgentServiceStatusView: View {
    public let status: AgentServiceStatus
    @State private var actionFailed = false

    public init(status: AgentServiceStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(
                    "后台 Agent",
                    systemImage: status == .running ? "checkmark.circle.fill" : "server.rack"
                )
                Spacer()
                Text(status.displayName)
                    .foregroundStyle(status == .running ? .green : .secondary)
            }
            HStack(spacing: 8) {
                Button("启用") {
                    perform { try AgentServiceRegistration.shared.register() }
                }
                Button("停用") {
                    perform { try AgentServiceRegistration.shared.unregister() }
                }
                Button("重启") {
                    Task { @MainActor in
                        do {
                            try await AgentServiceRegistration.shared.restart()
                            actionFailed = false
                        } catch {
                            actionFailed = true
                        }
                    }
                }
            }
            .buttonStyle(.borderless)
            if actionFailed {
                Text("无法更新后台 Agent 状态")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Text("SVLT.app 退出后 Agent 仍由 launchd 管理。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 12))
    }

    private func perform(_ action: () throws -> Void) {
        do {
            try action()
            actionFailed = false
        } catch {
            actionFailed = true
        }
    }
}
