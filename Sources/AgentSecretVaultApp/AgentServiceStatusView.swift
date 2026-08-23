import SwiftUI

public struct AgentServiceStatusView: View {
    @State private var currentStatus: AgentServiceStatus

    public init(status: AgentServiceStatus) {
        _currentStatus = State(initialValue: status)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(
                    "后台 Agent",
                    systemImage: currentStatus == .running ? "checkmark.circle.fill" : "server.rack"
                )
                Spacer()
                Text(currentStatus.displayName)
                    .foregroundStyle(currentStatus == .running ? .green : .secondary)
            }
            HStack(spacing: 8) {
                Button("启用") {
                    perform { try AgentServiceRegistration.shared.register() }
                }
                Button("停用") {
                    perform { try AgentServiceRegistration.shared.unregister() }
                }
                Button("重启") {
                    perform { try AgentServiceRegistration.shared.restart() }
                }
            }
            .buttonStyle(.borderless)
            Text("SVLT.app 退出后 Agent 仍由 launchd 管理。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 12))
    }

    private func refresh() {
        currentStatus = AgentServiceRegistration.shared.status
    }

    private func perform(_ action: () throws -> Void) {
        do {
            try action()
            refresh()
        } catch {
            currentStatus = .unavailable
        }
    }
}
