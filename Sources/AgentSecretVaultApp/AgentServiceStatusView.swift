import SwiftUI

public struct AgentServiceStatusView: View {
    public let status: AgentServiceStatus
    public let actionInFlight: Bool
    public let actionErrorMessage: String?
    public let enableAgent: (() async -> Void)?
    public let disableAgent: (() async -> Void)?
    public let restartAgent: (() async -> Void)?

    public init(
        status: AgentServiceStatus,
        actionInFlight: Bool = false,
        actionErrorMessage: String? = nil,
        enableAgent: (() async -> Void)? = nil,
        disableAgent: (() async -> Void)? = nil,
        restartAgent: (() async -> Void)? = nil
    ) {
        self.status = status
        self.actionInFlight = actionInFlight
        self.actionErrorMessage = actionErrorMessage
        self.enableAgent = enableAgent
        self.disableAgent = disableAgent
        self.restartAgent = restartAgent
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
                    run(enableAgent)
                }
                .disabled(actionInFlight || enableAgent == nil || status == .running || status == .registered)
                Button("停用") {
                    run(disableAgent)
                }
                .disabled(actionInFlight || disableAgent == nil || status == .disabled || status == .notRegistered)
                Button("重启") {
                    run(restartAgent)
                }
                .disabled(actionInFlight || restartAgent == nil || status == .notRegistered)
            }
            .buttonStyle(.borderless)
            if actionInFlight {
                ProgressView()
                    .controlSize(.small)
            }
            if let actionErrorMessage {
                Text(actionErrorMessage)
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

    private func run(_ action: (() async -> Void)?) {
        guard let action else { return }
        Task { await action() }
    }
}
