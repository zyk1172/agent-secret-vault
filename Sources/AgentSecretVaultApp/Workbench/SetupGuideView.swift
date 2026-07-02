import AppKit
import SwiftUI
import VaultIPC

public struct SetupGuideView: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("日常使用")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("三步完成")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(.quaternary, in: Capsule())
            }

            VStack(spacing: 10) {
                ForEach(Array(VaultWorkbenchCopy.simpleUsageSteps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .top, spacing: 12) {
                        Text("\(index + 1)")
                            .font(.headline)
                            .foregroundStyle(.white)
                            .frame(width: 26, height: 26)
                            .background(.blue, in: Circle())
                        Text(step.replacingOccurrences(of: "\(index + 1). ", with: ""))
                            .font(.body)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(12)
                    .background(.background.opacity(0.75), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
            }

            Divider()

            HStack(alignment: .center, spacing: 12) {
                Label(
                    status.pluginConnected ? "插件已连接，可以直接右键加密。" : VaultWorkbenchCopy.disconnected.primaryAction,
                    systemImage: status.pluginConnected ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                )
                .font(.callout.weight(.medium))
                .foregroundStyle(status.pluginConnected ? .green : .orange)

                Spacer()

                Button("复制自动化配置") {
                    copyToPasteboard(VaultWorkbenchCopy.mcpConfig)
                }

                Button("复制备用指令") {
                    copyToPasteboard(VaultWorkbenchCopy.agentPrompt)
                }
            }

            Text("正常情况下，智能体看到 secret:// 会自动调用安全工具；备用指令只用于不支持自动加载规则的客户端。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
