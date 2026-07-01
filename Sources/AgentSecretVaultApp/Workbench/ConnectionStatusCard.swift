import SwiftUI
import VaultIPC

public struct ConnectionStatusCard: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("当前状态")
                .font(.title3.weight(.semibold))

            HStack(spacing: 12) {
                StatusPill(
                    title: "插件",
                    value: status.pluginConnected ? "已连接" : "未连接",
                    systemImage: status.pluginConnected ? "checkmark.seal.fill" : "exclamationmark.triangle.fill",
                    tint: status.pluginConnected ? .green : .orange
                )
                StatusPill(
                    title: "保险箱",
                    value: status.locked ? "已锁定" : "已解锁",
                    systemImage: status.locked ? "lock.fill" : "lock.open.fill",
                    tint: status.locked ? .gray : .blue
                )
                StatusPill(
                    title: "本机通道",
                    value: status.ipcAvailable ? "可用" : "未就绪",
                    systemImage: status.ipcAvailable ? "bolt.horizontal.circle.fill" : "bolt.slash.circle.fill",
                    tint: status.ipcAvailable ? .green : .orange
                )
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("知识库位置")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(status.activeKnowledgeBaseRoot ?? "尚未选择")
                    .font(.system(.callout, design: .monospaced))
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

private struct StatusPill: View {
    let title: String
    let value: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.headline)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
