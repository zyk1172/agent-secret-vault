import SwiftUI
import VaultIPC

public struct ConnectionStatusCard: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(status.pluginConnected ? "Plugin connected · 插件已连接" : "Plugin not connected · 插件未连接",
                  systemImage: status.pluginConnected ? "checkmark.seal.fill" : "exclamationmark.triangle")
            Text("Vault: \(status.locked ? "Locked" : "Unlocked")")
            Text("Knowledge base: \(status.activeKnowledgeBaseRoot ?? "Not selected")")
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}
