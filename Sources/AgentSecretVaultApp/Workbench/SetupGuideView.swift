import SwiftUI
import VaultIPC

public struct SetupGuideView: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Next steps · 下一步")
                .font(.title3.weight(.semibold))
            Text(status.pluginConnected
                 ? "Use Obsidian commands to encrypt selections, scan notes, and request app-owned paragraph reveal."
                 : VaultWorkbenchCopy.disconnected.primaryAction)
            Text("No placeholder page is treated as a working encryption tool.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}
