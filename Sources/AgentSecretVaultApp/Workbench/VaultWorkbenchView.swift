import SwiftUI
import VaultIPC

public enum VaultWorkbenchCopy {
    public static let disconnected = (
        status: "Obsidian plugin is not connected.",
        primaryAction: "Install Obsidian plugin and pair it with this Mac app."
    )

    public static let securityBoundary =
        "The plugin does not receive decrypted values. Paragraph reveal opens an app-owned temporary window."
}

public struct VaultWorkbenchView: View {
    let status: WorkbenchStatus
    let orphanScanResult: OrphanScanResult?

    public init(status: WorkbenchStatus, orphanScanResult: OrphanScanResult? = nil) {
        self.status = status
        self.orphanScanResult = orphanScanResult
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Agent Secret Vault Workbench · 知识库加密工作台")
                    .font(.largeTitle.weight(.bold))
                ConnectionStatusCard(status: status)
                SetupGuideView(status: status)
                OrphanReviewView(result: orphanScanResult) { _ in }
                Text(VaultWorkbenchCopy.securityBoundary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .padding(28)
        }
        .frame(minWidth: 920, minHeight: 620)
    }
}
