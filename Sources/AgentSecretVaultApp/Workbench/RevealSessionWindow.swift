import SwiftUI
import VaultIPC

public enum RevealSessionWindowLayout {
    public static let contentSize = CGSize(width: 560, height: 320)
    public static let minimumSize = CGSize(width: 480, height: 240)
}

public struct RevealSessionWindow: View {
    let restoredParagraph: RestoredParagraph
    let close: () -> Void
    @State private var pendingCopyIndex: Int?

    public init(restoredParagraph: RestoredParagraph, close: @escaping () -> Void) {
        self.restoredParagraph = restoredParagraph
        self.close = close
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "eye.fill")
                    .foregroundStyle(.blue)
                Text("临时解密显示")
            }
                .font(.title2.weight(.semibold))
            Text("明文只在本机窗口显示，关闭后会清除。")
                .font(.callout)
                .foregroundStyle(.secondary)
            ScrollView {
                Text(restoredParagraph.text)
                    .textSelection(.enabled)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                ForEach(Array(restoredParagraph.values.enumerated()), id: \.offset) { index, _ in
                    Button("复制密文 \(index + 1)") {
                        pendingCopyIndex = index
                    }
                }
                Spacer()
                Button("关闭并清除", action: close)
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(22)
        .confirmationDialog("确认复制明文到剪贴板？", isPresented: Binding(
            get: { pendingCopyIndex != nil },
            set: { if !$0 { pendingCopyIndex = nil } }
        )) {
            Button("复制明文") {
                if let index = pendingCopyIndex, restoredParagraph.values.indices.contains(index) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(restoredParagraph.values[index], forType: .string)
                }
                pendingCopyIndex = nil
            }
            Button("取消", role: .cancel) { pendingCopyIndex = nil }
        } message: {
            Text("只在准备立即粘贴时复制。明文会进入系统剪贴板。")
        }
        .frame(
            width: RevealSessionWindowLayout.contentSize.width,
            height: RevealSessionWindowLayout.contentSize.height,
            alignment: .leading
        )
    }
}
