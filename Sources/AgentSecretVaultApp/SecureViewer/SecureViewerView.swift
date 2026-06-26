import SwiftUI

public struct SecureViewerView: View {
    @Bindable private var model: SecureViewerModel
    @State private var isConfirmingCopy = false

    public init(model: SecureViewerModel) {
        self.model = model
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header

            if let displayText = model.displayText {
                loadedPlaintext(displayText)
            } else {
                emptyState
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .onDisappear {
            model.close()
        }
        .confirmationDialog(
            "Copy plaintext to the clipboard?",
            isPresented: $isConfirmingCopy,
            titleVisibility: .visible
        ) {
            Button("Copy plaintext") {
                model.copyFor60SecondsAfterConfirmation()
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Copy only when you are ready to paste immediately. Plaintext will be placed on the system clipboard; clear or overwrite it when finished. 只在准备立即粘贴时复制。明文会进入系统剪贴板；完成后请清除或覆盖它。")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Reveal Secret · 查看明文", systemImage: "eye")
                .font(.largeTitle.weight(.bold))
            Text("Plaintext appears here only after local authorization, and clears on focus loss, sleep, close, or app exit.")
                .foregroundStyle(.secondary)
            Text("完成本机授权后，明文才会显示在这里；失焦、睡眠、关闭或退出都会清除。")
                .foregroundStyle(.secondary)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 16) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 42))
                    .foregroundStyle(.secondary)
                    .frame(width: 56)

                VStack(alignment: .leading, spacing: 8) {
                    Text(VaultUICopy.secureViewerEmptyTitle.english)
                        .font(.title2.weight(.semibold))
                    Text(VaultUICopy.secureViewerEmptyTitle.chinese)
                        .font(.title3.weight(.semibold))
                    Text(VaultUICopy.secureViewerOpenReferenceHint.english)
                        .foregroundStyle(.secondary)
                    Text(VaultUICopy.secureViewerOpenReferenceHint.chinese)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("How to open a secret · 如何打开密文")
                    .font(.headline)
                Text("1. Ask the agent to keep or send only the secret:// reference.")
                Text("2. Open the reference through this app when plaintext is needed.")
                Text("3. Authorize locally, then close the viewer when finished.")
                Text("Example: secret://0123456789ABCDEFGHJKMNPQRS")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.disabled)
                    .padding(10)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
    }

    private func loadedPlaintext(_ displayText: String) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Plaintext visible · 明文正在显示", systemImage: "exclamationmark.triangle")
                .font(.headline)
                .foregroundStyle(.orange)

            ScrollView {
                Text(displayText)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.disabled)
                    .privacySensitive()
                    .padding(18)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: 260, alignment: .topLeading)
            .background(.background, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(.quaternary, lineWidth: 1)
            }

            HStack {
                Button("Copy plaintext · 复制明文") {
                    isConfirmingCopy = true
                }

                Button("Close and clear plaintext · 关闭并清除明文") {
                    model.close()
                }
                .keyboardShortcut(.cancelAction)
            }

            Text("Copy only when ready to paste immediately. Plaintext copied to the system clipboard remains available until you clear or overwrite it.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("只在准备立即粘贴时复制。复制到系统剪贴板的明文会保留到你清除或覆盖它。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
