import SwiftUI

public enum RevealSessionWindowLayout {
    public static let contentSize = CGSize(width: 560, height: 320)
    public static let minimumSize = CGSize(width: 480, height: 240)
}

public struct RevealSessionWindow: View {
    let resolvedParagraph: String
    let close: () -> Void

    public init(resolvedParagraph: String, close: @escaping () -> Void) {
        self.resolvedParagraph = resolvedParagraph
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
                Text(resolvedParagraph)
                    .textSelection(.disabled)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            HStack {
                Spacer()
                Button("关闭并清除", action: close)
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(22)
        .frame(
            width: RevealSessionWindowLayout.contentSize.width,
            height: RevealSessionWindowLayout.contentSize.height,
            alignment: .leading
        )
    }
}
