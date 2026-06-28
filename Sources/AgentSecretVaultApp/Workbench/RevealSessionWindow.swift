import SwiftUI

public struct RevealSessionWindow: View {
    let resolvedParagraph: String
    let close: () -> Void

    public init(resolvedParagraph: String, close: @escaping () -> Void) {
        self.resolvedParagraph = resolvedParagraph
        self.close = close
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Temporary reveal · 临时解密显示")
                .font(.title2.weight(.semibold))
            Text("Plaintext stays in the Mac app. 明文只在 Mac App 内显示。")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(resolvedParagraph)
                .textSelection(.disabled)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            Button("Close and clear · 关闭并清除", action: close)
        }
        .padding(22)
        .frame(minWidth: 520, alignment: .leading)
    }
}
