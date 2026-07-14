import AppKit
import SwiftUI

public struct MenuBarParagraphRestoreView: View {
    let state: MenuBarParagraphRestoreState
    let restoreParagraph: (String) async throws -> RestoredParagraph

    public init(state: MenuBarParagraphRestoreState, restoreParagraph: @escaping (String) async throws -> RestoredParagraph) {
        self.state = state
        self.restoreParagraph = restoreParagraph
    }

    public var body: some View {
        @Bindable var state = state
        VStack(alignment: .leading, spacing: 10) {
            Text("待解密段落").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            TextEditor(text: $state.inputText)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 130)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            HStack {
                Button("解密整个段落") { Task { await state.restore(using: restoreParagraph) } }
                    .disabled(state.isRestoring || state.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Button("清空") {
                    state.inputText = ""
                    state.clearSensitiveOutput()
                }
                .disabled(state.inputText.isEmpty && state.restoredText.isEmpty && state.errorText == nil)
                Spacer()
                Button("复制结果") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(state.restoredText, forType: .string)
                }
                .disabled(state.restoredText.isEmpty)
            }
            .buttonStyle(.bordered)
            if state.isRestoring {
                Text("正在请求本机授权并解密段落").font(.caption).foregroundStyle(.secondary)
            } else if let errorText = state.errorText {
                Text(errorText).font(.callout).foregroundStyle(.red)
            } else if !state.restoredText.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("解密结果").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(state.restoredText)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    if let restoredParagraph = state.restoredParagraph {
                        HStack(spacing: 6) {
                            ForEach(Array(restoredParagraph.values.enumerated()), id: \.offset) { index, value in
                                Button("复制密文 \(index + 1)") {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(value, forType: .string)
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                }
            } else {
                Text("等待输入包含 secret:// 的段落").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
