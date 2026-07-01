import AppKit
import SwiftUI

public enum ParagraphRestoreCopy {
    public static let title = "段落解密"
    public static let guidance = "粘贴包含 secret:// 引用的整段内容。本应用会在本机授权后一次性解密全部引用，并在下方显示结果；不会自动写回 Obsidian。"
}

public struct ParagraphRestoreView: View {
    private let restoreParagraph: (String) async throws -> String

    @State private var inputText = ""
    @State private var restoredText = ""
    @State private var statusText = "等待输入包含 secret:// 的段落"
    @State private var isRestoring = false
    @State private var errorText: String?

    public init(restoreParagraph: @escaping (String) async throws -> String) {
        self.restoreParagraph = restoreParagraph
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label(ParagraphRestoreCopy.title, systemImage: "text.quote")
                    .font(.title3.weight(.semibold))
                Spacer()
                if isRestoring {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            Text(ParagraphRestoreCopy.guidance)
                .font(.callout)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                Text("待解密段落")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                TextEditor(text: $inputText)
                    .font(.body.monospaced())
                    .frame(minHeight: 120)
                    .padding(6)
                    .background(.background.opacity(0.8), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .stroke(.quaternary)
                    )
            }

            HStack {
                Button("解密整个段落") {
                    Task {
                        await restore()
                    }
                }
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(isRestoring || inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Button("清空") {
                    inputText = ""
                    restoredText = ""
                    errorText = nil
                    statusText = "等待输入包含 secret:// 的段落"
                }
                .disabled(isRestoring || (inputText.isEmpty && restoredText.isEmpty))

                Spacer()

                Button("复制结果") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(restoredText, forType: .string)
                    statusText = "已复制还原后的段落"
                }
                .disabled(restoredText.isEmpty)
            }

            if let errorText {
                Text(errorText)
                    .font(.callout)
                    .foregroundStyle(.red)
            } else {
                Text(statusText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if !restoredText.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("解密结果")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TextEditor(text: $restoredText)
                        .font(.body.monospaced())
                        .frame(minHeight: 120)
                        .padding(6)
                        .background(.background.opacity(0.8), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .stroke(.quaternary)
                        )
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    @MainActor
    private func restore() async {
        isRestoring = true
        errorText = nil
        statusText = "正在请求本机授权并解密段落…"

        do {
            let restored = try await restoreParagraph(inputText)
            restoredText = restored
            statusText = "已解密段落中的全部密文引用"
        } catch ParagraphRestoreBuilderError.noSecretReferences {
            restoredText = ""
            errorText = "没有找到 secret:// 开头的密文引用。"
        } catch ParagraphRestoreBuilderError.invalidReference {
            restoredText = ""
            errorText = "段落里存在格式不合法的密文引用。"
        } catch {
            restoredText = ""
            errorText = "解密失败：\(error)"
        }

        isRestoring = false
    }
}
