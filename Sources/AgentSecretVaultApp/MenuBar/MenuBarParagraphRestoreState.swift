import Foundation
import Observation

@MainActor
@Observable
public final class MenuBarParagraphRestoreState {
    public var inputText = ""
    public private(set) var restoredText = ""
    public private(set) var errorText: String?
    public private(set) var isRestoring = false

    public init() {}

    public func restore(using action: @escaping (String) async throws -> String) async {
        guard !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        isRestoring = true
        errorText = nil
        defer { isRestoring = false }

        do {
            restoredText = try await action(inputText)
        } catch ParagraphRestoreBuilderError.noSecretReferences {
            restoredText = ""
            errorText = "没有找到 secret:// 开头的密文引用。"
        } catch ParagraphRestoreBuilderError.invalidReference {
            restoredText = ""
            errorText = "段落里存在格式不合法的密文引用。"
        } catch {
            restoredText = ""
            errorText = "解密失败。"
        }
    }

    public func clearSensitiveOutput() {
        restoredText = ""
        errorText = nil
    }

    func applyRestoredTextForTesting(_ text: String) {
        restoredText = text
    }
}
