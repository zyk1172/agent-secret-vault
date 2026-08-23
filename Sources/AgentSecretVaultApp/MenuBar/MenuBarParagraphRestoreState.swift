import Foundation
import Observation
import VaultIPC

@MainActor
@Observable
public final class MenuBarParagraphRestoreState {
    public var inputText = ""
    public private(set) var restoredParagraph: RestoredParagraph?
    public var restoredText: String { restoredParagraph?.text ?? "" }
    public private(set) var errorText: String?
    public private(set) var isRestoring = false
    private var restoreGeneration = 0

    public init() {}

    public func restore(using action: @escaping (String) async throws -> RestoredParagraph) async {
        guard !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        restoreGeneration += 1
        let generation = restoreGeneration
        isRestoring = true
        errorText = nil
        defer {
            if generation == restoreGeneration {
                isRestoring = false
            }
        }

        do {
            let restoredParagraph = try await action(inputText)
            guard generation == restoreGeneration else { return }
            self.restoredParagraph = restoredParagraph
        } catch ParagraphRestoreBuilderError.noSecretReferences {
            guard generation == restoreGeneration else { return }
            restoredParagraph = nil
            errorText = "没有找到 secret:// 开头的密文引用。"
        } catch ParagraphRestoreBuilderError.invalidReference {
            guard generation == restoreGeneration else { return }
            restoredParagraph = nil
            errorText = "段落里存在格式不合法的密文引用。"
        } catch {
            guard generation == restoreGeneration else { return }
            restoredParagraph = nil
            errorText = "解密失败。"
        }
    }

    public func clearSensitiveOutput() {
        restoreGeneration += 1
        isRestoring = false
        restoredParagraph = nil
        errorText = nil
    }

    func applyRestoredTextForTesting(_ text: String) {
        restoredParagraph = RestoredParagraph(text: text, values: [])
    }
}
