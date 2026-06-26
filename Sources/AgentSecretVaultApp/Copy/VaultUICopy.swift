import Foundation

public struct BilingualText: Equatable, Sendable {
    public let english: String
    public let chinese: String

    public init(english: String, chinese: String) {
        self.english = english
        self.chinese = chinese
    }
}

public struct UsageStepCopy: Equatable, Sendable, Identifiable {
    public let id: Int
    public let englishTitle: String
    public let englishBody: String
    public let chineseTitle: String
    public let chineseBody: String

    public init(id: Int, englishTitle: String, englishBody: String, chineseTitle: String, chineseBody: String) {
        self.id = id
        self.englishTitle = englishTitle
        self.englishBody = englishBody
        self.chineseTitle = chineseTitle
        self.chineseBody = chineseBody
    }
}

public struct SecurityBoundaryCopy: Equatable, Sendable, Identifiable {
    public let id: String
    public let symbolName: String
    public let englishTitle: String
    public let englishBody: String
    public let chineseTitle: String
    public let chineseBody: String
    public let isLimitation: Bool

    public init(id: String, symbolName: String, englishTitle: String, englishBody: String, chineseTitle: String, chineseBody: String, isLimitation: Bool) {
        self.id = id
        self.symbolName = symbolName
        self.englishTitle = englishTitle
        self.englishBody = englishBody
        self.chineseTitle = chineseTitle
        self.chineseBody = chineseBody
        self.isLimitation = isLimitation
    }
}

public enum VaultUICopy {
    public static let overviewPromise = BilingualText(
        english: "Let agents work with secrets without seeing plaintext.",
        chinese: "让 Agent 使用敏感信息，但不接触明文。"
    )

    public static let overviewSubtitle = BilingualText(
        english: "Encrypt selected knowledge-base text into an opaque secret:// reference. Agents can carry the reference; this Mac app handles reveal, local authorization, and controlled sending.",
        chinese: "把知识库里的敏感文本加密成不透明的 secret:// 引用。Agent 可以传递引用；明文查看、本机授权和受控发送都由这个 Mac App 完成。"
    )

    public static let usageSteps: [UsageStepCopy] = [
        UsageStepCopy(id: 1, englishTitle: "Select sensitive text", englishBody: "Choose the password, token, note fragment, or credential text in your knowledge base.", chineseTitle: "选择敏感文本", chineseBody: "在知识库中选择密码、令牌、笔记片段或凭据文本。"),
        UsageStepCopy(id: 2, englishTitle: "Encrypt into a reference", englishBody: "Agent Secret Vault stores encrypted bytes and replaces the text with a secret:// reference.", chineseTitle: "加密为引用", chineseBody: "Agent Secret Vault 保存加密数据，并把原文替换成 secret:// 引用。"),
        UsageStepCopy(id: 3, englishTitle: "Let the agent use the reference", englishBody: "Codex, Claude, or Hermes can discuss and pass the reference without receiving plaintext.", chineseTitle: "让 Agent 使用引用", chineseBody: "Codex、Claude 或 Hermes 可以讨论和传递引用，但不会收到明文。"),
        UsageStepCopy(id: 4, englishTitle: "Reveal or send locally", englishBody: "Use this app to reveal or send the secret after fresh local authorization.", chineseTitle: "在本机查看或发送", chineseBody: "需要查看或发送时，通过本 App 完成本机授权。")
    ]

    public static let securityBoundaries: [SecurityBoundaryCopy] = [
        SecurityBoundaryCopy(id: "agent-plaintext", symbolName: "eye.slash", englishTitle: "Plaintext stays local", englishBody: "Agents never receive decrypted values.", chineseTitle: "明文留在本机", chineseBody: "Agent 不会收到解密后的值。", isLimitation: false),
        SecurityBoundaryCopy(id: "clipboard", symbolName: "doc.on.clipboard", englishTitle: "Clipboard is explicit", englishBody: "Copy only when you are ready to paste immediately. The app clears only its own clipboard value if unchanged.", chineseTitle: "剪贴板必须显式使用", chineseBody: "只在准备立即粘贴时复制。App 只会在内容未被替换时清除自己写入的剪贴板内容。", isLimitation: false),
        SecurityBoundaryCopy(id: "risk-classes", symbolName: "touchid", englishTitle: "Fresh authorization for risk", englishBody: "Send, delete, and credential-change actions cannot reuse a read authorization.", chineseTitle: "高风险操作重新授权", chineseBody: "发送、删除和凭据变更不能复用读取授权。", isLimitation: false),
        SecurityBoundaryCopy(id: "excluded-threats", symbolName: "exclamationmark.triangle", englishTitle: "Local compromise is out of scope", englishBody: "This does not protect against malware running as the same macOS user, screen recording, or an attacker with administrator or root control.", chineseTitle: "本机失陷不在防御范围内", chineseBody: "这不能防御以同一 macOS 用户身份运行的恶意软件、屏幕录制，或拥有管理员或 root 权限的攻击者。", isLimitation: true)
    ]

    public static let secureViewerEmptyTitle = BilingualText(english: "No plaintext is currently loaded.", chinese: "当前没有载入明文。")
    public static let secureViewerOpenReferenceHint = BilingualText(english: "Open a secret:// reference to reveal it temporarily after local authorization.", chinese: "打开一个 secret:// 引用并完成本机授权后，可在此临时查看明文。")
    public static let clipboardWarning = BilingualText(english: "Copy only when you are ready to paste immediately.", chinese: "只在准备立即粘贴时复制。")
    public static let orphanReviewSafety = BilingualText(english: "Scanning only finds candidates. It never deletes encrypted records by itself.", chinese: "扫描只会找出候选项，不会自动删除任何加密记录。")
}
