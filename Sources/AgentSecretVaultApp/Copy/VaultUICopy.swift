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
        chinese: "让智能体使用敏感信息，但不接触明文。"
    )

    public static let overviewSubtitle = BilingualText(
        english: "Manage credentials as catalog entries. Markdown stays editable in Obsidian; this Mac app handles reveal, local authorization, and controlled sending.",
        chinese: "凭据按分组和条目管理，Markdown 保持可在 Obsidian 中编辑；明文查看、本机授权和受控发送都由本应用完成。"
    )

    public static let usageSteps: [UsageStepCopy] = [
        UsageStepCopy(id: 1, englishTitle: "Manage credentials in the catalog", englishBody: "Open a group and entry in this app; ordinary fields are visible and password fields stay encrypted.", chineseTitle: "在目录中管理凭据", chineseBody: "在 App 中打开分组和条目；普通字段直接可见，密码字段保持加密。"),
        UsageStepCopy(id: 2, englishTitle: "Keep Markdown valid v3", englishBody: "Edit headings, notes, and WikiLinks in Obsidian normally. The plugin validates format and never decrypts.", chineseTitle: "保持 v3 Markdown 合法", chineseBody: "在 Obsidian 中正常编辑标题、备注和双链；插件只校验格式，不解密。"),
        UsageStepCopy(id: 3, englishTitle: "Reveal by field", englishBody: "Click Decrypt next to one password field and complete device-owner authentication to show it temporarily in this app.", chineseTitle: "按字段查看密码", chineseBody: "在具体密码字段点击“解密”，完成本机身份认证后仅在本应用内短暂显示。"),
        UsageStepCopy(id: 4, englishTitle: "Approve agent mutations", englishBody: "Each Agent catalog mutation starts its own request; approving one operation never authorizes another.", chineseTitle: "逐笔批准智能体修改", chineseBody: "智能体每笔目录修改都会单独申请授权；批准一笔不会授权另一笔。")
    ]

    public static let securityBoundaries: [SecurityBoundaryCopy] = [
        SecurityBoundaryCopy(id: "agent-plaintext", symbolName: "eye.slash", englishTitle: "Plaintext stays local by default", englishBody: "Field reveal shows plaintext only inside this app after fresh device-owner authentication. The plugin and MCP never receive plaintext.", chineseTitle: "默认明文留在本机", chineseBody: "密码字段解密后的明文只在本应用内显示，每次都需要本机身份认证；插件和 MCP 都拿不到明文。", isLimitation: false),
        SecurityBoundaryCopy(id: "clipboard", symbolName: "doc.on.clipboard", englishTitle: "Clipboard is explicit", englishBody: "Copying places plaintext on the system clipboard. Paste immediately, then clear or overwrite the clipboard when finished.", chineseTitle: "剪贴板必须显式使用", chineseBody: "复制会把明文放入系统剪贴板。请立即粘贴，并在完成后清除或覆盖剪贴板。", isLimitation: false),
        SecurityBoundaryCopy(id: "risk-classes", symbolName: "touchid", englishTitle: "Fresh authorization for risk", englishBody: "Delete, bind, replace, or reveal existing secret references require fresh local authorization and cannot reuse another approval.", chineseTitle: "高风险操作重新授权", chineseBody: "删除、绑定、替换或查看已有密码引用都必须重新本机授权，不能复用其他批准。", isLimitation: false),
        SecurityBoundaryCopy(id: "excluded-threats", symbolName: "exclamationmark.triangle", englishTitle: "Local compromise is out of scope", englishBody: "This does not protect against malware running as the same macOS user, screen recording, or an attacker with administrator or root control.", chineseTitle: "本机失陷不在防御范围内", chineseBody: "这不能防御以同一 macOS 用户身份运行的恶意软件、屏幕录制，或拥有管理员或 root 权限的攻击者。", isLimitation: true)
    ]

    public static let secureViewerEmptyTitle = BilingualText(english: "No plaintext is currently loaded.", chinese: "当前没有载入明文。")
    public static let secureViewerOpenReferenceHint = BilingualText(english: "Open a secret:// reference to reveal it temporarily after local authorization.", chinese: "打开一个 secret:// 引用并完成本机授权后，可在此临时查看明文。")
    public static let clipboardWarning = BilingualText(english: "Copy only when you are ready to paste immediately.", chinese: "只在准备立即粘贴时复制。")
    public static let orphanReviewSafety = BilingualText(english: "Scanning only finds candidates. It never deletes encrypted records by itself.", chinese: "扫描只会找出候选项，不会自动删除任何加密记录。")
}
