# Agent Secret Vault UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native macOS A+B UI for Agent Secret Vault: a security-console main window plus clear bilingual usage guidance.

**Architecture:** Add a focused dashboard layer around the existing secure viewer instead of replacing security logic. Centralize bilingual copy in `VaultUICopy` so tests can guard the instructional and boundary language. Keep `SecureViewerModel` behavior unchanged.

**Tech Stack:** SwiftUI, Observation, Swift Testing, XcodeGen, macOS 14+, Xcode beta at `/Applications/Xcode-beta.app`.

---

## File structure

- Create `Sources/AgentSecretVaultApp/Copy/VaultUICopy.swift`
  - Owns user-facing bilingual strings and small data models for guide steps and security boundaries.
- Create `Sources/AgentSecretVaultApp/Dashboard/VaultDashboardView.swift`
  - Owns the main window layout, left rail, and selected section state.
- Create `Sources/AgentSecretVaultApp/Dashboard/OverviewGuideView.swift`
  - Renders promise, four-step guide, and security boundary cards.
- Create `Sources/AgentSecretVaultApp/Dashboard/InstructionStepCard.swift`
  - Reusable numbered step card.
- Create `Sources/AgentSecretVaultApp/Dashboard/SecurityBoundaryCard.swift`
  - Reusable security claim / limitation card.
- Modify `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
  - Launches `VaultDashboardView` instead of opening `SecureViewerView` directly.
- Modify `Sources/AgentSecretVaultApp/SecureViewer/SecureViewerView.swift`
  - Improves empty and loaded states while preserving copy confirmation and clear behavior.
- Modify `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift`
  - Restyles orphan review with explicit safety guidance.
- Create `Tests/VaultAuthorizationTests/VaultUICopyTests.swift`
  - Guards bilingual copy, usage steps, and safety boundaries.
- Regenerate `AgentSecretVault.xcodeproj` with `xcodegen generate` after adding files.

Do not commit `.superpowers/` companion files or `AgentSecretVault.xcodeproj/project.xcworkspace/xcuserdata/`.

---

## Task 1: Centralize bilingual UI copy with tests

**Files:**
- Create: `Sources/AgentSecretVaultApp/Copy/VaultUICopy.swift`
- Create: `Tests/VaultAuthorizationTests/VaultUICopyTests.swift`

- [ ] **Step 1: Write the failing copy tests**

Create `Tests/VaultAuthorizationTests/VaultUICopyTests.swift`:

```swift
import Testing
@testable import AgentSecretVaultApp

@Test func bilingualProductPromiseIsNativeAndSpecific() {
    #expect(VaultUICopy.overviewPromise.english == "Let agents work with secrets without seeing plaintext.")
    #expect(VaultUICopy.overviewPromise.chinese == "让 Agent 使用敏感信息，但不接触明文。")
}

@Test func overviewGuideContainsExactlyFourUsageSteps() {
    let steps = VaultUICopy.usageSteps

    #expect(steps.count == 4)
    #expect(steps.map(\.englishTitle) == [
        "Select sensitive text",
        "Encrypt into a reference",
        "Let the agent use the reference",
        "Reveal or send locally"
    ])
    #expect(steps.map(\.chineseTitle) == [
        "选择敏感文本",
        "加密为引用",
        "让 Agent 使用引用",
        "在本机查看或发送"
    ])
}

@Test func safetyBoundariesStayHonestAboutExcludedThreats() {
    let allEnglish = VaultUICopy.securityBoundaries
        .map { "\($0.englishTitle) \($0.englishBody)" }
        .joined(separator: "\n")
    let allChinese = VaultUICopy.securityBoundaries
        .map { "\($0.chineseTitle) \($0.chineseBody)" }
        .joined(separator: "\n")

    #expect(allEnglish.contains("Agents never receive decrypted values."))
    #expect(allEnglish.contains("same macOS user"))
    #expect(allEnglish.contains("administrator or root"))
    #expect(allChinese.contains("Agent 不会收到解密后的值。"))
    #expect(allChinese.contains("同一 macOS 用户"))
    #expect(allChinese.contains("管理员或 root"))
}

@Test func secureViewerEmptyStateGivesActionableGuidance() {
    #expect(VaultUICopy.secureViewerEmptyTitle.english == "No plaintext is currently loaded.")
    #expect(VaultUICopy.secureViewerEmptyTitle.chinese == "当前没有载入明文。")
    #expect(VaultUICopy.secureViewerOpenReferenceHint.english.contains("secret://"))
    #expect(VaultUICopy.secureViewerOpenReferenceHint.chinese.contains("secret://"))
}

@Test func orphanReviewCopySaysScanningDoesNotDeleteAutomatically() {
    #expect(VaultUICopy.orphanReviewSafety.english.contains("never deletes"))
    #expect(VaultUICopy.orphanReviewSafety.chinese.contains("不会自动删除"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: FAIL because `VaultUICopy` is not defined.

- [ ] **Step 3: Implement `VaultUICopy`**

Create `Sources/AgentSecretVaultApp/Copy/VaultUICopy.swift`:

```swift
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

    public init(
        id: Int,
        englishTitle: String,
        englishBody: String,
        chineseTitle: String,
        chineseBody: String
    ) {
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

    public init(
        id: String,
        symbolName: String,
        englishTitle: String,
        englishBody: String,
        chineseTitle: String,
        chineseBody: String,
        isLimitation: Bool
    ) {
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
        UsageStepCopy(
            id: 1,
            englishTitle: "Select sensitive text",
            englishBody: "Choose the password, token, note fragment, or credential text in your knowledge base.",
            chineseTitle: "选择敏感文本",
            chineseBody: "在知识库中选择密码、令牌、笔记片段或凭据文本。"
        ),
        UsageStepCopy(
            id: 2,
            englishTitle: "Encrypt into a reference",
            englishBody: "Agent Secret Vault stores encrypted bytes and replaces the text with a secret:// reference.",
            chineseTitle: "加密为引用",
            chineseBody: "Agent Secret Vault 保存加密数据，并把原文替换成 secret:// 引用。"
        ),
        UsageStepCopy(
            id: 3,
            englishTitle: "Let the agent use the reference",
            englishBody: "Codex, Claude, or Hermes can discuss and pass the reference without receiving plaintext.",
            chineseTitle: "让 Agent 使用引用",
            chineseBody: "Codex、Claude 或 Hermes 可以讨论和传递引用，但不会收到明文。"
        ),
        UsageStepCopy(
            id: 4,
            englishTitle: "Reveal or send locally",
            englishBody: "Use this app to reveal or send the secret after fresh local authorization.",
            chineseTitle: "在本机查看或发送",
            chineseBody: "需要查看或发送时，通过本 App 完成本机授权。"
        )
    ]

    public static let securityBoundaries: [SecurityBoundaryCopy] = [
        SecurityBoundaryCopy(
            id: "agent-plaintext",
            symbolName: "eye.slash",
            englishTitle: "Plaintext stays local",
            englishBody: "Agents never receive decrypted values.",
            chineseTitle: "明文留在本机",
            chineseBody: "Agent 不会收到解密后的值。",
            isLimitation: false
        ),
        SecurityBoundaryCopy(
            id: "clipboard",
            symbolName: "doc.on.clipboard",
            englishTitle: "Clipboard is explicit",
            englishBody: "Copy only when you are ready to paste immediately. The app clears only its own clipboard value if unchanged.",
            chineseTitle: "剪贴板必须显式使用",
            chineseBody: "只在准备立即粘贴时复制。App 只会在内容未被替换时清除自己写入的剪贴板内容。",
            isLimitation: false
        ),
        SecurityBoundaryCopy(
            id: "risk-classes",
            symbolName: "touchid",
            englishTitle: "Fresh authorization for risk",
            englishBody: "Send, delete, and credential-change actions cannot reuse a read authorization.",
            chineseTitle: "高风险操作重新授权",
            chineseBody: "发送、删除和凭据变更不能复用读取授权。",
            isLimitation: false
        ),
        SecurityBoundaryCopy(
            id: "excluded-threats",
            symbolName: "exclamationmark.triangle",
            englishTitle: "Local compromise is out of scope",
            englishBody: "This does not protect against malware running as the same macOS user, screen recording, or an attacker with administrator or root control.",
            chineseTitle: "本机失陷不在防御范围内",
            chineseBody: "这不能防御以同一 macOS 用户身份运行的恶意软件、屏幕录制，或拥有管理员或 root 权限的攻击者。",
            isLimitation: true
        )
    ]

    public static let secureViewerEmptyTitle = BilingualText(
        english: "No plaintext is currently loaded.",
        chinese: "当前没有载入明文。"
    )

    public static let secureViewerOpenReferenceHint = BilingualText(
        english: "Open a secret:// reference to reveal it temporarily after local authorization.",
        chinese: "打开一个 secret:// 引用并完成本机授权后，可在此临时查看明文。"
    )

    public static let clipboardWarning = BilingualText(
        english: "Copy only when you are ready to paste immediately.",
        chinese: "只在准备立即粘贴时复制。"
    )

    public static let orphanReviewSafety = BilingualText(
        english: "Scanning only finds candidates. It never deletes encrypted records by itself.",
        chinese: "扫描只会找出候选项，不会自动删除任何加密记录。"
    )
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: PASS, including the new `VaultUICopyTests`.

- [ ] **Step 5: Commit**

```bash
git add Sources/AgentSecretVaultApp/Copy/VaultUICopy.swift Tests/VaultAuthorizationTests/VaultUICopyTests.swift
git commit -m "feat: add bilingual vault ui copy"
```

---

## Task 2: Add dashboard shell and overview guide

**Files:**
- Create: `Sources/AgentSecretVaultApp/Dashboard/VaultDashboardView.swift`
- Create: `Sources/AgentSecretVaultApp/Dashboard/OverviewGuideView.swift`
- Create: `Sources/AgentSecretVaultApp/Dashboard/InstructionStepCard.swift`
- Create: `Sources/AgentSecretVaultApp/Dashboard/SecurityBoundaryCard.swift`
- Modify: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`

- [ ] **Step 1: Create reusable step card**

Create `Sources/AgentSecretVaultApp/Dashboard/InstructionStepCard.swift`:

```swift
import SwiftUI

public struct InstructionStepCard: View {
    private let step: UsageStepCopy

    public init(step: UsageStepCopy) {
        self.step = step
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("\(step.id)")
                .font(.headline.monospacedDigit())
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(Circle().fill(Color.accentColor))

            VStack(alignment: .leading, spacing: 4) {
                Text(step.englishTitle)
                    .font(.headline)
                Text(step.chineseTitle)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(step.englishBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(step.chineseBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 172, alignment: .topLeading)
        .padding(16)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(.quaternary, lineWidth: 1)
        }
    }
}
```

- [ ] **Step 2: Create security boundary card**

Create `Sources/AgentSecretVaultApp/Dashboard/SecurityBoundaryCard.swift`:

```swift
import SwiftUI

public struct SecurityBoundaryCard: View {
    private let boundary: SecurityBoundaryCopy

    public init(boundary: SecurityBoundaryCopy) {
        self.boundary = boundary
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: boundary.symbolName)
                .font(.title3)
                .foregroundStyle(boundary.isLimitation ? .orange : .green)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Text(boundary.englishTitle)
                    .font(.headline)
                Text(boundary.chineseTitle)
                    .font(.subheadline.weight(.semibold))
                Text(boundary.englishBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(boundary.chineseBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
```

- [ ] **Step 3: Create overview guide**

Create `Sources/AgentSecretVaultApp/Dashboard/OverviewGuideView.swift`:

```swift
import SwiftUI

public struct OverviewGuideView: View {
    public init() {}

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                hero
                usageGuide
                securityBoundaries
            }
            .padding(28)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Overview · 总览", systemImage: "lock.shield")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)

            Text(VaultUICopy.overviewPromise.english)
                .font(.system(size: 34, weight: .bold, design: .default))
                .lineLimit(3)
                .minimumScaleFactor(0.8)

            Text(VaultUICopy.overviewPromise.chinese)
                .font(.title2.weight(.semibold))

            Text(VaultUICopy.overviewSubtitle.english)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text(VaultUICopy.overviewSubtitle.chinese)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private var usageGuide: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("How it works · 使用方法")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                ForEach(VaultUICopy.usageSteps) { step in
                    InstructionStepCard(step: step)
                }
            }
        }
    }

    private var securityBoundaries: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Safety boundaries · 安全边界")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                ForEach(VaultUICopy.securityBoundaries) { boundary in
                    SecurityBoundaryCard(boundary: boundary)
                }
            }
        }
    }
}
```

- [ ] **Step 4: Create dashboard shell**

Create `Sources/AgentSecretVaultApp/Dashboard/VaultDashboardView.swift`:

```swift
import SwiftUI

public struct VaultDashboardView: View {
    @Bindable private var secureViewerModel: SecureViewerModel
    @State private var selectedSection: DashboardSection = .overview

    public init(secureViewerModel: SecureViewerModel) {
        self.secureViewerModel = secureViewerModel
    }

    public var body: some View {
        NavigationSplitView {
            List(DashboardSection.allCases, selection: $selectedSection) { section in
                Label(section.title, systemImage: section.symbolName)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 230)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Agent Secret Vault")
                        .font(.headline)
                    Text("Local-only secret bridge")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
        } detail: {
            detailView
        }
        .frame(minWidth: 920, minHeight: 620)
    }

    @ViewBuilder
    private var detailView: some View {
        switch selectedSection {
        case .overview:
            OverviewGuideView()
        case .encryptText:
            WorkflowInfoView(
                title: "Encrypt Text · 加密文本",
                systemImage: "text.badge.lock",
                englishBody: "Select sensitive text in your knowledge base and replace it with a secret:// reference.",
                chineseBody: "在知识库中选择敏感文本，并把它替换为 secret:// 引用。"
            )
        case .revealSecret:
            SecureViewerView(model: secureViewerModel)
        case .agentSend:
            WorkflowInfoView(
                title: "Agent Send · Agent 发送",
                systemImage: "paperplane",
                englishBody: "External-send actions require fresh authorization and sanitized outputs.",
                chineseBody: "对外发送需要重新授权，并且返回内容会经过脱敏处理。"
            )
        case .orphanReview:
            OrphanReviewView(candidates: [], requestPermanentDelete: { _ in })
        case .securityModel:
            SecurityModelSummaryView()
        }
    }
}

public enum DashboardSection: String, CaseIterable, Identifiable {
    case overview
    case encryptText
    case revealSecret
    case agentSend
    case orphanReview
    case securityModel

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: "Overview"
        case .encryptText: "Encrypt Text"
        case .revealSecret: "Reveal Secret"
        case .agentSend: "Agent Send"
        case .orphanReview: "Orphan Review"
        case .securityModel: "Security Model"
        }
    }

    public var symbolName: String {
        switch self {
        case .overview: "rectangle.grid.2x2"
        case .encryptText: "text.badge.lock"
        case .revealSecret: "eye"
        case .agentSend: "paperplane"
        case .orphanReview: "tray.full"
        case .securityModel: "shield.lefthalf.filled"
        }
    }
}

private struct WorkflowInfoView: View {
    let title: String
    let systemImage: String
    let englishBody: String
    let chineseBody: String

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(title, systemImage: systemImage)
                .font(.largeTitle.weight(.bold))
            Text(englishBody)
                .foregroundStyle(.secondary)
            Text(chineseBody)
                .foregroundStyle(.secondary)
            Text("This section documents the safe workflow for the first UI release.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct SecurityModelSummaryView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Security Model · 安全模型")
                    .font(.largeTitle.weight(.bold))
                ForEach(VaultUICopy.securityBoundaries) { boundary in
                    SecurityBoundaryCard(boundary: boundary)
                }
            }
            .padding(28)
        }
    }
}
```

- [ ] **Step 5: Launch the dashboard from the app**

Modify `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`:

```swift
import AppKit
import AgentSecretVaultApp
import SwiftUI

@main
struct AgentSecretVaultApplication: App {
    @NSApplicationDelegateAdaptor(AgentSecretVaultAppDelegate.self) private var appDelegate
    @State private var secureViewerModel = SecureViewerModel()

    var body: some Scene {
        WindowGroup {
            VaultDashboardView(secureViewerModel: secureViewerModel)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    secureViewerModel.handleFocusChanged(isFocused: false)
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                }
        }
        .commands {
            CommandGroup(replacing: .pasteboard) {}
        }
    }
}

final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }
}
```

- [ ] **Step 6: Regenerate project and run tests**

Run:

```bash
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Sources/AgentSecretVaultApp/Dashboard Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift AgentSecretVault.xcodeproj
git commit -m "feat: add guided vault dashboard"
```

---

## Task 3: Improve Secure Viewer empty and loaded states

**Files:**
- Modify: `Sources/AgentSecretVaultApp/SecureViewer/SecureViewerView.swift`

- [ ] **Step 1: Replace Secure Viewer layout**

Replace `Sources/AgentSecretVaultApp/SecureViewer/SecureViewerView.swift` with:

```swift
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
            "Copy plaintext to the clipboard for 60 seconds?",
            isPresented: $isConfirmingCopy,
            titleVisibility: .visible
        ) {
            Button("Copy for 60 seconds") {
                model.copyFor60SecondsAfterConfirmation()
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(VaultUICopy.clipboardWarning.english) \(VaultUICopy.clipboardWarning.chinese) The app will clear the clipboard only if nothing else has replaced it.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Reveal Secret · 查看明文", systemImage: "eye")
                .font(.largeTitle.weight(.bold))
            Text("Plaintext appears here only after local authorization, and clears on focus loss, sleep, timeout, close, or app exit.")
                .foregroundStyle(.secondary)
            Text("完成本机授权后，明文才会显示在这里；失焦、睡眠、超时、关闭或退出都会清除。")
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

            Text(displayText)
                .font(.system(.body, design: .monospaced))
                .textSelection(.disabled)
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(.quaternary, lineWidth: 1)
                }

            HStack {
                Button("Copy for 60 seconds · 复制 60 秒") {
                    isConfirmingCopy = true
                }

                Button("Close and clear plaintext · 关闭并清除明文") {
                    model.close()
                }
                .keyboardShortcut(.cancelAction)
            }

            Text("Copy only when ready to paste immediately. Clipboard clearing is best-effort and app-owned only.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("只在准备立即粘贴时复制。剪贴板清除是尽力而为，并且只清除本 App 写入且未被替换的内容。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: PASS. Existing secure viewer model tests must still pass.

- [ ] **Step 3: Commit**

```bash
git add Sources/AgentSecretVaultApp/SecureViewer/SecureViewerView.swift
git commit -m "feat: improve secure viewer guidance"
```

---

## Task 4: Restyle Orphan Review and guard safety copy

**Files:**
- Modify: `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift`
- Modify: `Tests/VaultAuthorizationTests/VaultUICopyTests.swift`

- [ ] **Step 1: Replace Orphan Review layout**

Replace `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift` with:

```swift
import SwiftUI
import VaultCore

public struct OrphanReviewView: View {
    private let candidates: [OrphanCandidate]
    private let requestPermanentDelete: (OrphanCandidate) -> Void
    @State private var candidatePendingDeletion: OrphanCandidate?
    @State private var isConfirmingDeletion = false

    public init(
        candidates: [OrphanCandidate],
        requestPermanentDelete: @escaping (OrphanCandidate) -> Void
    ) {
        self.candidates = candidates
        self.requestPermanentDelete = requestPermanentDelete
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header

            if candidates.isEmpty {
                emptyState
            } else {
                candidateList
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .confirmationDialog(
            "Permanently delete all versions?",
            isPresented: $isConfirmingDeletion,
            titleVisibility: .visible
        ) {
            if let candidatePendingDeletion {
                Button("Request highest-risk authorization", role: .destructive) {
                    requestPermanentDelete(candidatePendingDeletion)
                }
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            if let candidatePendingDeletion {
                Text("This only requests deletion for secret://\(candidatePendingDeletion.id). The caller must authorize and delete all versions explicitly.")
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Orphan Review · 孤立记录检查", systemImage: "tray.full")
                .font(.largeTitle.weight(.bold))
            Text(VaultUICopy.orphanReviewSafety.english)
                .foregroundStyle(.secondary)
            Text(VaultUICopy.orphanReviewSafety.chinese)
                .foregroundStyle(.secondary)
            Text("\(candidates.count) candidate\(candidates.count == 1 ? "" : "s") found")
                .font(.caption.weight(.semibold))
                .foregroundStyle(candidates.isEmpty ? .green : .orange)
        }
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No orphan candidates",
            systemImage: "checkmark.shield",
            description: Text("All stored records are referenced by the scanned Markdown roots. 已扫描的 Markdown 根目录仍引用所有存储记录。")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var candidateList: some View {
        List(candidates) { candidate in
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text("secret://\(candidate.id)")
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                    Button("Request permanent delete", role: .destructive) {
                        candidatePendingDeletion = candidate
                        isConfirmingDeletion = true
                    }
                }

                Text("Versions: \(candidate.versions.map(String.init).joined(separator: ", "))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Deletion requires a separate highest-risk authorization. 删除前必须再次完成最高风险级别授权。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 8)
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
```

- [ ] **Step 2: Run tests**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift Tests/VaultAuthorizationTests/VaultUICopyTests.swift
git commit -m "feat: improve orphan review guidance"
```

---

## Task 5: Release-gate verification and cleanup

**Files:**
- Inspect: `AgentSecretVault.xcodeproj/project.pbxproj` after XcodeGen and stage it when it contains tracked source-file membership changes.
- Do not commit `.superpowers/`.
- Do not commit `AgentSecretVault.xcodeproj/project.xcworkspace/xcuserdata/`.

- [ ] **Step 1: Regenerate Xcode project**

Run:

```bash
xcodegen generate
```

Expected: exits 0 and writes `AgentSecretVault.xcodeproj`.

- [ ] **Step 2: Run full macOS tests**

Run:

```bash
dd="$(mktemp -d /tmp/asv-ui-dd.XXXXXX)"
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -derivedDataPath "$dd" test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
```

Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 3: Run MCP tests, typecheck, and build**

Run:

```bash
cd mcp-server
npm test
npm run typecheck
npm run build
cd ..
```

Expected:

- Vitest exits 0.
- `tsc -p tsconfig.json --noEmit` exits 0.
- `tsc -p tsconfig.json` exits 0.

- [ ] **Step 4: Run plaintext leak gate**

Run:

```bash
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts
```

Expected: exits 0 and does not print the canary value.

- [ ] **Step 5: Run whitespace and status checks**

Run:

```bash
git diff --check
git status --short
```

Expected:

- `git diff --check` exits 0.
- `git status --short` shows only intended tracked project changes and untracked local companion/user-state files.

- [ ] **Step 6: Commit generated project changes if needed**

If `git status --short` shows tracked Xcode project changes from new Swift files, commit them:

```bash
git add AgentSecretVault.xcodeproj
git commit -m "chore: regenerate project for vault ui"
```

If XcodeGen produced no tracked changes, skip this commit.

---

## Self-review

Spec coverage:

- First-launch explanation: Task 2.
- `secret://` workflow guidance: Tasks 1 and 2.
- Secure Viewer empty and loaded states: Task 3.
- Orphan Review visual consistency and safety copy: Task 4.
- Native bilingual copy: Task 1, then consumed by Tasks 2-4.
- Honest security boundaries: Tasks 1 and 2.
- Existing security behavior preserved: Tasks 3-5.

Red-flag scan:

- No `TBD`, `TODO`, unfinished filler, “similar to”, or unspecified “add tests” steps remain.
- Each code-changing task includes concrete files, snippets, commands, and expected results.

Type consistency:

- `VaultUICopy`, `BilingualText`, `UsageStepCopy`, and `SecurityBoundaryCopy` are defined in Task 1 before any view consumes them.
- `VaultDashboardView` takes `SecureViewerModel`, matching the existing app state.
- Existing `SecureViewerView(model:)` initializer remains available for tests and dashboard embedding.
