# Menu Bar Extra Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a compact macOS menu-bar workbench that stays available after the main window closes and terminates only through its menu-bar Quit control.

**Architecture:** A SwiftUI `MenuBarExtra` shares the app-owned `AgentSecretVaultRuntime` with the current `WindowGroup`. New compact views own only UI state. The AppKit delegate blocks regular termination until the compact panel explicitly clears reveal sessions and permits `NSApp.terminate(nil)`.

**Tech Stack:** Swift 6, SwiftUI, AppKit, Observation, Swift Testing, XcodeGen, macOS 14.

## Global Constraints

- Use `MenuBarExtra` with `.menuBarExtraStyle(.window)`.
- Keep the existing `VaultWorkbenchView` layout and main-window copy unchanged.
- Use `lock.fill` as the status symbol and a fixed 420 by 600 point panel.
- Reuse the existing runtime and service closures; never start a second IPC server.
- Compact saved-reference, audit, and status views must never expose plaintext.
- Clear compact paragraph-restore output on panel disappearance and app focus loss.
- Only the compact panel's Quit control can permit app termination.

---

### Task 1: Add Presentation Constants And Restore State

**Files:**
- Create: `Sources/AgentSecretVaultApp/MenuBar/MenuBarPresentation.swift`
- Create: `Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreState.swift`
- Create: `Tests/VaultAuthorizationTests/MenuBarPresentationTests.swift`

**Interfaces:**
- Produces `MenuBarPresentation.statusItemSymbol`, `mainWindowID`, and `panelSize`.
- Produces `MenuBarParagraphRestoreState`, consumed by the compact restore view.
- Consumes the existing async paragraph-restore closure and `ParagraphRestoreBuilderError`.

- [ ] **Step 1: Write failing constants and cleanup tests**

```swift
import SwiftUI
import Testing
@testable import AgentSecretVaultApp

@Test func menuBarPresentationUsesCompactNativeDimensions() {
    #expect(MenuBarPresentation.statusItemSymbol == "lock.fill")
    #expect(MenuBarPresentation.panelSize == CGSize(width: 420, height: 600))
    #expect(MenuBarPresentation.mainWindowID == "agent-secret-vault-main")
}

@Test @MainActor func compactRestoreStateClearsOutputOnDismissal() {
    let state = MenuBarParagraphRestoreState()
    state.applyRestoredTextForTesting("temporary paragraph")
    state.clearSensitiveOutput()

    #expect(state.restoredText.isEmpty)
    #expect(state.errorText == nil)
}
```

- [ ] **Step 2: Run the focused test and confirm it fails**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarPresentationTests test
```

Expected: compilation failure because the presentation and restore-state types are absent.

- [ ] **Step 3: Implement the minimal state**

```swift
// MenuBarPresentation.swift
import CoreGraphics

public enum MenuBarPresentation {
    public static let statusItemSymbol = "lock.fill"
    public static let mainWindowID = "agent-secret-vault-main"
    public static let panelSize = CGSize(width: 420, height: 600)
}
```

```swift
// MenuBarParagraphRestoreState.swift
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
```

- [ ] **Step 4: Run the focused test and commit**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarPresentationTests test
git add Sources/AgentSecretVaultApp/MenuBar/MenuBarPresentation.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreState.swift \
  Tests/VaultAuthorizationTests/MenuBarPresentationTests.swift
git commit -m "feat: add menu bar presentation state"
```

Expected: focused tests pass before commit.

### Task 2: Build The Compact Menu-Bar Workbench

**Files:**
- Create: `Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift`
- Create: `Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreView.swift`
- Modify: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`
- Create: `Tests/VaultAuthorizationTests/MenuBarPanelTests.swift`

**Interfaces:**
- `MenuBarVaultPanel` receives `WorkbenchStatus`, `OrphanScanResult?`, audit entries, saved references, restore/refresh closures, `clearRevealSessions`, and `requestTermination`.
- `MenuBarParagraphRestoreView` receives the restore state and action closure.
- `SavedReferenceDisplay` is an internal helper shared by the existing saved-reference row and the compact reference list.

- [ ] **Step 1: Write failing panel tests**

```swift
import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func menuBarPanelCoversEveryWorkbenchSection() {
    #expect(MenuBarVaultPanel.supportedSections == VaultWorkbenchSection.allCases)
}

@Test func menuBarPanelUsesSimpleStatusSymbol() {
    #expect(MenuBarVaultPanel.statusItemSymbol == "lock.fill")
}

@Test func compactPanelOmitsMainWindowTutorialCopy() throws {
    let source = try menuBarSource(named: "MenuBarVaultPanel.swift")
    #expect(!source.contains("安装、Obsidian 插件、MCP 配置和完整教程"))
    #expect(source.contains(".help(section.title)"))
}
```

Add `menuBarSource(named:)` as a private helper that derives `Sources/AgentSecretVaultApp/MenuBar` from `#filePath`, matching the repository's current source-inspection test pattern.

- [ ] **Step 2: Run the focused test and confirm it fails**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarPanelTests test
```

Expected: compilation failure because `MenuBarVaultPanel` does not exist.

- [ ] **Step 3: Implement the panel and compact feature variants**

```swift
public struct MenuBarVaultPanel: View {
    public static let statusItemSymbol = MenuBarPresentation.statusItemSymbol
    public static let supportedSections = VaultWorkbenchSection.allCases

    let status: WorkbenchStatus
    let orphanScanResult: OrphanScanResult?
    let auditEntries: [AgentAutomationAuditEntry]
    let savedReferences: [SecretReferenceMetadata]
    let restoreParagraph: (String) async throws -> String
    let refreshSavedReferences: () async -> Void
    let clearRevealSessions: () -> Void
    let requestTermination: () -> Void

    @State private var selectedSection: VaultWorkbenchSection = .overview
    @State private var restoreState = MenuBarParagraphRestoreState()

    public var body: some View {
        VStack(spacing: 0) {
            compactHeader
            compactNavigation
            Divider()
            ScrollView { compactContent.padding(14) }
            Divider()
            footer
        }
        .frame(width: MenuBarPresentation.panelSize.width, height: MenuBarPresentation.panelSize.height)
        .onDisappear { clearSensitiveState() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            clearSensitiveState()
        }
    }

    private func clearSensitiveState() {
        restoreState.clearSensitiveOutput()
        clearRevealSessions()
    }
}
```

Implement the private compact views in `MenuBarVaultPanel.swift`:

- Header: `lock.fill`, selected short title, and concise IPC/vault state.
- Navigation: one icon button for each `VaultWorkbenchSection`, with `.accessibilityLabel(section.title)` and `.help(section.title)`.
- Dashboard: three visible status values, section shortcuts, and at most two redacted audit entries.
- Saved references: preserve Refresh and Copy; render only the existing sanitized paragraph template and opaque reference.
- Records: show missing and unreferenced counts, plus the existing protected-delete explanation; no direct delete implementation.
- Automation: show at most six existing redacted audit entries.
- Security: render four short allowed/blocked facts without tutorial copy.
- Footer: Open Main Window calls `NSApp.activate(ignoringOtherApps: true)` then `openWindow(id: MenuBarPresentation.mainWindowID)`; Quit calls `requestTermination()`.

Implement `MenuBarParagraphRestoreView` with `TextEditor` input, Restore, Clear, result, Copy Result, and existing concise unavailable/error states. Do not include the main view's tutorial paragraph. Clear resets input and invokes `state.clearSensitiveOutput()`.

Extract this safe formatting from `SavedSecretReferenceRow` without changing its default UI strings or layout:

```swift
enum SavedReferenceDisplay {
    static let paragraphReferenceMarker = "[[ASV_REFERENCE]]"

    static func title(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return "未命名密文"
        }
        return label.contains(paragraphReferenceMarker) ? "可用段落" : label
    }

    static func text(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return metadata.reference
        }
        if label.contains(paragraphReferenceMarker) {
            return label.replacingOccurrences(
                of: paragraphReferenceMarker,
                with: metadata.reference
            )
        }
        return "\(label)：\(metadata.reference)"
    }
}
```

The compact reference list and the existing row both call the helper, so paragraph-template substitution remains identical.

- [ ] **Step 4: Run the focused and existing workbench tests**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarPanelTests \
  -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests test
```

Expected: both test classes pass; no main-window copy assertion changes are needed.

- [ ] **Step 5: Commit the compact panel**

```bash
git add Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreView.swift \
  Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Tests/VaultAuthorizationTests/MenuBarPanelTests.swift
git commit -m "feat: add compact menu bar workbench"
```

### Task 3: Integrate Shared Runtime And Termination Control

**Files:**
- Modify: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
- Create: `Tests/VaultAuthorizationTests/MenuBarLifecycleTests.swift`

**Interfaces:**
- The App scene passes one runtime's published state and closures into `MenuBarVaultPanel`.
- `AgentSecretVaultAppDelegate.requestMenuBarTermination()` is the only function that sets the termination permit.

- [ ] **Step 1: Write failing scene and termination tests**

```swift
import Foundation
import Testing

@Test func appSceneProvidesWindowStyleMenuBarExtra() throws {
    let source = try appSource()
    #expect(source.contains("MenuBarExtra("))
    #expect(source.contains(".menuBarExtraStyle(.window)"))
    #expect(source.contains("WindowGroup(id: MenuBarPresentation.mainWindowID)"))
}

@Test func appDelegateKeepsProcessAliveUntilMenuBarQuit() throws {
    let source = try appSource()
    #expect(source.contains("applicationShouldTerminateAfterLastWindowClosed"))
    #expect(source.contains("requestMenuBarTermination"))
    #expect(source.contains("applicationShouldTerminate"))
    #expect(source.contains("permitsTermination ? .terminateNow : .terminateCancel"))
}
```

Add `appSource()` as a private helper that reads `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift` from `#filePath`.

- [ ] **Step 2: Run the focused test and confirm it fails**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarLifecycleTests test
```

Expected: source assertions fail because the menu-bar scene and termination gate are absent.

- [ ] **Step 3: Add the scene and termination gate**

Change the main window declaration and append this scene:

```swift
WindowGroup(id: MenuBarPresentation.mainWindowID) {
    VaultWorkbenchView(
        status: runtime.status,
        orphanScanResult: runtime.orphanScanResult,
        auditEntries: runtime.auditEntries,
        savedReferences: runtime.savedReferences,
        restoreParagraph: { try await runtime.restoreParagraph($0) },
        refreshSavedReferences: { await runtime.refreshSavedReferences() }
    )
        .task { await runtime.start() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            secureViewerModel.handleFocusChanged(isFocused: false)
            runtime.clearRevealSessions()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            secureViewerModel.handleSleepNotification()
            runtime.clearRevealSessions()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.willSleepNotification)) { _ in
            secureViewerModel.handleSleepNotification()
            runtime.clearRevealSessions()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
            secureViewerModel.handleLockNotification()
            runtime.clearRevealSessions()
        }
}

MenuBarExtra("Agent Secret Vault", systemImage: MenuBarPresentation.statusItemSymbol) {
    MenuBarVaultPanel(
        status: runtime.status,
        orphanScanResult: runtime.orphanScanResult,
        auditEntries: runtime.auditEntries,
        savedReferences: runtime.savedReferences,
        restoreParagraph: { try await runtime.restoreParagraph($0) },
        refreshSavedReferences: { await runtime.refreshSavedReferences() },
        clearRevealSessions: { runtime.clearRevealSessions() },
        requestTermination: { appDelegate.requestMenuBarTermination() }
    )
    .task { await runtime.start() }
}
.menuBarExtraStyle(.window)
```

Add the delegate gate:

```swift
private var permitsTermination = false

func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
}

func requestMenuBarTermination() {
    RevealSessionLifecycle.clearAll()
    permitsTermination = true
    NSApp.terminate(nil)
}

func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    permitsTermination ? .terminateNow : .terminateCancel
}
```

Replace the default app-termination command group with an empty group so Command-Q is not an advertised alternate exit path. Keep the existing navigation command menu unchanged.

- [ ] **Step 4: Run the focused test and commit**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization \
  -destination 'platform=macOS' \
  -only-testing:VaultAuthorizationTests/MenuBarLifecycleTests test
git add Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift \
  Tests/VaultAuthorizationTests/MenuBarLifecycleTests.swift
git commit -m "feat: keep vault running from menu bar"
```

Expected: lifecycle tests pass before commit.

### Task 4: Generate, Test, And Manually Verify

**Files:**
- Modify only if generated by XcodeGen: `AgentSecretVault.xcodeproj/project.pbxproj`

**Interfaces:**
- Validates the complete macOS app and actual menu-bar behavior.

- [ ] **Step 1: Regenerate the Xcode project**

```bash
xcodegen generate
git diff --check
```

Expected: new MenuBar sources are included and no whitespace errors are reported.

- [ ] **Step 2: Run the full macOS suite**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault \
  -destination 'platform=macOS' test
```

Expected: VaultCore, VaultAuthorization, VaultIPC, VaultExecution, and leak tests all pass.

- [ ] **Step 3: Run plaintext-canary validation**

```bash
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' \
  ./scripts/scan-plaintext.sh build test-artifacts
```

Expected: no canary value appears outside intended test fixtures.

- [ ] **Step 4: Verify the macOS flow manually**

1. Launch the app and wait for IPC to become available.
2. Close the main window; verify the `lock.fill` menu item remains.
3. Open the compact 420 by 600 panel; verify six concise icon tabs and visible status.
4. Exercise dashboard routing, paragraph restore, saved-reference copy, record state, audit list, and security facts.
5. Open the unchanged main workbench from the panel.
6. Close the window and try Command-Q; verify the process remains running.
7. Choose the panel's Quit control; verify the process exits and reveal-session windows close.

- [ ] **Step 5: Commit generated metadata only when it changed**

```bash
git status --short
git add AgentSecretVault.xcodeproj/project.pbxproj
git commit -m "build: include menu bar sources"
```

Skip the final add and commit when XcodeGen leaves the project file unchanged.
