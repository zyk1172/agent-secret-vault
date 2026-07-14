import Foundation
import Testing
import VaultIPC
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

@Test func compactPanelInvalidatesRestoreStateAtEverySecurityBoundary() throws {
    let source = try menuBarSource(named: "MenuBarVaultPanel.swift")

    #expect(source.contains("NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)"))
    #expect(source.contains("NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)"))
    #expect(source.contains("NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)"))
    #expect(source.contains("Button(\"退出\") { clearSensitiveState(); Task { await requestTermination() } }"))
}

@Test func compactPanelPreservesTheProtectedDeleteRequestPath() throws {
    let source = try menuBarSource(named: "MenuBarVaultPanel.swift")

    #expect(source.contains("let requestPermanentDelete: (String) -> Void"))
    #expect(source.contains(".confirmationDialog("))
    #expect(source.contains("requestPermanentDelete(referencePendingDeletion)"))
    #expect(source.contains("请求高风险授权"))
}

@Test func compactPanelAnnouncesTheSelectedNavigationItem() throws {
    let source = try menuBarSource(named: "MenuBarVaultPanel.swift")

    #expect(source.contains(".accessibilityValue(selectedSection == section ? \"已选中\" : \"未选中\")"))
}

@Test func allParagraphRevealSurfacesRenderNumberedCopyControls() throws {
    let menuBar = try menuBarSource(named: "MenuBarParagraphRestoreView.swift")
    let workbench = try workbenchSource(named: "ParagraphRestoreView.swift")
    let temporaryReveal = try workbenchSource(named: "RevealSessionWindow.swift")

    #expect(menuBar.contains("复制密文 \\(index + 1)"))
    #expect(workbench.contains("复制密文 \\(index + 1)"))
    #expect(temporaryReveal.contains("复制密文 \\(index + 1)"))
    #expect(temporaryReveal.contains("确认复制明文到剪贴板？"))
}

@Test func savedReferenceDisplaySubstitutesTheCurrentReferenceIntoParagraphTemplates() {
    let metadata = SecretReferenceMetadata(
        reference: "secret://current-reference",
        policy: .credential,
        label: "NAS 密码：[[ASV_REFERENCE]]",
        createdAt: .distantPast,
        updatedAt: .distantPast
    )

    #expect(SavedReferenceDisplay.title(for: metadata) == "可用段落")
    #expect(SavedReferenceDisplay.text(for: metadata) == "NAS 密码：secret://current-reference")
}

@Test func savedReferenceDisplayPreservesLegacyLabels() {
    let metadata = SecretReferenceMetadata(
        reference: "secret://current-reference",
        policy: .read,
        label: "NAS 密码",
        createdAt: .distantPast,
        updatedAt: .distantPast
    )

    #expect(SavedReferenceDisplay.title(for: metadata) == "NAS 密码")
    #expect(SavedReferenceDisplay.text(for: metadata) == "NAS 密码：secret://current-reference")
}

private func menuBarSource(named fileName: String) throws -> String {
    let sourceDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/MenuBar")
    return try String(contentsOf: sourceDirectory.appendingPathComponent(fileName), encoding: .utf8)
}

private func workbenchSource(named fileName: String) throws -> String {
    let sourceDirectory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench")
    return try String(contentsOf: sourceDirectory.appendingPathComponent(fileName), encoding: .utf8)
}
