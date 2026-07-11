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
