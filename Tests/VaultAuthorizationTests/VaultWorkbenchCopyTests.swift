import Testing
import Foundation
@testable import AgentSecretVaultApp

@Test func workbenchCopyDoesNotPretendDisconnectedToolsAreReady() {
    let copy = VaultWorkbenchCopy.disconnected
    #expect(copy.primaryAction.contains("安装"))
    #expect(copy.primaryAction.contains("Obsidian 插件"))
    #expect(copy.status == "Obsidian 插件未连接")
}

@Test func workbenchCopyDistinguishesTemporaryRevealFromExplicitRestore() {
    let boundary = VaultWorkbenchCopy.securityBoundary
    #expect(boundary.contains("临时解密"))
    #expect(boundary.contains("不会把明文返回给插件或智能体"))
    #expect(boundary.contains("还原写回 Obsidian 是显式操作"))
    #expect(!boundary.contains("Temporary reveal"))
}

@Test func workbenchCopyProvidesExternalDocumentationLink() {
    #expect(VaultWorkbenchCopy.documentationURL.absoluteString == "https://github.com/zyk1172/agent-secret-vault")
}

@Test func workbenchCopyProvidesCopyableMcpConfigAndPrompt() {
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"agent-secret-vault\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"command\": \"/bin/zsh\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"-lc\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js"))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("Library/Application Support/AgentSecretVault/MCP/dist/server.js"))
    #expect(!VaultWorkbenchCopy.mcpConfig.contains("/Users/zhengyunkai/"))
    #expect(VaultWorkbenchCopy.agentPrompt.contains("secret://"))
    #expect(VaultWorkbenchCopy.agentPrompt.contains("不要让我粘贴明文"))
    #expect(!VaultWorkbenchCopy.agentPrompt.localizedLowercase.contains("qnap"))
}

@Test func primaryWorkbenchCopyAvoidsBilingualSeparators() {
    let visibleCopy = [
        VaultWorkbenchCopy.disconnected.status,
        VaultWorkbenchCopy.disconnected.primaryAction,
        VaultWorkbenchCopy.securityBoundary
    ]

    for text in visibleCopy {
        #expect(!text.contains(" · "))
        #expect(!text.contains("Temporary reveal"))
        #expect(!text.contains("Workbench"))
    }
}

@Test func workbenchProvidesMenuSectionsForMajorTasks() {
    let titles = VaultWorkbenchSection.allCases.map(\.title)

    #expect(titles == [
        "控制台",
        "段落解密",
        "密文库",
        "记录维护",
        "智能体自动化",
        "安全边界"
    ])
    #expect(VaultWorkbenchSection.paragraph.subtitle.contains("一次解密"))
    #expect(VaultWorkbenchSection.secrets.subtitle.contains("secret://"))
    #expect(VaultWorkbenchSection.allCases.allSatisfy { !$0.systemImage.isEmpty })
}

@Test func workbenchShowsSavedSecretReferencesWithoutPlaintext() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("SavedSecretReferencesCard(references: savedReferences"))
    #expect(source.contains("refresh: refreshSavedReferences"))
    #expect(source.contains("复制引用"))
    #expect(source.contains("不展示明文"))
}

@Test func overviewKeepsStatusProminentAndCompact() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("OverviewStatusStrip(status: status)"))
    #expect(source.contains("CompactAuditPreviewCard(entries: Array(auditEntries.prefix(2)))"))
    #expect(!source.contains("HeroCard("))
}

@Test func workbenchUsesStableRenderingForBetaMacOSCompatibility() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(VaultWorkbenchRenderingPolicy.usesStableRendering)
    #expect(!VaultWorkbenchRenderingPolicy.usesRepeatingAnimations)
    #expect(!VaultWorkbenchRenderingPolicy.usesBlurredBackgrounds)
    #expect(!VaultWorkbenchRenderingPolicy.usesMaterialBackgrounds)
    #expect(VaultWorkbenchRenderingPolicy.usesTransientAnimations)
    #expect(source.contains("VaultWorkbenchMotion.interactive"))
    #expect(source.contains("withAnimation(VaultWorkbenchMotion.interactive)"))
    #expect(source.contains(".animation(VaultWorkbenchMotion.interactive, value: isHovering)"))
}

@Test func numericTelemetryLabelsRespondToStringSelectorsOnMacOS27() {
    if #available(macOS 27.0, *) {
        let number = NSNumber(value: 42)
        #expect(number.responds(to: NSSelectorFromString("length")))
        #expect(number.responds(to: NSSelectorFromString("getCString:maxLength:encoding:")))
        #expect(number.responds(to: NSSelectorFromString("_getCString:maxLength:encoding:")))
        #expect(number.responds(to: NSSelectorFromString("UTF8String")))
    }
}
