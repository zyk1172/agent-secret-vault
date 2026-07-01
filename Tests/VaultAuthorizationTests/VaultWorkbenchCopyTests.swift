import Testing
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

@Test func workbenchCopyProvidesSimpleUserWorkflow() {
    #expect(VaultWorkbenchCopy.simpleUsageSteps.count == 3)
    #expect(VaultWorkbenchCopy.simpleUsageSteps[0].contains("右键"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[1].contains("secret://"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[1].contains("Codex"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[1].contains("Claude"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[1].contains("Hermes"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[1].contains("自动识别"))
    #expect(VaultWorkbenchCopy.simpleUsageSteps[2].contains("解密整个段落"))
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
    ] + VaultWorkbenchCopy.simpleUsageSteps

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
        "使用教程",
        "段落解密",
        "记录维护",
        "智能体自动化",
        "安全边界"
    ])
    #expect(VaultWorkbenchSection.tutorial.subtitle.contains("安装"))
    #expect(VaultWorkbenchSection.paragraph.subtitle.contains("一次解密"))
    #expect(VaultWorkbenchSection.allCases.allSatisfy { !$0.systemImage.isEmpty })
}
