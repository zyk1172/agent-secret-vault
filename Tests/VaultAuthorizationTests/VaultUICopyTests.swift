import Testing
@testable import AgentSecretVaultApp

@Test func bilingualProductPromiseIsNativeAndSpecific() {
    #expect(VaultUICopy.overviewPromise.english == "Let agents work with secrets without seeing plaintext.")
    #expect(VaultUICopy.overviewPromise.chinese == "让智能体使用敏感信息，但不接触明文。")
}

@Test func overviewGuideContainsExactlyFourUsageSteps() {
    let steps = VaultUICopy.usageSteps

    #expect(steps.count == 4)
    #expect(steps.map(\.englishTitle) == [
        "Select sensitive text",
        "Encrypt into a reference",
        "Let the agent use the reference",
        "Reveal, send, or restore locally"
    ])
    #expect(steps.map(\.chineseTitle) == [
        "选择敏感文本",
        "加密为引用",
        "让智能体使用引用",
        "在本机查看、发送或还原"
    ])
    #expect(steps.map(\.chineseBody).joined().contains("Mac App") == false)
    #expect(steps.map(\.chineseBody).joined().contains("Agent ") == false)
}

@Test func safetyBoundariesStayHonestAboutExcludedThreats() {
    let allEnglish = VaultUICopy.securityBoundaries
        .map { "\($0.englishTitle) \($0.englishBody)" }
        .joined(separator: "\n")
    let allChinese = VaultUICopy.securityBoundaries
        .map { "\($0.chineseTitle) \($0.chineseBody)" }
        .joined(separator: "\n")

    #expect(allEnglish.contains("Temporary reveal does not return decrypted values to the plugin."))
    #expect(allEnglish.contains("Restore is explicit"))
    #expect(allEnglish.contains("same macOS user"))
    #expect(allEnglish.contains("administrator or root"))
    #expect(allChinese.contains("临时解密不会把明文返回给插件。"))
    #expect(allChinese.contains("还原是显式操作"))
    #expect(allChinese.contains("同一 macOS 用户"))
    #expect(allChinese.contains("管理员或 root"))
}

@Test func clipboardBoundaryDoesNotClaimAppClipboardClearing() throws {
    let clipboardBoundary = try #require(VaultUICopy.securityBoundaries.first { $0.id == "clipboard" })

    #expect(clipboardBoundary.englishBody.contains("system clipboard"))
    #expect(clipboardBoundary.chineseBody.contains("系统剪贴板"))
    #expect(clipboardBoundary.englishBody.contains("The app clears") == false)
    #expect(clipboardBoundary.chineseBody.contains("App") == false)
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
