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
        "Manage credentials in the catalog",
        "Keep Markdown valid v3",
        "Reveal by field",
        "Approve agent mutations"
    ])
    #expect(steps.map(\.chineseTitle) == [
        "在目录中管理凭据",
        "保持 v3 Markdown 合法",
        "按字段查看密码",
        "逐笔批准智能体修改"
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

    #expect(allEnglish.contains("Field reveal shows plaintext only inside this app"))
    #expect(allEnglish.contains("fresh device-owner authentication"))
    #expect(allEnglish.contains("same macOS user"))
    #expect(allEnglish.contains("administrator or root"))
    #expect(allChinese.contains("密码字段解密后的明文只在本应用内显示"))
    #expect(allChinese.contains("每次都需要本机身份认证"))
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
