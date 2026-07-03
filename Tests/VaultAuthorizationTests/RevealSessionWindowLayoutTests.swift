import CoreGraphics
import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func revealSessionWindowUsesFixedContentSizeToAvoidConstraintLoops() {
    #expect(RevealSessionWindowLayout.contentSize == CGSize(width: 560, height: 320))
    #expect(RevealSessionWindowLayout.minimumSize == CGSize(width: 480, height: 240))
}

@Test func revealSessionWindowDoesNotDisableResolvedTextSelection() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(!source.contains(".textSelection(.disabled)"))
    #expect(source.contains(".textSelection(.enabled)"))
}
