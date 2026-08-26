import SwiftUI
import Testing
@testable import AgentSecretVaultApp

@Test func menuBarPresentationUsesCompactNativeDimensions() {
    #expect(MenuBarPresentation.statusItemSymbol == "lock.fill")
    #expect(MenuBarPresentation.panelSize == CGSize(width: 420, height: 600))
    #expect(MenuBarPresentation.mainWindowID == "agent-secret-vault-main")
}
