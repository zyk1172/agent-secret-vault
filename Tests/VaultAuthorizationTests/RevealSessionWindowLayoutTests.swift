import CoreGraphics
import Testing
@testable import AgentSecretVaultApp

@Test func revealSessionWindowUsesFixedContentSizeToAvoidConstraintLoops() {
    #expect(RevealSessionWindowLayout.contentSize == CGSize(width: 560, height: 320))
    #expect(RevealSessionWindowLayout.minimumSize == CGSize(width: 480, height: 240))
}
