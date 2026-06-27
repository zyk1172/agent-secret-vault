import Testing
@testable import AgentSecretVaultApp

@Test func workbenchCopyDoesNotPretendDisconnectedToolsAreReady() {
    let copy = VaultWorkbenchCopy.disconnected
    #expect(copy.primaryAction.contains("Install Obsidian plugin"))
    #expect(!copy.status.lowercased().contains("ready to encrypt"))
}

@Test func workbenchCopySaysPluginNeverReceivesDecryptedValues() {
    let boundary = VaultWorkbenchCopy.securityBoundary
    #expect(boundary.contains("plugin does not receive decrypted values"))
    #expect(!boundary.contains("plugin decrypts"))
}
