import Foundation
import Testing
import VaultCore

@Test func auditCallerIsDisplayOnlyAndSanitized() {
    let caller = AuditCaller(name: "Codex\nsecret://0123456789ABCDEFGHJKMNPQRS", version: "1.2")

    #expect(caller.displayName == "Unknown MCP Client")
    #expect(caller.displayLabel == "Unknown MCP Client（自报 1.2）")
    #expect(!caller.displayLabel.contains("secret://"))
    #expect(!caller.displayLabel.contains("\n"))
}

@Test func auditCallerLimitsUtf8BytesWithoutSplittingUnicodeScalars() {
    let caller = AuditCaller(name: String(repeating: "测", count: 100))

    #expect(caller.displayName.utf8.count <= 64)
    #expect(caller.displayName.unicodeScalars.allSatisfy { $0.value == 0x6D4B })
}

@Test func auditCallerSanitizesUnicodeLineSeparators() {
    let caller = AuditCaller(name: "Codex\u{2028}Pi\u{2029}Hermes")

    #expect(caller.displayName == "CodexPiHermes")
    #expect(!caller.displayLabel.contains("\u{2028}"))
    #expect(!caller.displayLabel.contains("\u{2029}"))
}

@Test func missingCallerIsExplicitlySelfDeclaredUnknown() {
    let caller = AuditCaller.unknownMCPClient

    #expect(caller.displayLabel == "Unknown MCP Client（自报）")
    #expect(caller.trust == .selfDeclared)
}
