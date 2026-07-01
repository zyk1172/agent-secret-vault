import Testing
import VaultIPC
@testable import AgentSecretVaultApp

@Test func paragraphRestoreBuilderBuildsContextForMultipleReferences() throws {
    let request = try ParagraphRestoreBuilder.build(
        from: "账号 secret://0123456789ABCDEFGHJKMNPQRS，密码 secret://ABCDEFGHJKMNPQRSTVWXYZ0123。"
    )

    #expect(request.references == [
        "secret://0123456789ABCDEFGHJKMNPQRS",
        "secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
    ])
    #expect(request.context == RevealContext(
        reason: "在本应用中解密段落",
        template: "账号 {{0}}，密码 {{1}}。",
        ranges: [
            ReferenceRange(index: 0, placeholder: "{{0}}"),
            ReferenceRange(index: 1, placeholder: "{{1}}")
        ]
    ))
}

@Test func paragraphRestoreBuilderRejectsParagraphWithoutReferences() {
    #expect(throws: ParagraphRestoreBuilderError.noSecretReferences) {
        _ = try ParagraphRestoreBuilder.build(from: "这里没有 Vault 引用")
    }
}
