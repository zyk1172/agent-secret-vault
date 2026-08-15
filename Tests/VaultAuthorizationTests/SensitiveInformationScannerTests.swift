import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func localSensitiveScannerReturnsWholeParagraphAndDoesNotSelectAnything() throws {
    let text = """
    NewAPI
    服务：NewAPI
    API：sk-ASVSCANFIXTURE0000000000000000

    已加密：[OpenAI API Key](secret://0123456789ABCDEFGHJKMNPQRS)
    """
    let scanner = LocalSensitiveInformationScanner()

    let candidates = try scanner.scan(filePath: "AI/工具与服务.md", text: text)

    #expect(candidates.count == 1)
    #expect(candidates[0].paragraph.contains("服务：NewAPI"))
    #expect(candidates[0].paragraph.contains("API：sk-ASVSCANFIXTURE0000000000000000"))
    #expect(candidates[0].matchedValue == "sk-ASVSCANFIXTURE0000000000000000")
    #expect(candidates[0].rule == "API Key 与访问密钥")
    #expect(candidates[0].risk == .high)
    #expect(candidates[0].source.line == 3)
}

@Test func localSensitiveScannerStillFindsUnencryptedValueInParagraphThatAlreadyHasAReference() throws {
    let text = "密码：ASVSCANFIXTURE0000 secret://0123456789ABCDEFGHJKMNPQRS"
    let scanner = LocalSensitiveInformationScanner()

    let candidates = try scanner.scan(filePath: "AI/工具与服务.md", text: text)
    #expect(candidates.count == 1)
    #expect(candidates[0].matchedValue == "ASVSCANFIXTURE0000")
}

@Test func localSensitiveWriterReplacesMultipleCandidatesInOneFileAtomically() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let fileURL = directory.appendingPathComponent("服务.md")
    let text = "API: abc123\nToken: xyz789"
    try text.write(to: fileURL, atomically: true, encoding: .utf8)
    let scanner = LocalSensitiveInformationScanner()
    let candidates = try scanner.scan(fileURL: fileURL, filePath: "服务.md", text: text)

    #expect(candidates.count == 2)
    try LocalSensitiveInformationWriter.replace(
        candidates,
        references: [
            "secret://ABCDEFGHJKMNPQRSTVWXYZ0123",
            "secret://0123456789ABCDEFGHJKMNPQRS"
        ]
    )

    let updated = try String(contentsOf: fileURL, encoding: .utf8)
    #expect(updated == "API: secret://ABCDEFGHJKMNPQRSTVWXYZ0123\nToken: secret://0123456789ABCDEFGHJKMNPQRS")
}

@Test func localSensitiveWriterReplacesOnlyAnUnchangedScannedCandidate() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let fileURL = directory.appendingPathComponent("服务.md")
    let text = "NAS 密码：ASVSCANFIXTURE0000"
    try text.write(to: fileURL, atomically: true, encoding: .utf8)
    let scanner = LocalSensitiveInformationScanner()
    let candidate = try #require(scanner.scan(fileURL: fileURL, filePath: "服务.md", text: text).first)

    try LocalSensitiveInformationWriter.replace(candidate, reference: "secret://0123456789ABCDEFGHJKMNPQRS")

    let updated = try String(contentsOf: fileURL, encoding: .utf8)
    #expect(updated == "NAS 密码： secret://0123456789ABCDEFGHJKMNPQRS")
}

@Test func localSensitiveScannerHandlesChineseSeparatorsWhitespaceAndWrappers() throws {
    let text = "API Key：  **ASVSCANFIXTURE0000**\n密码: \"ASVSCANPASSWORD0000\"\nToken＝`ASVSCANTOKEN0000`"
    let candidates = try LocalSensitiveInformationScanner().scan(filePath: "服务.md", text: text)

    #expect(candidates.count == 3)
    #expect(candidates.map(\.matchedValue) == ["ASVSCANFIXTURE0000", "ASVSCANPASSWORD0000", "ASVSCANTOKEN0000"])
    #expect(candidates.allSatisfy { $0.replacementText.hasPrefix(" ") || $0.replacementText.hasPrefix("**") || $0.replacementText.hasPrefix("\"") || $0.replacementText.hasPrefix("`") })
}
