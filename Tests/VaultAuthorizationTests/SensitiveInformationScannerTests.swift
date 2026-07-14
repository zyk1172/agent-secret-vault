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
    #expect(candidates[0].risk == .high)
    #expect(candidates[0].source.line == 3)
}

@Test func localSensitiveScannerSkipsEntireParagraphThatAlreadyHasAReference() throws {
    let text = "密码：ASVSCANFIXTURE0000 secret://0123456789ABCDEFGHJKMNPQRS"
    let scanner = LocalSensitiveInformationScanner()

    #expect(try scanner.scan(filePath: "AI/工具与服务.md", text: text).isEmpty)
}

@Test func localSensitiveWriterReplacesOnlyAnUnchangedScannedCandidate() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let fileURL = directory.appendingPathComponent("服务.md")
    let text = "NAS 密码：ASVSCANFIXTURE0000"
    try text.write(to: fileURL, atomically: true, encoding: .utf8)
    let scanner = LocalSensitiveInformationScanner()
    let candidate = try #require(scanner.scan(fileURL: fileURL, filePath: "服务.md", text: text).first)

    try LocalSensitiveInformationWriter.replace(
        candidate,
        displayID: "S-001",
        reference: "secret://0123456789ABCDEFGHJKMNPQRS"
    )

    let updated = try String(contentsOf: fileURL, encoding: .utf8)
    #expect(updated == "NAS 密码：[S-001 NAS 密码](secret://0123456789ABCDEFGHJKMNPQRS)")
}
