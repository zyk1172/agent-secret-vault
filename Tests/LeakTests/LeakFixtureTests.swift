import Foundation
import Testing

@Test func plaintextScannerFindsCanaryWithoutEchoingSecretValue() async throws {
    let canary = "ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST"
    let root = projectRoot()
    let fixtureDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("LeakFixtureTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: fixtureDirectory, withIntermediateDirectories: true)
    defer {
        try? FileManager.default.removeItem(at: fixtureDirectory)
    }

    let leakURL = fixtureDirectory.appendingPathComponent("deliberate-leak.txt")
    try Data(canary.utf8).write(to: leakURL)

    let result = try await runScanner(
        root: root,
        canary: canary,
        scanPaths: [fixtureDirectory]
    )

    #expect(result.exitCode != 0)
    #expect(result.stdout.contains(leakURL.path))
    #expect(!result.stdout.contains(canary))
    #expect(!result.stderr.contains(canary))
}

private struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

private func runScanner(
    root: URL,
    canary: String,
    scanPaths: [URL]
) async throws -> ProcessResult {
    let process = Process()
    let stdout = Pipe()
    let stderr = Pipe()
    process.executableURL = root.appendingPathComponent("scripts/scan-plaintext.sh")
    process.arguments = scanPaths.map(\.path)
    process.environment = ProcessInfo.processInfo.environment.merging(
        ["ASV_CANARY": canary],
        uniquingKeysWith: { _, new in new }
    )
    process.standardOutput = stdout
    process.standardError = stderr

    try process.run()
    process.waitUntilExit()

    return ProcessResult(
        exitCode: process.terminationStatus,
        stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
        stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    )
}

private func projectRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}
