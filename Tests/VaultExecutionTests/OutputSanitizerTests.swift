import Foundation
import Testing
@testable import VaultExecution

@Test func redactsExactUTF8SecretMatchesInStdoutAndStderr() throws {
    let result = ProcessResult(
        exitCode: 0,
        stdout: bytes("sent token-123"),
        stderr: bytes("debug token-123")
    )

    let sanitized = OutputSanitizer().sanitize(result, secrets: [bytes("token-123")])

    #expect(sanitized == .sanitized(ProcessResult(
        exitCode: 0,
        stdout: bytes("sent [REDACTED_SECRET]"),
        stderr: bytes("debug [REDACTED_SECRET]")
    )))
}

@Test func redactsRepeatedAndOverlappingSecretsLongestFirst() throws {
    let result = ProcessResult(
        exitCode: 0,
        stdout: bytes("abcd abc abcd"),
        stderr: Data()
    )

    let sanitized = OutputSanitizer().sanitize(
        result,
        secrets: [bytes("abc"), bytes("abcd")]
    )

    #expect(sanitized == .sanitized(ProcessResult(
        exitCode: 0,
        stdout: bytes("[REDACTED_SECRET] [REDACTED_SECRET] [REDACTED_SECRET]"),
        stderr: Data()
    )))
}

@Test func redactsSecretsSplitAcrossReadChunksAfterReassembly() throws {
    var stdout = Data()
    stdout.append(bytes("prefix tok"))
    stdout.append(bytes("en-123 suffix"))

    let sanitized = OutputSanitizer().sanitize(
        ProcessResult(exitCode: 0, stdout: stdout, stderr: Data()),
        secrets: [bytes("token-123")]
    )

    #expect(sanitized == .sanitized(ProcessResult(
        exitCode: 0,
        stdout: bytes("prefix [REDACTED_SECRET] suffix"),
        stderr: Data()
    )))
}

@Test func quarantinesBinaryOutput() throws {
    let result = ProcessResult(
        exitCode: 0,
        stdout: Data([0x41, 0x00, 0x42]),
        stderr: Data()
    )

    let sanitized = OutputSanitizer().sanitize(result, secrets: [bytes("token-123")])

    #expect(sanitized == .quarantined(reason: .binaryOutput))
}

@Test func quarantinesInvalidUTF8Output() throws {
    let result = ProcessResult(
        exitCode: 0,
        stdout: Data([0xFF, 0xFE]),
        stderr: Data()
    )

    let sanitized = OutputSanitizer().sanitize(result, secrets: [bytes("token-123")])

    #expect(sanitized == .quarantined(reason: .invalidUTF8))
}

@Test func quarantinesEncodedSecretVariantsThatAreNotDeclaredSafe() throws {
    let encodedSecret = bytes("secret value").base64EncodedString()
    let result = ProcessResult(
        exitCode: 0,
        stdout: bytes("remote echoed \(encodedSecret)"),
        stderr: Data()
    )

    let sanitized = OutputSanitizer().sanitize(result, secrets: [bytes("secret value")])

    #expect(sanitized == .quarantined(reason: .encodedSecretVariantDetected))
}

@Test func quarantinesHexSecretVariantsThatAreNotDeclaredSafe() throws {
    let secret = bytes("secret value")
    let hexSecret = secret.map { String(format: "%02x", $0) }.joined()
    let result = ProcessResult(
        exitCode: 0,
        stdout: bytes("remote echoed \(hexSecret)"),
        stderr: Data()
    )

    let sanitized = OutputSanitizer().sanitize(result, secrets: [secret])

    #expect(sanitized == .quarantined(reason: .encodedSecretVariantDetected))
}

@Test func quarantinesEmptySecretMaterial() throws {
    let result = ProcessResult(exitCode: 0, stdout: bytes("safe"), stderr: Data())

    let sanitized = OutputSanitizer().sanitize(result, secrets: [Data()])

    #expect(sanitized == .quarantined(reason: .emptySecretMaterial))
}

private func bytes(_ value: String) -> Data {
    Data(value.utf8)
}
