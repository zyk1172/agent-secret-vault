import Foundation
import Testing
import VaultCore
@testable import VaultExecution

@Test func structuredSSHArgumentsAreQuotedIndependentlyAtRemoteShellBoundary() throws {
    let payloads = [
        "a b",
        "a'b",
        "$(id)",
        "; rm -rf /",
        "| cat",
        "> file",
        "`id`",
        "$HOME",
        "通道参数"
    ]

    for payload in payloads {
        let command = SSHCommandSpec(executable: "printf", arguments: [payload])
        let encoded = try SSHRemoteCommandEncoder.encode(command)

        #expect(encoded == "'printf' \(SSHRemoteCommandEncoder.quote(payload))")
    }
}

@Test func structuredSSHNewlineIsQuotedAsALiteralArgument() throws {
    let command = SSHCommandSpec(executable: "printf", arguments: ["line1\nline2"])

    #expect(try SSHRemoteCommandEncoder.encode(command) == "'printf' 'line1\nline2'")
}

@Test func structuredSSHNulIsRejected() {
    let command = SSHCommandSpec(executable: "printf", arguments: ["line1\0line2"])

    do {
        _ = try SSHRemoteCommandEncoder.encode(command)
        Issue.record("NUL must not cross the process argument boundary.")
    } catch SSHCommandBatchValidationError.argumentContainsControlCharacter {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func legacySSHCommandRejectsShellCompositionAndQuotes() {
    for command in [
        "whoami; pwd",
        "whoami && pwd",
        "whoami | cat",
        "echo > file",
        "echo `id`",
        "echo $(id)",
        "sh -c id",
        "bash -c id",
        "echo 'quoted'"
    ] {
        do {
            _ = try SSHRemoteCommandEncoder.parseLegacy(command)
            Issue.record("Legacy command was accepted: \(command)")
        } catch SSHRemoteCommandEncodingError.unsupportedLegacySyntax {
            continue
        } catch SSHRemoteCommandEncodingError.unsupportedShellExecutable {
            continue
        } catch {
            Issue.record("Unexpected error for \(command): \(error)")
        }
    }
}

@Test func shellExecutablesAreRejectedEvenWhenStructured() {
    for executable in ["sh", "/bin/bash", "zsh"] {
        do {
            _ = try SSHRemoteCommandEncoder.encode(
                SSHCommandSpec(executable: executable, arguments: ["-c", "id"])
            )
            Issue.record("Shell executable was accepted: \(executable)")
        } catch SSHRemoteCommandEncodingError.unsupportedShellExecutable {
            continue
        } catch {
            Issue.record("Unexpected error for \(executable): \(error)")
        }
    }
}

@Test func legacySimpleSSHCommandBecomesExplicitlyQuotedArgv() throws {
    let spec = try SSHRemoteCommandEncoder.parseLegacy("df -h /share/external")

    #expect(spec == SSHCommandSpec(
        executable: "df",
        arguments: ["-h", "/share/external"]
    ))
    #expect(try SSHRemoteCommandEncoder.encode(spec) == "'df' '-h' '/share/external'")
}
