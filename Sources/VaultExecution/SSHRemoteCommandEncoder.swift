import Foundation
import VaultCore

public enum SSHRemoteCommandEncodingError: Error, Equatable, Sendable {
    case invalidCommand
    case unsupportedLegacySyntax
    case unsupportedShellExecutable
}

/// Converts structured argv-like input to the one remote command string that
/// OpenSSH ultimately gives to the remote login shell. Every field is quoted
/// independently using POSIX single-quote rules; no raw shell fragment is
/// accepted.
public enum SSHRemoteCommandEncoder {
    public static func encode(_ command: SSHCommandSpec) throws -> String {
        try command.validate()
        let executable = URL(fileURLWithPath: command.executable).lastPathComponent.lowercased()
        guard !shellExecutables.contains(executable) else {
            throw SSHRemoteCommandEncodingError.unsupportedShellExecutable
        }
        return ([command.executable] + command.arguments).map(quote).joined(separator: " ")
    }

    /// Compatibility bridge for the original one-string tool. It accepts only
    /// simple whitespace-separated argv and then applies the same quoting as a
    /// structured request. Shell syntax, quotes, and backslashes require the
    /// structured API instead of being interpreted by SVLT.
    public static func parseLegacy(_ command: String) throws -> SSHCommandSpec {
        guard !command.isEmpty,
              !command.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
        else {
            throw SSHRemoteCommandEncodingError.invalidCommand
        }
        let forbidden = [";", "&&", "||", "|", ">", "<", "`", "$(", "${", "&", "*", "?", "[", "]", "'", "\"", "\\"]
        guard !forbidden.contains(where: command.contains) else {
            throw SSHRemoteCommandEncodingError.unsupportedLegacySyntax
        }
        let tokens = command.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let executable = tokens.first else {
            throw SSHRemoteCommandEncodingError.invalidCommand
        }
        let spec = SSHCommandSpec(executable: executable, arguments: Array(tokens.dropFirst()))
        try spec.validate()
        let executableName = URL(fileURLWithPath: spec.executable).lastPathComponent.lowercased()
        guard !shellExecutables.contains(executableName) else {
            throw SSHRemoteCommandEncodingError.unsupportedShellExecutable
        }
        return spec
    }

    public static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static let shellExecutables: Set<String> = [
        "sh", "bash", "zsh", "fish", "ksh", "dash", "ash", "csh", "tcsh"
    ]
}
