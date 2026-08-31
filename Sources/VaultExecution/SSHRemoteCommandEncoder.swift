import Foundation
import VaultCore

public enum SSHRemoteCommandEncodingError: Error, Equatable, Sendable {
    case invalidCommand
    case commandTooLong
}

/// Produces the one remote command string that OpenSSH ultimately gives to
/// the remote login shell.
///
/// SVLT does not re-parse, re-interpret, or second-guess remote commands:
///
/// - A raw single-line or multi-line command is validated for technical
///   sanity only (non-empty, UTF-8, no NUL, size limit) and is passed
///   byte-for-byte as a single `ssh` argv element, so the local shell never
///   interprets it and the remote login shell sees exactly what the caller
///   wrote.
/// - A structured batch command keeps its argv semantics: every field is
///   quoted independently with POSIX single-quote rules, so
///   `executable=bash, arguments=["-c", "..."]` runs exactly that argv on the
///   remote host.
///
/// There is deliberately no syntax blocklist here: shell syntax, quotes,
/// pipelines, redirects, heredocs, interpreters, and unknown commands are the
/// remote login shell's job, and the authorization level is the policy
/// engine's job — not the encoder's.
public enum SSHRemoteCommandEncoder {
    /// The technical size ceiling for one raw remote command.
    public static let maxRawCommandBytes = 65_536

    /// Validates and returns the raw command unchanged. Newlines, quotes,
    /// backslashes, `$`, globs, pipelines, redirects, and heredocs are
    /// preserved exactly; only NUL and oversize input are technical errors.
    public static func rawRemoteCommand(_ command: String) throws -> String {
        guard !command.isEmpty else {
            throw SSHRemoteCommandEncodingError.invalidCommand
        }
        guard !command.contains("\u{0}") else {
            throw SSHRemoteCommandEncodingError.invalidCommand
        }
        guard command.utf8.count <= maxRawCommandBytes else {
            throw SSHRemoteCommandEncodingError.commandTooLong
        }
        return command
    }

    /// Converts structured argv-like input to the remote command string. The
    /// remote login shell receives the quoted argv; the interpreter choice
    /// (including `sh`/`bash`/`python`/...) belongs to the caller and is only
    /// reflected in the authorization level, never refused here.
    public static func encode(_ command: SSHCommandSpec) throws -> String {
        try command.validate()
        return ([command.executable] + command.arguments).map(quote).joined(separator: " ")
    }

    public static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}
