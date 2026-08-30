import Foundation
import VaultCore

/// SVLT uses a device-owner authorization lease, not a semantic command
/// firewall.
///
/// The classifier answers exactly one question: "which authorization level
/// does this command need?" It never answers "is this command allowed?".
///
/// - Every technically valid SSH command defaults to `reusableApproval`:
///   one device-owner approval opens the scoped five-minute window.
/// - Only the small, explicitly declared fixed fresh rules (at most five
///   categories, see `SSHFreshRules`) promote a command to
///   `freshApprovalRequired`. They are detected with a deliberately shallow
///   lexical scan of the raw command; the scan exists solely to promote
///   reusable → fresh and can never deny.
/// - There is no safe-read tier, no unknown tier, and no syntax blocklist:
///   shell interpreters, pipelines, redirects, heredocs, `sudo`, interpreters,
///   `find -exec`, and unknown NAS CLIs are all ordinary operations. When the
///   scan cannot decide, the command stays on the ordinary path.
/// - Hard failures are reserved for malformed input (empty, NUL, oversized),
///   which the policy engine surfaces as technical errors.
public struct SSHCommandRiskClassification: Equatable, Sendable {
    public let risk: OperationRisk
    public let authorizationRequirement: AuthorizationRequirement
    public let reasons: [String]
    public let ruleID: String

    public init(
        risk: OperationRisk,
        authorizationRequirement: AuthorizationRequirement,
        reasons: [String],
        ruleID: String
    ) {
        self.risk = risk
        self.authorizationRequirement = authorizationRequirement
        self.reasons = reasons
        self.ruleID = ruleID
    }
}

/// The complete, explicit registry of SSH fresh rules. Test code asserts that
/// this list never grows past five categories.
public enum SSHFreshRules {
    public static let powerControl = "ssh.fresh.power-control"
    public static let filesystemDelete = "ssh.fresh.filesystem-delete"
    public static let blockDeviceFilesystem = "ssh.fresh.block-device-filesystem"
    public static let storageRaidDestruction = "ssh.fresh.storage-raid-destruction"
    public static let containerDestruction = "ssh.fresh.container-destruction"

    public static let all: [String] = [
        powerControl,
        filesystemDelete,
        blockDeviceFilesystem,
        storageRaidDestruction,
        containerDestruction
    ]
}

public struct SSHCommandRiskClassifier: Sendable {
    public let maxCommandLength: Int

    public init(maxCommandLength: Int = 65_536) {
        self.maxCommandLength = maxCommandLength
    }

    public func classify(command: String?) -> SSHCommandRiskClassification {
        guard let command, !command.isEmpty else {
            return technicalFailure("SSH 命令为空", ruleID: "ssh.command.missing")
        }
        guard command.utf8.count <= maxCommandLength else {
            return technicalFailure("SSH 命令超过长度限制", ruleID: "ssh.command.too-long")
        }
        guard !command.contains("\u{0}") else {
            return technicalFailure("SSH 命令包含 NUL 字节", ruleID: "ssh.command.nul")
        }
        // Tokenizing here is classification-only. The executor sends the raw
        // string byte-for-byte as one ssh remote-command argument; this split
        // never changes what runs remotely.
        return classifyTier(rawCommand: command)
    }

    public func classify(batch: SSHCommandBatch?) -> SSHCommandRiskClassification {
        guard let batch else {
            return technicalFailure("SSH 批处理缺失", ruleID: "ssh.batch.missing")
        }
        do {
            try batch.validate()
        } catch {
            return technicalFailure("SSH 批处理参数无效", ruleID: "ssh.batch.invalid")
        }

        for command in batch.commands {
            let current = classify(spec: command)
            if current.authorizationRequirement == .freshApprovalRequired {
                return SSHCommandRiskClassification(
                    risk: .approvalRequired,
                    authorizationRequirement: .freshApprovalRequired,
                    reasons: ["批处理最高风险："] + current.reasons,
                    ruleID: current.ruleID
                )
            }
        }
        return SSHCommandRiskClassification(
            risk: .approvalRequired,
            authorizationRequirement: .reusableApproval,
            reasons: ["SSH 批处理属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
            ruleID: "ssh.ordinary.reusable-approval"
        )
    }

    public func classify(spec: SSHCommandSpec) -> SSHCommandRiskClassification {
        guard (try? spec.validate()) != nil else {
            return technicalFailure("SSH 命令参数无效", ruleID: "ssh.command.invalid")
        }
        // A structured command is already an argv vector. Do not flatten it
        // into a shell-looking string merely for classification: doing so
        // would lose argument boundaries (notably `sh -c <script>`) and could
        // reintroduce the very argument-as-executable false positives this
        // scanner is meant to avoid.
        return classifyTier(executable: spec.executable, arguments: spec.arguments)
    }

    // MARK: - Tier classification

    private func classifyTier(rawCommand: String) -> SSHCommandRiskClassification {
        if let freshRule = matchFixedFreshRule(in: rawCommand) {
            return SSHCommandRiskClassification(
                risk: .approvalRequired,
                authorizationRequirement: .freshApprovalRequired,
                reasons: ["SSH 命令匹配固定高危类别（\(freshRule)），每次都需要设备所有者重新认证后执行"],
                ruleID: freshRule
            )
        }
        return SSHCommandRiskClassification(
            risk: .approvalRequired,
            authorizationRequirement: .reusableApproval,
            reasons: ["SSH 命令属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
            ruleID: "ssh.ordinary.reusable-approval"
        )
    }

    private func classifyTier(
        executable: String,
        arguments: [String]
    ) -> SSHCommandRiskClassification {
        if let freshRule = matchFixedFreshRule(
            executable: executable,
            arguments: arguments,
            depth: 0
        ) {
            return SSHCommandRiskClassification(
                risk: .approvalRequired,
                authorizationRequirement: .freshApprovalRequired,
                reasons: ["SSH 命令匹配固定高危类别（\(freshRule)），每次都需要设备所有者重新认证后执行"],
                ruleID: freshRule
            )
        }
        return SSHCommandRiskClassification(
            risk: .approvalRequired,
            authorizationRequirement: .reusableApproval,
            reasons: ["SSH 命令属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
            ruleID: "ssh.ordinary.reusable-approval"
        )
    }

    /// Shallow lexical detection for the fixed fresh rules only. It recognizes
    /// *command positions*, never arbitrary words: the start of a command
    /// segment, after a shell composition operator, after `sudo`/`env`, or
    /// inside the explicit script argument of `sh -c`/`bash -c`. This avoids
    /// treating an argument, path, grep pattern, or heredoc body as an
    /// executable. The scan is best-effort by design: an unmatched command
    /// stays on the ordinary path, and the scan can never deny anything.
    func matchFixedFreshRule(in rawCommand: String) -> String? {
        matchFixedFreshRule(in: rawCommand, depth: 0)
    }

    private func matchFixedFreshRule(in rawCommand: String, depth: Int) -> String? {
        // The nested script recursion is deliberately bounded. An opaque or
        // excessively nested script remains ordinary rather than turning this
        // classifier into a shell interpreter.
        guard depth <= 8 else { return nil }

        var commandWords: [String] = []
        for token in Self.shellTokens(in: rawCommand) {
            switch token {
            case let .word(word):
                commandWords.append(word)
            case .separator:
                if let freshRule = matchFixedFreshRule(inCommand: commandWords, depth: depth) {
                    return freshRule
                }
                commandWords.removeAll(keepingCapacity: true)
            }
        }
        return matchFixedFreshRule(inCommand: commandWords, depth: depth)
    }

    private func matchFixedFreshRule(inCommand words: [String], depth: Int) -> String? {
        guard let invocation = Self.commandInvocation(in: words) else {
            return nil
        }

        return matchFixedFreshRule(
            executable: invocation.executable,
            arguments: invocation.arguments,
            depth: depth
        )
    }

    private func matchFixedFreshRule(
        executable rawExecutable: String,
        arguments: [String],
        depth: Int
    ) -> String? {
        let executable = Self.basename(rawExecutable)
        if Self.powerControlExecutables.contains(executable) {
            return SSHFreshRules.powerControl
        }
        if Self.filesystemDeleteExecutables.contains(executable) {
            return SSHFreshRules.filesystemDelete
        }
        if executable.hasPrefix("mkfs") || Self.blockDeviceExecutables.contains(executable) {
            return SSHFreshRules.blockDeviceFilesystem
        }

        if executable == "systemctl",
           let subcommand = Self.significantArguments(
               arguments,
               optionsWithValue: Self.systemctlOptionsWithValue
           ).first,
           Self.dangerousSystemctlSubcommands.contains(subcommand) {
            return SSHFreshRules.powerControl
        }
        if executable == "zpool",
           Self.significantArguments(arguments).first == "destroy" {
            return SSHFreshRules.storageRaidDestruction
        }
        if executable == "mdadm",
           arguments
            .map(Self.basename)
            .contains(where: Self.destructiveMdadmFlags.contains) {
            return SSHFreshRules.storageRaidDestruction
        }
        if executable == "docker" {
            let subcommands = Self.significantArguments(
                arguments,
                optionsWithValue: Self.dockerOptionsWithValue
            )
            if subcommands.first == "rm"
                || (subcommands.first == "volume" && subcommands.dropFirst().first == "rm")
                || (subcommands.first == "system" && subcommands.dropFirst().first == "prune") {
                return SSHFreshRules.containerDestruction
            }
        }

        if Self.shellExecutables.contains(executable),
           let script = Self.shellCommandString(in: arguments) {
            return matchFixedFreshRule(in: script, depth: depth + 1)
        }

        return nil
    }

    private struct ShellInvocation {
        let executable: String
        let arguments: [String]
    }

    private enum ShellToken {
        case word(String)
        case separator
    }

    private struct HereDocumentDelimiter {
        let value: String
        let stripsLeadingTabs: Bool
    }

    /// A minimal lexer for the scanner only. It preserves quoted strings as
    /// one word, recognizes composition boundaries, and skips heredoc bodies
    /// so text such as `echo rm`, `/tmp/rm`, and `<<EOF ... rm ... EOF` is not
    /// misclassified as an executable.
    private static func shellTokens(in command: String) -> [ShellToken] {
        let characters = Array(command)
        var index = 0
        var word: [Character] = []
        var tokens: [ShellToken] = []
        var waitingForHereDocumentDelimiter: Bool?
        var hereDocuments: [HereDocumentDelimiter] = []

        func flushWord() {
            guard !word.isEmpty else { return }
            let value = String(word)
            word.removeAll(keepingCapacity: true)
            if let stripsLeadingTabs = waitingForHereDocumentDelimiter {
                hereDocuments.append(HereDocumentDelimiter(
                    value: value,
                    stripsLeadingTabs: stripsLeadingTabs
                ))
                waitingForHereDocumentDelimiter = nil
            } else {
                tokens.append(.word(value))
            }
        }

        while index < characters.count {
            let character = characters[index]
            switch character {
            case " ", "\t":
                flushWord()
                index += 1
            case "\n", "\r":
                flushWord()
                // Treat CRLF as one command boundary.
                if character == "\r", index + 1 < characters.count, characters[index + 1] == "\n" {
                    index += 1
                }
                index += 1
                tokens.append(.separator)
                if !hereDocuments.isEmpty {
                    skipHereDocumentBodies(
                        hereDocuments,
                        in: characters,
                        index: &index
                    )
                    hereDocuments.removeAll(keepingCapacity: true)
                }
            case ";", "&", "|", "(", ")", "{", "}":
                flushWord()
                tokens.append(.separator)
                if (character == "&" || character == "|")
                    && index + 1 < characters.count
                    && characters[index + 1] == character {
                    index += 1
                }
                index += 1
            case "<":
                flushWord()
                if index + 1 < characters.count, characters[index + 1] == "<" {
                    index += 2
                    var stripsLeadingTabs = false
                    if index < characters.count, characters[index] == "-" {
                        stripsLeadingTabs = true
                        index += 1
                    }
                    waitingForHereDocumentDelimiter = stripsLeadingTabs
                } else {
                    index += 1
                }
            case ">":
                flushWord()
                index += 1
                if index < characters.count, characters[index] == ">" {
                    index += 1
                }
            case "'", "\"":
                let quote = character
                index += 1
                while index < characters.count {
                    let quotedCharacter = characters[index]
                    if quotedCharacter == quote {
                        index += 1
                        break
                    }
                    if quote == "\"", quotedCharacter == "\\", index + 1 < characters.count {
                        index += 1
                    }
                    word.append(characters[index])
                    index += 1
                }
            case "\\":
                if index + 1 < characters.count {
                    word.append(characters[index + 1])
                    index += 2
                } else {
                    word.append(character)
                    index += 1
                }
            case "#" where word.isEmpty:
                while index < characters.count, characters[index] != "\n", characters[index] != "\r" {
                    index += 1
                }
            default:
                word.append(character)
                index += 1
            }
        }
        flushWord()
        return tokens
    }

    private static func skipHereDocumentBodies(
        _ delimiters: [HereDocumentDelimiter],
        in characters: [Character],
        index: inout Int
    ) {
        for delimiter in delimiters {
            while index < characters.count {
                let lineStart = index
                while index < characters.count,
                      characters[index] != "\n",
                      characters[index] != "\r" {
                    index += 1
                }
                var line = String(characters[lineStart..<index])
                if line.last == "\r" {
                    line.removeLast()
                }
                let comparison = delimiter.stripsLeadingTabs
                    ? String(line.drop(while: { $0 == "\t" }))
                    : line
                if index < characters.count, characters[index] == "\r" {
                    index += 1
                }
                if index < characters.count, characters[index] == "\n" {
                    index += 1
                }
                if comparison == delimiter.value {
                    break
                }
            }
        }
    }

    private static func commandInvocation(in words: [String]) -> ShellInvocation? {
        var index = 0
        while index < words.count {
            let rawWord = words[index]
            let word = basename(rawWord)
            guard !word.isEmpty else {
                index += 1
                continue
            }
            if shellControlKeywords.contains(word) || looksLikeVariableAssignment(rawWord) {
                index += 1
                continue
            }
            if word == "sudo" || word == "doas" {
                index = skipSudoOptions(in: words, from: index + 1)
                continue
            }
            if word == "env" {
                index = skipEnvironmentPrefix(in: words, from: index + 1)
                continue
            }
            return ShellInvocation(
                executable: word,
                arguments: Array(words.dropFirst(index + 1))
            )
        }
        return nil
    }

    private static func skipSudoOptions(in words: [String], from start: Int) -> Int {
        var index = start
        while index < words.count {
            let argument = words[index]
            if argument == "--" {
                return index + 1
            }
            guard argument.hasPrefix("-") else { return index }
            if sudoOptionsWithValue.contains(argument) {
                index += 2
            } else {
                index += 1
            }
        }
        return index
    }

    private static func skipEnvironmentPrefix(in words: [String], from start: Int) -> Int {
        var index = start
        while index < words.count {
            let argument = words[index]
            if argument == "--" {
                return index + 1
            }
            if environmentOptionsWithValue.contains(argument) {
                index += 2
                continue
            }
            if argument.hasPrefix("-") || looksLikeVariableAssignment(argument) {
                index += 1
                continue
            }
            return index
        }
        return index
    }

    private static func significantArguments(
        _ arguments: [String],
        optionsWithValue: Set<String> = []
    ) -> [String] {
        var result: [String] = []
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--" {
                result.append(contentsOf: arguments.dropFirst(index + 1).map(basename))
                break
            }
            if argument.hasPrefix("-") {
                index += optionsWithValue.contains(argument) ? 2 : 1
                continue
            }
            result.append(basename(argument))
            index += 1
        }
        return result.filter { !$0.isEmpty }
    }

    private static func shellCommandString(in arguments: [String]) -> String? {
        for (index, argument) in arguments.enumerated() {
            if argument == "-c" || argument == "--command" {
                guard index + 1 < arguments.count else { return nil }
                return arguments[index + 1]
            }
            if argument.hasPrefix("--command=") {
                return String(argument.dropFirst("--command=".count))
            }
            if argument.hasPrefix("-"),
               !argument.hasPrefix("--"),
               argument.dropFirst().contains("c"),
               index + 1 < arguments.count {
                return arguments[index + 1]
            }
        }
        return nil
    }

    private static func looksLikeVariableAssignment(_ word: String) -> Bool {
        guard let equals = word.firstIndex(of: "="), equals != word.startIndex else {
            return false
        }
        let name = word[..<equals]
        guard let first = name.first, first == "_" || first.isLetter else {
            return false
        }
        return name.dropFirst().allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber }
    }

    /// Normalizes an executable only after it was identified in command
    /// position, so `/bin/rm` is recognized but `/tmp/rm` as an argument is
    /// not. Classification only — the raw command sent to SSH is never
    /// rewritten.
    private static func basename(_ word: String) -> String {
        let trimmed = word.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        guard !trimmed.isEmpty else { return "" }
        return URL(fileURLWithPath: trimmed).lastPathComponent.lowercased()
    }

    private static let powerControlExecutables: Set<String> = [
        "reboot", "shutdown", "poweroff", "halt"
    ]

    private static let dangerousSystemctlSubcommands: Set<String> = [
        "reboot", "poweroff", "halt", "kexec", "isolate", "rescue", "emergency"
    ]

    private static let filesystemDeleteExecutables: Set<String> = [
        "rm", "shred"
    ]

    private static let blockDeviceExecutables: Set<String> = [
        "wipefs", "fdisk", "parted", "dd"
    ]

    private static let destructiveMdadmFlags: Set<String> = [
        "--zero-superblock", "--fail", "--stop", "--remove"
    ]

    private static let shellExecutables: Set<String> = [
        "sh", "bash", "dash", "zsh", "ksh", "ash"
    ]

    private static let shellControlKeywords: Set<String> = [
        "if", "then", "elif", "else", "fi", "for", "while", "until",
        "do", "done", "case", "esac", "in", "function", "!"
    ]

    private static let sudoOptionsWithValue: Set<String> = [
        "-u", "-g", "-h", "-p", "-r", "-t", "-C"
    ]

    private static let environmentOptionsWithValue: Set<String> = [
        "-u", "-C", "--unset", "--chdir", "-S"
    ]

    private static let systemctlOptionsWithValue: Set<String> = [
        "-H", "--host", "-M", "--machine", "--root"
    ]

    private static let dockerOptionsWithValue: Set<String> = [
        "-H", "--host", "--context", "-c", "--config"
    ]

    private func technicalFailure(_ reason: String, ruleID: String) -> SSHCommandRiskClassification {
        SSHCommandRiskClassification(
            risk: .denied,
            authorizationRequirement: .denied,
            reasons: [reason],
            ruleID: ruleID
        )
    }
}
