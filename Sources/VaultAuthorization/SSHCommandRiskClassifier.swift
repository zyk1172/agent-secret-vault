import Foundation
import VaultCore

/// Conservative classifier for SSH commands. Known read-only commands are
/// silent, known reversible writes use the scoped reusable approval lease, and
/// destructive or unparseable commands require a fresh device-owner decision.
/// Shell composition is rejected by the policy engine rather than treated as
/// a command that can be made safe by quoting.
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

public struct SSHCommandRiskClassifier: Sendable {
    public let maxCommandLength: Int

    public init(maxCommandLength: Int = 2_000) {
        self.maxCommandLength = maxCommandLength
    }

    public func classify(command: String?) -> SSHCommandRiskClassification {
        guard let command, !command.isEmpty else {
            return denied("SSH 命令为空", ruleID: "ssh.command.missing")
        }
        guard command.utf8.count <= maxCommandLength else {
            return denied("SSH 命令超过长度限制", ruleID: "ssh.command.too-long")
        }
        guard !containsForbiddenShellSyntax(command) else {
            return denied("SSH 命令包含不支持的 shell 组合语法", ruleID: "ssh.command.ambiguous-shell")
        }

        let tokens = command.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let executable = tokens.first else {
            return denied("SSH 命令无法解析", ruleID: "ssh.command.unparseable")
        }
        return classify(spec: SSHCommandSpec(executable: executable, arguments: Array(tokens.dropFirst())))
    }

    public func classify(batch: SSHCommandBatch?) -> SSHCommandRiskClassification {
        guard let batch else {
            return denied("SSH 批处理缺失", ruleID: "ssh.batch.missing")
        }
        do {
            try batch.validate()
        } catch {
            return denied("SSH 批处理参数无效", ruleID: "ssh.batch.invalid")
        }

        var highest = SSHCommandRiskClassification(
            risk: .silent,
            authorizationRequirement: .none,
            reasons: [],
            ruleID: "ssh.batch.read-only.silent"
        )
        for command in batch.commands {
            let current = classify(spec: command)
            highest = combine(highest, current)
            if highest.authorizationRequirement == .denied {
                break
            }
        }
        if highest.reasons.isEmpty {
            return SSHCommandRiskClassification(
                risk: .silent,
                authorizationRequirement: .none,
                reasons: ["SSH 批处理被本地解析为只读操作"],
                ruleID: "ssh.batch.read-only.silent"
            )
        }
        return SSHCommandRiskClassification(
            risk: highest.risk,
            authorizationRequirement: highest.authorizationRequirement,
            reasons: ["批处理最高风险："] + highest.reasons,
            ruleID: highest.ruleID
        )
    }

    public func classify(spec: SSHCommandSpec) -> SSHCommandRiskClassification {
        guard (try? spec.validate()) != nil else {
            return denied("SSH 命令参数无效", ruleID: "ssh.command.invalid")
        }

        let executable = URL(fileURLWithPath: spec.executable).lastPathComponent.lowercased()
        let arguments = spec.arguments.map { $0.lowercased() }
        if Self.shellExecutables.contains(executable) {
            return denied("SSH 不允许通过 shell 解释器执行未结构化命令", ruleID: "ssh.shell-executable.denied")
        }
        if isDestructive(executable: executable, arguments: arguments) {
            return SSHCommandRiskClassification(
                risk: .approvalRequired,
                authorizationRequirement: .freshApprovalRequired,
                reasons: ["SSH 命令可能造成不可逆远程破坏，必须重新本机认证"],
                ruleID: "ssh.destructive.fresh-approval"
            )
        }

        if isReadOnly(executable: executable, arguments: arguments) {
            return SSHCommandRiskClassification(
                risk: .silent,
                authorizationRequirement: .none,
                reasons: ["SSH 命令被本地解析为只读操作"],
                ruleID: "ssh.read-only.silent"
            )
        }

        if Self.reversibleWriteCommands.contains(executable) {
            return SSHCommandRiskClassification(
                risk: .approvalRequired,
                authorizationRequirement: .reusableApproval,
                reasons: ["SSH 命令可能修改远程状态，需要本机审批"],
                ruleID: "ssh.effect.reusable-approval"
            )
        }

        // Unknown semantics are never silently approved. A fresh decision is
        // safer than an incomplete blacklist and still allows a user to make
        // an explicit decision for a purpose-built command.
        return SSHCommandRiskClassification(
            risk: .approvalRequired,
            authorizationRequirement: .freshApprovalRequired,
            reasons: ["SSH 命令语义无法可靠解析，必须重新本机认证"],
            ruleID: "ssh.unknown.fresh-approval"
        )
    }

    private func combine(
        _ lhs: SSHCommandRiskClassification,
        _ rhs: SSHCommandRiskClassification
    ) -> SSHCommandRiskClassification {
        let requirement = AuthorizationRequirement.max(
            lhs.authorizationRequirement,
            rhs.authorizationRequirement
        )
        let risk: OperationRisk
        switch requirement {
        case .none:
            risk = .silent
        case .reusableApproval, .freshApprovalRequired:
            risk = .approvalRequired
        case .denied:
            risk = .denied
        }
        return SSHCommandRiskClassification(
            risk: risk,
            authorizationRequirement: requirement,
            reasons: lhs.reasons + rhs.reasons,
            ruleID: requirement == rhs.authorizationRequirement ? rhs.ruleID : lhs.ruleID
        )
    }

    private func isReadOnly(executable: String, arguments: [String]) -> Bool {
        if Self.readOnlyCommands.contains(executable) {
            return true
        }
        guard executable == "docker", let subcommand = arguments.first else {
            return false
        }
        return subcommand == "ps" || subcommand == "inspect" || subcommand == "images"
    }

    private func isDestructive(executable: String, arguments: [String]) -> Bool {
        if executable == "rm" || executable == "shred" || executable.hasPrefix("mkfs")
            || executable == "wipefs" || executable == "fdisk" || executable == "parted"
            || executable == "reboot" || executable == "shutdown" || executable == "poweroff"
            || executable == "halt" || executable == "dd" || executable == "zpool"
            || executable == "mdadm" {
            return true
        }
        if executable == "find",
           arguments.contains(where: { $0 == "-delete" || $0 == "-exec" || $0 == "-execdir" }) {
            return true
        }
        if executable == "systemctl", arguments.contains(where: { $0 == "disable" || $0 == "mask" || $0 == "stop" }) {
            return true
        }
        if executable == "docker" {
            if arguments.first == "system" && arguments.dropFirst().first == "prune" {
                return true
            }
            if arguments.first == "volume" && arguments.dropFirst().first == "rm" {
                return true
            }
            if arguments.first == "rm" && arguments.contains("-f") {
                return true
            }
        }
        return false
    }

    private func denied(_ reason: String, ruleID: String) -> SSHCommandRiskClassification {
        SSHCommandRiskClassification(
            risk: .denied,
            authorizationRequirement: .denied,
            reasons: [reason],
            ruleID: ruleID
        )
    }

    private func containsForbiddenShellSyntax(_ command: String) -> Bool {
        if command.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) {
            return true
        }
        // These characters are rejected even when they could be represented
        // as a quoted argument. The legacy single-command API cannot
        // preserve argument boundaries, and allowing them here would make
        // policy say "approved" while the executor later fails closed.
        let disallowed = [";", "&&", "||", "|", ">", "<", "`", "$(", "${", "&", "'", "\"", "\\", "$"]
        if disallowed.contains(where: command.contains) {
            return true
        }
        return command.contains("*") || command.contains("?") || command.contains("[") || command.contains("]")
    }

    private static let readOnlyCommands: Set<String> = [
        "hostname", "uptime", "df", "du", "ps", "uname", "whoami", "id", "date", "free", "w", "last",
        "ls", "cat", "head", "tail", "grep", "stat", "find", "pwd", "printenv"
    ]

    private static let reversibleWriteCommands: Set<String> = [
        // Keep this allow-list deliberately small. Commands such as cp/mv can
        // overwrite existing data, while chmod/chown/ln/install/tee can
        // change security properties or replace an existing path. Without a
        // complete argument-aware proof they must take the unknown-command
        // fresh-approval path instead of reusing a five-minute lease.
        "mkdir", "touch"
    ]

    private static let shellExecutables: Set<String> = [
        "sh", "bash", "zsh", "fish", "ksh", "dash", "ash", "csh", "tcsh"
    ]
}
