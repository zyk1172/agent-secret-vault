import Foundation
import VaultCore

/// SVLT policy classifies authorization requirements; it does not replace the
/// device owner's decision.
///
/// The classifier answers exactly one question: "which authorization level
/// does this command need?" It never answers "is this command allowed?".
///
/// - Safe metadata reads (small explicit list) require no approval.
/// - Explicitly dangerous, hard-to-reverse commands always require a fresh
///   device-owner decision with the full command shown.
/// - Everything else — unknown commands, shell interpreters, interpreters,
///   pipelines, NAS CLIs — is an ordinary reversible write from the local
///   classifier's point of view and enters the scoped five-minute window.
///
/// There is deliberately no "unknown → denied" and no "unknown → fresh" tier:
/// an incomplete allowlist must never widen or restrict what the device owner
/// may decide. Hard failures are reserved for malformed input (empty, NUL,
/// oversized), which the policy engine surfaces as technical errors.
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
        let tokens = command.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let executable = tokens.first else {
            return technicalFailure("SSH 命令为空", ruleID: "ssh.command.missing")
        }
        return classifyTier(executable: executable, arguments: Array(tokens.dropFirst()))
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

        var highest = SSHCommandRiskClassification(
            risk: .silent,
            authorizationRequirement: .none,
            reasons: [],
            ruleID: "ssh.batch.read-only.silent"
        )
        for command in batch.commands {
            let current = classify(spec: command)
            highest = combine(highest, current)
            if highest.authorizationRequirement.severity >= AuthorizationRequirement.freshApprovalRequired.severity {
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
            return technicalFailure("SSH 命令参数无效", ruleID: "ssh.command.invalid")
        }

        let executable = URL(fileURLWithPath: spec.executable).lastPathComponent.lowercased()
        let arguments = spec.arguments.map { $0.lowercased() }
        return classifyTier(executable: executable, arguments: arguments)
    }

    private func classifyTier(executable: String, arguments: [String]) -> SSHCommandRiskClassification {
        if isDangerous(executable: executable, arguments: arguments) {
            return SSHCommandRiskClassification(
                risk: .approvalRequired,
                authorizationRequirement: .freshApprovalRequired,
                reasons: ["SSH 命令可能造成难以撤销的远程破坏，必须由设备所有者重新认证后执行"],
                ruleID: "ssh.dangerous.fresh-approval"
            )
        }

        if isSafeRead(executable: executable) {
            return SSHCommandRiskClassification(
                risk: .silent,
                authorizationRequirement: .none,
                reasons: ["SSH 命令被本地解析为明确的元数据只读操作"],
                ruleID: "ssh.read-only.silent"
            )
        }

        // Everything else — ordinary writes, unknown executables, shell
        // interpreters, interpreters, pipelines, NAS CLIs — is an ordinary
        // operation for the local classifier. The device owner approves the
        // first use, and the scoped five-minute window covers follow-ups.
        return SSHCommandRiskClassification(
            risk: .approvalRequired,
            authorizationRequirement: .reusableApproval,
            reasons: ["SSH 命令属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
            ruleID: "ssh.ordinary.reusable-approval"
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

    /// A small, explicit list of metadata reads that cannot mutate the remote
    /// host. Anything not on the list is NOT denied — it simply takes the
    /// ordinary approval path.
    private func isSafeRead(executable: String) -> Bool {
        Self.safeReadCommands.contains(executable)
    }

    /// A small, explicit list of locally provable destructive forms. These are
    /// never executed silently or on a reusable lease; the device owner sees
    /// the full command and re-authenticates for every use. They are NOT
    /// denied: approval executes them.
    private func isDangerous(executable: String, arguments: [String]) -> Bool {
        if Self.dangerousExecutables.contains(executable) {
            return true
        }
        if executable.hasPrefix("mkfs") {
            return true
        }
        if executable == "systemctl",
           let subcommand = arguments.first,
           Self.dangerousSystemctlSubcommands.contains(subcommand) {
            return true
        }
        if executable == "docker" {
            if arguments.first == "rm" {
                return true
            }
            if arguments.first == "volume", arguments.dropFirst().first == "rm" {
                return true
            }
            if arguments.first == "system", arguments.dropFirst().first == "prune" {
                return true
            }
        }
        return false
    }

    private func technicalFailure(_ reason: String, ruleID: String) -> SSHCommandRiskClassification {
        SSHCommandRiskClassification(
            risk: .denied,
            authorizationRequirement: .denied,
            reasons: [reason],
            ruleID: ruleID
        )
    }

    private static let safeReadCommands: Set<String> = [
        "hostname", "whoami", "pwd", "uname", "id", "date", "uptime", "df", "du", "stat", "ls"
    ]

    private static let dangerousExecutables: Set<String> = [
        "rm", "shred", "wipefs", "fdisk", "parted", "dd",
        "reboot", "shutdown", "poweroff", "halt", "zpool", "mdadm"
    ]

    private static let dangerousSystemctlSubcommands: Set<String> = [
        "reboot", "poweroff", "halt", "kexec", "isolate", "rescue", "emergency"
    ]
}
