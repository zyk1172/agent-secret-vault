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
        return classifyTier(rawCommand: ([spec.executable] + spec.arguments).joined(separator: " "))
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

    /// Shallow lexical detection for the fixed fresh rules only. It splits the
    /// raw command on whitespace and shell separators, normalizes each word to
    /// its basename (so `/bin/rm`, `'rm'`, and `rm` are recognized), and walks
    /// adjacent word pairs for subcommand forms. This is best-effort by
    /// design: an unmatched command stays on the ordinary path, and the scan
    /// can never deny anything.
    func matchFixedFreshRule(in rawCommand: String) -> String? {
        let separators = CharacterSet(charactersIn: " \t\n\r;&|'\"`()<>")
        let words = rawCommand
            .components(separatedBy: separators)
            .map { Self.basename($0) }
            .filter { !$0.isEmpty }
        guard !words.isEmpty else { return nil }

        for (index, word) in words.enumerated() {
            let next = index + 1 < words.count ? words[index + 1] : nil
            let next2 = index + 2 < words.count ? words[index + 2] : nil

            if Self.powerControlExecutables.contains(word) {
                return SSHFreshRules.powerControl
            }
            if word == "systemctl", let next, Self.dangerousSystemctlSubcommands.contains(next) {
                return SSHFreshRules.powerControl
            }
            if Self.filesystemDeleteExecutables.contains(word) {
                return SSHFreshRules.filesystemDelete
            }
            if word.hasPrefix("mkfs") || Self.blockDeviceExecutables.contains(word) {
                return SSHFreshRules.blockDeviceFilesystem
            }
            if word == "zpool", next == "destroy" {
                return SSHFreshRules.storageRaidDestruction
            }
            if word == "mdadm", let next, Self.destructiveMdadmFlags.contains(next) {
                return SSHFreshRules.storageRaidDestruction
            }
            if word == "docker", let next {
                if next == "rm" {
                    return SSHFreshRules.containerDestruction
                }
                if next == "volume", next2 == "rm" {
                    return SSHFreshRules.containerDestruction
                }
                if next == "system", next2 == "prune" {
                    return SSHFreshRules.containerDestruction
                }
            }
        }
        return nil
    }

    /// Strips surrounding quotes and any leading path so `/bin/rm`, `'rm'`, and
    /// `rm` all normalize to `rm`. Classification only — the raw command sent
    /// to SSH is never rewritten.
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

    private func technicalFailure(_ reason: String, ruleID: String) -> SSHCommandRiskClassification {
        SSHCommandRiskClassification(
            risk: .denied,
            authorizationRequirement: .denied,
            reasons: [reason],
            ruleID: ruleID
        )
    }
}
