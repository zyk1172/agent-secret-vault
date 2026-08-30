import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import VaultService

private struct SummaryTextEncryptor: TextEncrypting {
    func encryptText(_: String, label _: String?, policy _: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private func makeService() -> VaultAppServices {
    VaultAppServices(textEncryptor: SummaryTextEncryptor(), activeRoot: nil)
}

private func batchMetadata(_ reference: SecretReference) -> [SecretPolicyMetadata] {
    [SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "NAS 凭据",
        allowedDestinations: ["192.168.2.240"],
        allowedProtocols: ["ssh"]
    )]
}

@Test func destructiveSSHBatchSummaryShowsTheActualCommandsAndHighestRequirement() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [
            SSHCommandSpec(executable: "whoami"),
            SSHCommandSpec(executable: "mkdir", arguments: ["/share/test"]),
            SSHCommandSpec(executable: "rm", arguments: ["-rf", "/share/test"]),
            SSHCommandSpec(executable: "docker", arguments: ["system", "prune"])
        ])
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))
    #expect(decision.authorizationRequirement == .freshApprovalRequired)

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    // The device owner must see what a destructive batch will run; the
    // single-command fallback text would hide the actual operations.
    #expect(!summary.contains("未提供命令"))
    #expect(summary.contains("SSH 批处理（4 条）"))
    #expect(summary.contains("whoami"))
    #expect(summary.contains("rm"))
    #expect(summary.contains("-rf"))
    #expect(summary.contains("/share/test"))
    #expect(summary.contains("批处理最高授权级别：必须重新本机认证"))
    #expect(summary.contains("192.168.2.240"))
    #expect(!summary.contains("secret://"))
}

@Test func sshBatchSummaryBoundsDisplayedCommandsAndArguments() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let longArgument = "/share/" + String(repeating: "a", count: 300)
    var commands = (0..<7).map { index in
        SSHCommandSpec(executable: "touch", arguments: ["/tmp/svlt-\(index)"])
    }
    commands[0] = SSHCommandSpec(
        executable: "rm",
        arguments: ["-rf", longArgument, "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: commands)
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    #expect(summary.contains("SSH 批处理（7 条）"))
    #expect(summary.contains("其余 2 条命令未在摘要展开"))
    #expect(summary.contains("还有 3 个参数"))
    // The long path must be truncated, and the batch detail stays bounded so
    // a hostile batch cannot flood the approval prompt (1_600-byte detail
    // plus the fixed prompt scaffolding around it).
    #expect(summary.contains("…"))
    #expect(!summary.contains(longArgument))
    #expect(summary.utf8.count <= 2_400)
    // Control characters must never reach the approval prompt.
    #expect(!summary.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F })
}

@Test func sshBatchSummaryNeverIncludesCredentialLabelsOrReferencesFromArguments() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "192.168.2.240",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [
            SSHCommandSpec(executable: "hostname"),
            SSHCommandSpec(executable: "df", arguments: ["-h", "/share"])
        ])
    )
    let decision = SecretOperationPolicyEngine().evaluate(descriptor, metadata: batchMetadata(reference))

    let summary = await makeService().approvalSummary(
        descriptor: descriptor,
        metadata: batchMetadata(reference),
        decision: decision
    )

    // A read-only batch takes the plain prompt, and the summary must not
    // echo secret:// references from anywhere in the descriptor. The
    // credential label itself is intended, user-owned display text.
    #expect(summary.contains("SSH 批处理（2 条）"))
    #expect(summary.contains("hostname"))
    #expect(summary.contains("df"))
    #expect(!summary.contains("secret://"))
    #expect(summary.contains("凭据：NAS 凭据"))
}
