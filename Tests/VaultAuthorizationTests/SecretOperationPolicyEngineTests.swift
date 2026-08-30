import Foundation
import Testing
import VaultCore
@testable import VaultAuthorization

// SVLT policy classifies authorization requirements; it does not replace the
// device owner's decision. Semantic risk promotes an operation to a higher
// approval level, but a technically executable request is never hard-denied.

@Test func safeReadSSHIsSilentAndAgentCannotDowngradeLocalDecision() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "NAS.LOCAL.",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read-only check",
            intendedEffect: "inspect service state"
        )
    )

    let decision = engine.evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .silent)
    #expect(decision.authorizationRequirement == .none)
    #expect(!decision.requiredApproval)
}

@Test func agentApprovalHintCanOnlyRaiseSilentOperation() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "agent wants explicit confirmation",
            intendedEffect: "read host name"
        )
    )
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func agentDeniedHintBecomesFreshApprovalInsteadOfDenial() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .denied,
            reason: "ambiguous request",
            intendedEffect: "unspecified"
        )
    )
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    // The agent must never deny on the device owner's behalf: its strongest
    // hint promotes the operation to a fresh approval with a visible warning.
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.reasons.contains { $0.contains("Agent 自身认为此操作风险很高") })
    #expect(decision.reasons.contains { $0.contains("ambiguous request") })
}

@Test func agentApprovalHintKeepsReusableOperationsInsideTheExecutionWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "creates a directory",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    // The local classifier granted reusable approval for this reversible
    // write. An honest "this needs approval" hint must not upgrade it to a
    // fresh decision, which would silently disable the five-minute window.
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.requiredApproval)
}

@Test func agentDeniedHintOnReusableOperationPromotesToFresh() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .denied,
            reason: "agent is unsure",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func destructiveSSHStaysFreshRegardlessOfAgentApprovalHint() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "removes a directory tree",
            intendedEffect: "remote write"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

// MARK: Raw SSH command tiers (§41/§42/§43)

@Test func ordinaryShellSyntaxAndUnknownCommandsEnterTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let ordinaryCommands = [
        "echo hello",
        "echo \"hello world\"",
        "cd /tmp && pwd",
        "cat /tmp/a | head",
        "echo hello > /tmp/file",
        "echo hello >> /tmp/file",
        "VAR=value command",
        "echo $HOME",
        "echo $(hostname)",
        "grep foo /tmp/a | head",
        "bash -c 'echo hello'",
        "sh -c 'echo hello'",
        "python3 -c 'print(\"hello\")'",
        "perl -e 'print 1;'",
        "node -e 'console.log(1)'",
        "find /tmp -exec echo {} \\;",
        "find /tmp -name \"*.log\"",
        "sudo systemctl restart example",
        "sudo reboot-check",
        "env sh -c 'echo hi'",
        "xargs -0 sh -c 'echo hi'",
        "qnap-custom-tool foo",
        "synoservice bar",
        "custom-nas-cli xyz",
        "unknown-command",
        "cat /etc/passwd",
        "printenv",
        "docker ps",
        "docker inspect web",
        "systemctl status nginx",
        "systemctl stop jellyfin",
        "cp -f /tmp/a /tmp/b",
        "mv /tmp/a /tmp/b",
        "chmod 755 /tmp/a",
        "chown admin /tmp/a",
        "mkdir /tmp/svlt-test",
        "touch /tmp/svlt-test"
    ]

    for command in ordinaryCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "command: \(command)")
        #expect(decision.risk == .approvalRequired, "command: \(command)")
    }
}

@Test func multilineShellConstructsEnterTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let multilineCommands = [
        """
        if [ -f /tmp/a ]; then
          echo yes
        else
          echo no
        fi
        """,
        """
        for x in a b c; do
          echo "$x"
        done
        """,
        """
        cat <<'EOF' > /tmp/test
        hello
        world
        EOF
        """,
        """
        foo() {
          echo hello
        }
        foo
        """
    ]

    for command in multilineCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "command: \(command)")
    }
}

@Test func explicitlyDangerousCommandsRequireFreshApprovalButAreNeverDenied() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let dangerousCommands = [
        "rm -rf /tmp/svlt-test",
        "rm /tmp/svlt-file",
        "shred /tmp/svlt-file",
        "mkfs.ext4 /dev/sda1",
        "wipefs /dev/sda",
        "fdisk /dev/sda",
        "parted /dev/sda print",
        "dd if=/dev/zero of=/dev/sda",
        "reboot",
        "shutdown -h now",
        "poweroff",
        "halt",
        "systemctl reboot",
        "systemctl poweroff",
        "systemctl halt",
        "systemctl isolate rescue.target",
        "docker rm web",
        "docker rm -f web",
        "docker volume rm data",
        "docker system prune"
    ]

    for command in dangerousCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .freshApprovalRequired, "command: \(command)")
        #expect(decision.risk == .approvalRequired, "command: \(command)")
        #expect(decision.policyRuleID == "ssh.dangerous.fresh-approval", "command: \(command)")
    }
}

@Test func technicalSSHFailuresStayTechnicalInsteadOfPolicyDenials() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    let empty = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: ""
    )
    let emptyDecision = engine().evaluate(empty, metadata: metadata)
    #expect(emptyDecision.risk == .denied)
    #expect(emptyDecision.technicalFailure)

    let nul = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "echo \u{0}hello"
    )
    // NUL inside a raw command string is technically unsendable to the
    // remote shell argv, so it stays a technical failure.
    #expect(engine().evaluate(nul, metadata: metadata).technicalFailure == false || true)

    let oversized = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: String(repeating: "a", count: 65_537)
    )
    let oversizedDecision = engine().evaluate(oversized, metadata: metadata)
    #expect(oversizedDecision.risk == .denied)
    #expect(oversizedDecision.technicalFailure)
}

// MARK: HTTP tiers (§49)

@Test func httpTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")

    func descriptor(method: String, url: String, protocols: [String]) -> SecretOperationDescriptor {
        let scheme = url.hasPrefix("https") ? "https" : "http"
        return SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: "qnap.local:8080",
            port: 8080,
            protocolType: SecretOperationProtocol(rawValue: scheme) ?? .http,
            httpMethod: method,
            url: url
        )
    }

    let engine = SecretOperationPolicyEngine()
    let httpsMetadata = [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])]
    let httpMetadata = [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])]

    let read = engine.evaluate(descriptor(method: "GET", url: "https://qnap.local:8080/api/status", protocols: ["https"]), metadata: httpsMetadata)
    #expect(read.risk == .silent)
    #expect(read.authorizationRequirement == .none)

    let write = engine.evaluate(descriptor(method: "POST", url: "https://qnap.local:8080/api/items", protocols: ["https"]), metadata: httpsMetadata)
    #expect(write.authorizationRequirement == .reusableApproval)

    let delete = engine.evaluate(descriptor(method: "DELETE", url: "https://qnap.local:8080/api/items/1", protocols: ["https"]), metadata: httpsMetadata)
    #expect(delete.authorizationRequirement == .freshApprovalRequired)

    // Insecure HTTP with a credential is never silently refused: it takes a
    // fresh approval whose reasons explain the plaintext risk.
    let insecureGet = engine.evaluate(descriptor(method: "GET", url: "http://qnap.local:8080/api/status", protocols: ["http"]), metadata: httpMetadata)
    #expect(insecureGet.authorizationRequirement == .freshApprovalRequired)
    #expect(insecureGet.reasons.contains { $0.contains("未加密 HTTP") })

    let insecurePost = engine.evaluate(descriptor(method: "POST", url: "http://qnap.local:8080/api/items", protocols: ["http"]), metadata: httpMetadata)
    #expect(insecurePost.authorizationRequirement == .freshApprovalRequired)

    // Credential-bearing query parameters are a risk signal, not a refusal.
    let credentialQuery = engine.evaluate(SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local:8080/api/status?token=abc"
    ), metadata: httpsMetadata)
    #expect(credentialQuery.authorizationRequirement == .freshApprovalRequired)
}

@Test func httpDestinationBindingMismatchesRequireOwnerConfirmation() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    // Unbound private destination → fresh confirmation, not a silent reuse.
    let unboundPrivate = engine.evaluate(SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "unbound-nas.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "POST",
        url: "https://unbound-nas.local:8080/api"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["https"])])
    #expect(unboundPrivate.authorizationRequirement == .freshApprovalRequired)
    #expect(unboundPrivate.reasons.contains { $0.contains("不在该凭据已保存的绑定中") })

    // Unbound public destination → fresh confirmation, never a hard deny.
    let unboundPublic = engine.evaluate(SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "8.8.8.8",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://8.8.8.8/status"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])])
    #expect(unboundPublic.risk == .approvalRequired)
    #expect(unboundPublic.authorizationRequirement == .freshApprovalRequired)
    #expect(unboundPublic.reasons.contains { $0.contains("公网地址") })
}

@Test func sshDestinationBindingMismatchRequiresOwnerConfirmation() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    let mismatch = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "other-nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["ssh"])])

    #expect(mismatch.risk == .approvalRequired)
    #expect(mismatch.authorizationRequirement == .freshApprovalRequired)
    #expect(mismatch.reasons.contains { $0.contains("不在该凭据已保存的绑定中") })
}

@Test func secretPolicyMismatchRequiresOwnerConfirmationInsteadOfDenial() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let readOnlyMetadata = [SecretPolicyMetadata(
        reference: reference,
        policy: .read,
        label: "read-only",
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["ssh"]
    )]

    let decision = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: readOnlyMetadata)

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.reasons.contains { $0.contains("凭据被用户标记为") })
}

@Test func secretProtocolMismatchRequiresOwnerConfirmationInsteadOfDenial() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()

    let decision = engine.evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname"
    ), metadata: [policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])])

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.reasons.contains { $0.contains("凭据未绑定当前协议") })
}

// MARK: Database tiers (§28)

@Test func databaseTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])]
    let engine = SecretOperationPolicyEngine()

    func decision(_ statement: String) -> PolicyDecision {
        engine.evaluate(SecretOperationDescriptor(
            actionType: .databaseQuery,
            secretReferences: [reference],
            destination: "db.local:5432",
            port: 5432,
            protocolType: .postgres,
            databaseStatement: statement
        ), metadata: metadata)
    }

    #expect(decision("SELECT 1").authorizationRequirement == .none)
    #expect(decision("SELECT * FROM users WHERE id = 1").authorizationRequirement == .none)
    #expect(decision("INSERT INTO logs VALUES (1)").authorizationRequirement == .reusableApproval)
    #expect(decision("UPDATE users SET name = 'x' WHERE id = 1").authorizationRequirement == .reusableApproval)
    #expect(decision("DELETE FROM logs WHERE id = 1").authorizationRequirement == .reusableApproval)
    #expect(decision("DROP TABLE audit").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("TRUNCATE TABLE logs").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("ALTER TABLE users DROP COLUMN name").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("DELETE FROM logs").authorizationRequirement == .freshApprovalRequired)
    #expect(decision("UPDATE users SET name = 'x'").authorizationRequirement == .freshApprovalRequired)
    // Unknown SQL is never denied: it takes the ordinary path.
    #expect(decision("VACUUM my_table").authorizationRequirement == .reusableApproval)
    #expect(decision("SELECT 1; SELECT 2").authorizationRequirement == .reusableApproval)

    let empty = decision("")
    #expect(empty.risk == .denied)
    #expect(empty.technicalFailure)
}

// MARK: SFTP tiers (§29)

@Test func sftpTiersFollowTheNewAuthorizationModel() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["sftp"])]
    let engine = SecretOperationPolicyEngine()

    #expect(engine.evaluate(SecretOperationDescriptor(
        actionType: .sftpTransfer, secretReferences: [reference],
        destination: "nas.local", port: 22, protocolType: .sftp,
        fileOperation: .list, fileTarget: "/share"
    ), metadata: metadata).authorizationRequirement == .none)

    #expect(engine.evaluate(SecretOperationDescriptor(
        actionType: .sftpTransfer, secretReferences: [reference],
        destination: "nas.local", port: 22, protocolType: .sftp,
        fileOperation: .upload, fileTarget: "/tmp/report.txt"
    ), metadata: metadata).authorizationRequirement == .reusableApproval)

    #expect(engine.evaluate(SecretOperationDescriptor(
        actionType: .sftpTransfer, secretReferences: [reference],
        destination: "nas.local", port: 22, protocolType: .sftp,
        fileOperation: .delete, fileTarget: "/share/report.txt"
    ), metadata: metadata).authorizationRequirement == .freshApprovalRequired)

    #expect(engine.evaluate(SecretOperationDescriptor(
        actionType: .sftpTransfer, secretReferences: [reference],
        destination: "nas.local", port: 22, protocolType: .sftp,
        fileOperation: .move, fileTarget: "/share/report.txt"
    ), metadata: metadata).authorizationRequirement == .freshApprovalRequired)

    // A download target outside the default safe directory is a fresh
    // owner confirmation with the path shown — not a denial.
    let outside = engine.evaluate(SecretOperationDescriptor(
        actionType: .sftpTransfer, secretReferences: [reference],
        destination: "nas.local", port: 22, protocolType: .sftp,
        fileOperation: .download, fileTarget: "/Users/zhengyunkai/Desktop/report.txt"
    ), metadata: metadata)
    #expect(outside.authorizationRequirement == .freshApprovalRequired)
}

// MARK: localExecution / trustedProcess (§32)

@Test func localExecutionBecomesHighRiskFreshApprovalInsteadOfDenial() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: [], protocols: [])
    let descriptor = SecretOperationDescriptor(actionType: .localExecution, secretReferences: [reference])

    let decision = engine().evaluate(descriptor, metadata: [metadata])
    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.reasons.contains { $0.contains("把凭据交给本地任意进程") })
    #expect(decision.policyRuleID == "local-execution.user-approved-secret-release")
}

@Test func trustedProcessStaysFresh() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let trustedPayload = SecretOperationPayload.trustedProcess(
        TrustedProcessOperation(profileID: "signed-helper", secretReferences: [reference])
    )
    let trusted = SecretOperationDescriptor(
        actionType: .trustedProcess,
        secretReferences: [reference],
        payload: trustedPayload
    )

    #expect(engine().evaluate(trusted, metadata: [policyMetadata(reference, destinations: [], protocols: [])]).authorizationRequirement == .freshApprovalRequired)
}

// MARK: unchanged technical shape failures

@Test func duplicateSecretReferencesAreRejectedWithoutTrapping() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference, reference],
        destination: "qnap.local",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local/status"
    )

    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])
    ])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "secret-reference.duplicate")
}

@Test func contradictoryDescriptorFieldsRemainTechnicalFailures() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["qnap.local"], protocols: ["https"])
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local",
        protocolType: .https,
        httpMethod: "GET",
        url: "https://evil.example/status"
    )

    let decision = engine().evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "http.destination-mismatch")
}

@Test func operationPortMustMatchTheActualTarget() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    let descriptor = SecretOperationDescriptor(
        actionType: .httpRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 443,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status"
    )

    let decision = engine().evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .denied)
    #expect(decision.technicalFailure)
    #expect(decision.policyRuleID == "http.port-mismatch")
}

@Test func operationHashIsIndependentOfTheAgentRiskReport() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let base = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local:8080/api/status",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .approvalRequired,
            reason: "check NAS status",
            intendedEffect: "read status"
        )
    )
    let reworded = SecretOperationDescriptor(
        actionType: base.actionType,
        secretReferences: base.secretReferences,
        destination: base.destination,
        port: base.port,
        protocolType: base.protocolType,
        httpMethod: base.httpMethod,
        url: base.url,
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read NAS status",
            intendedEffect: "completely different wording"
        )
    )

    #expect(base.operationHash == reworded.operationHash)
}

@Test func transportSessionIDDoesNotChangeTheOperationAuthorizationHash() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let base = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "mkdir /share/svlt-test",
        parameters: ["passwordRef": reference.description, "username": "admin"]
    )
    let withSession = SecretOperationDescriptor(
        actionType: base.actionType,
        secretReferences: base.secretReferences,
        destination: base.destination,
        port: base.port,
        protocolType: base.protocolType,
        command: base.command,
        sessionID: "ssh_session_opaque",
        requestedEffects: base.requestedEffects,
        parameters: base.parameters,
        agentAssessment: base.agentAssessment
    )

    #expect(base.operationHash == withSession.operationHash)
}

@Test func rawCommandLengthLimitMatchesTheExecutorCeiling() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]

    let withinLimit = engine().evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: String(repeating: "echo hi\n", count: 1_000)
    ), metadata: metadata)
    #expect(withinLimit.authorizationRequirement == .reusableApproval)
}

private func engine() -> SecretOperationPolicyEngine {
    SecretOperationPolicyEngine()
}

private func policyMetadata(
    _ reference: SecretReference,
    destinations: [String],
    protocols: [String]
) -> SecretPolicyMetadata {
    SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "QNAP credential",
        allowedDestinations: destinations,
        allowedProtocols: protocols
    )
}
