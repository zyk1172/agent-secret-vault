import Foundation
import Testing
import VaultCore
@testable import VaultAuthorization

@Test func boundReadOnlySSHIsSilentAndAgentCannotDowngradeLocalDecision() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let engine = SecretOperationPolicyEngine()
    let metadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "NAS.LOCAL.",
        port: 22,
        protocolType: .ssh,
        command: "docker ps",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read-only check",
            intendedEffect: "inspect service state"
        )
    )

    let decision = engine.evaluate(descriptor, metadata: [metadata])

    #expect(decision.risk == .silent)
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

@Test func agentApprovalHintCannotDestroyTheReusableExecutionWindow() throws {
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
    #expect(!decision.requiresFreshApprovalOnFirstUse)
}

@Test func serviceAndContainerLifecycleWritesEnterTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let reusableCommands = [
        "systemctl start jellyfin",
        "systemctl restart jellyfin",
        "systemctl reload nginx",
        "docker start web",
        "docker restart web",
        "docker stop web",
        "docker pause web",
        "docker unpause web"
    ]

    for command in reusableCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .reusableApproval, "command: \(command)")
        #expect(decision.policyRuleID == "ssh.ordinary-write.reusable-approval", "command: \(command)")
    }
}

@Test func destructiveAndOverwritingFormsStayFreshAroundTheReusableWindow() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let freshCommands = [
        "systemctl stop jellyfin",
        "systemctl disable jellyfin",
        "systemctl mask jellyfin",
        "docker rm web",
        "docker rm -f web",
        "docker volume rm data",
        "docker system prune",
        "cp -f /tmp/a /etc/passwd",
        "mv /tmp/a /etc/passwd",
        "chmod 000 /etc/passwd",
        "chown root /etc/passwd",
        "qnap-tool restart service"
    ]

    for command in freshCommands {
        let decision = engine().evaluate(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: command
        ), metadata: metadata)
        #expect(decision.authorizationRequirement == .freshApprovalRequired, "command: \(command)")
    }
}

@Test func operationHashIsIndependentOfTheAgentRiskReport() throws {    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
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

    // Two byte-identical operations must share one lease even when the
    // Agent rewords its free-text assessment between calls. The policy
    // engine re-evaluates the risk hint on every request, so the exact
    // operation fingerprint must not depend on it.
    #expect(base.operationHash == reworded.operationHash)
}

@Test func deniedAgentHintRemainsDenied() throws {
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

    #expect(engine().evaluate(descriptor, metadata: [metadata]).risk == .denied)
}

@Test func boundHTTPReadIsSilentButInsecureSecretUseRequiresFirstApproval() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    let read = SecretOperationDescriptor(
        actionType: .httpRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status"
    )
    let write = SecretOperationDescriptor(
        actionType: .httpRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "POST",
        url: "http://qnap.local:8080/api/restart"
    )

    let readDecision = engine().evaluate(read, metadata: [metadata])
    #expect(readDecision.risk == .approvalRequired)
    #expect(readDecision.authorizationRequirement == .reusableApproval)
    #expect(readDecision.requiresFreshApprovalOnFirstUse)
    #expect(engine().evaluate(write, metadata: [metadata]).risk == .approvalRequired)
}

@Test func insecureHTTPDeleteCannotBeDowngradedToReusableApproval() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "DELETE",
        url: "http://qnap.local:8080/api/items/123"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    ])

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(!decision.requiresFreshApprovalOnFirstUse)
}

@Test func insecureHTTPWithoutAnExplicitSavedProfileIsDenied() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: [])
    ])

    #expect(decision.risk == .denied)
    #expect(decision.policyRuleID == "http.insecure-transport.denied")
}

@Test func loopbackHTTPProfileIsExplicitAndNarrowlyBound() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "localhost:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://localhost:8080/api/status"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["localhost:8080"], protocols: ["http-loopback"])
    ])

    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.requiresFreshApprovalOnFirstUse)
}

@Test func insecureHTTPProfileAllowsNonCredentialQueryParameters() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status?limit=10"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    ])

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .reusableApproval)
    #expect(decision.requiresFreshApprovalOnFirstUse)
}

@Test func insecureHTTPProfileCannotWidenFromOnePortToAnother() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8081",
        port: 8081,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8081/api/status"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["qnap.local:8080"], protocols: ["http"])
    ])

    #expect(decision.risk == .denied)
    #expect(decision.policyRuleID == "http.insecure-transport.denied")
}

@Test func insecureHTTPAbsoluteProfileWithoutPortStaysOnDefaultPort() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local:8080",
        port: 8080,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://qnap.local:8080/api/status"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["http://qnap.local"], protocols: ["http"])
    ])

    #expect(decision.risk == .denied)
    #expect(decision.policyRuleID == "http.insecure-transport.denied")
}

@Test func HTTPOriginNormalizationSeparatesRequestPathsFromProfileOrigins() {
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "http://qnap.local:8080/api/status",
        defaultPort: 8080,
        allowURLPath: true
    ) == "http://qnap.local:8080")
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "http://qnap.local:8080/api/status",
        defaultPort: 8080
    ) == nil)
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "qnap.local:8080",
        expectedScheme: "http",
        requireExplicitPort: true
    ) == "http://qnap.local:8080")
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "qnap.local",
        expectedScheme: "http",
        defaultPort: 8080,
        requireExplicitPort: true
    ) == nil)
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "http://qnap.local/api/status",
        expectedScheme: "http",
        requireExplicitPort: true
    ) == nil)
    #expect(SecretOperationDescriptor.normalizeHTTPOrigin(
        "http://qnap.local",
        expectedScheme: "http",
        defaultPort: 8080,
        requireExplicitPort: true
    ) == "http://qnap.local:80")
}

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
    #expect(decision.policyRuleID == "secret-reference.duplicate")
}

@Test func trustedProcessIsDistinctFromPermanentlyDeniedGenericShell() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let trustedPayload = SecretOperationPayload.trustedProcess(
        TrustedProcessOperation(profileID: "signed-helper", secretReferences: [reference])
    )
    let trusted = SecretOperationDescriptor(
        actionType: .trustedProcess,
        secretReferences: [reference],
        payload: trustedPayload
    )
    let generic = SecretOperationDescriptor(actionType: .localExecution, secretReferences: [reference])

    #expect(engine().evaluate(trusted, metadata: [policyMetadata(reference, destinations: [], protocols: [])]).authorizationRequirement == .freshApprovalRequired)
    #expect(engine().evaluate(generic, metadata: [policyMetadata(reference, destinations: [], protocols: [])]).risk == .denied)
}

@Test func HTTPBindingCannotBeSpoofedByASeparateDestinationField() throws {
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
    #expect(decision.policyRuleID == "http.destination-mismatch")
}

@Test func unboundPublicDestinationIsDeniedAndNewPrivateDestinationNeedsApproval() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["10.0.0.2"], protocols: ["ssh"])
    let publicDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "8.8.8.8",
        protocolType: .ssh,
        command: "hostname"
    )
    let privateDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "10.0.0.3",
        protocolType: .ssh,
        command: "hostname"
    )

    #expect(engine().evaluate(publicDescriptor, metadata: [metadata]).risk == .denied)
    #expect(engine().evaluate(privateDescriptor, metadata: [metadata]).risk == .approvalRequired)

    let publicHostnameDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "example.com",
        protocolType: .ssh,
        command: "hostname"
    )
    let privateHostnameDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "qnap.local",
        protocolType: .ssh,
        command: "hostname"
    )

    #expect(engine().evaluate(publicHostnameDescriptor, metadata: [metadata]).risk == .denied)
    #expect(engine().evaluate(privateHostnameDescriptor, metadata: [metadata]).risk == .approvalRequired)
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
    #expect(decision.policyRuleID == "http.port-mismatch")
}

@Test func databaseAndSFTPReadRulesAreExplicit() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let dbMetadata = policyMetadata(reference, destinations: ["db.local:5432"], protocols: ["postgres"])
    let select = SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [reference],
        destination: "db.local:5432",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: "SELECT 1"
    )
    let multiStatement = SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [reference],
        destination: "db.local:5432",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: "SELECT 1; DROP TABLE audit"
    )
    let sftpMetadata = policyMetadata(reference, destinations: ["nas.local"], protocols: ["sftp"])
    let list = SecretOperationDescriptor(
        actionType: .sftpTransfer,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .sftp,
        fileOperation: .list,
        fileTarget: "/share"
    )
    let upload = SecretOperationDescriptor(
        actionType: .sftpTransfer,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .sftp,
        fileOperation: .upload,
        fileTarget: "/tmp/report.txt"
    )

    #expect(engine().evaluate(select, metadata: [dbMetadata]).risk == .silent)
    #expect(engine().evaluate(multiStatement, metadata: [dbMetadata]).risk == .denied)
    #expect(engine().evaluate(list, metadata: [sftpMetadata]).risk == .silent)
    #expect(engine().evaluate(upload, metadata: [sftpMetadata]).risk == .approvalRequired)
}

@Test func plaintextAndGenericExecutionAreNeverSilent() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let reveal = SecretOperationDescriptor(actionType: .revealPlaintext, secretReferences: [reference])
    let generic = SecretOperationDescriptor(actionType: .localExecution, secretReferences: [reference])
    let metadata = policyMetadata(reference, destinations: [], protocols: [])

    #expect(engine().evaluate(reveal, metadata: [metadata]).risk == .approvalRequired)
    #expect(engine().evaluate(generic, metadata: []).risk == .denied)
}

@Test func destructiveSSHRequiresFreshApprovalEvenWhenAgentClaimsReadOnly() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/svlt-test",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "maintenance",
            intendedEffect: "read-only"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.risk == .approvalRequired)
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "ssh.destructive.fresh-approval")
}

@Test func unknownSSHCommandRequiresFreshApprovalRatherThanSilentReuse() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        command: "custom-maintenance --check",
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "check",
            intendedEffect: "inspect status"
        )
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func structuredSSHBatchUsesHighestRequirementBeforeExecution() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let batch = SSHCommandBatch(commands: [
        SSHCommandSpec(executable: "whoami"),
        SSHCommandSpec(executable: "mkdir", arguments: ["/share/svlt-test"]),
        SSHCommandSpec(executable: "rm", arguments: ["-rf", "/share/svlt-test"]),
        SSHCommandSpec(executable: "df", arguments: ["-h"])
    ])
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: batch,
        requestedEffects: ["ssh-batch"]
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.authorizationRequirement == .freshApprovalRequired)
    #expect(decision.policyRuleID == "ssh.destructive.fresh-approval")
}

@Test func shellExecutablesAreDeniedEvenWhenStructured() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [
            SSHCommandSpec(executable: "/bin/sh", arguments: ["-c", "id"])
        ])
    )

    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )

    #expect(decision.risk == .denied)
    #expect(decision.authorizationRequirement == .denied)
}

@Test func commandWrappersAndBroadFilesystemMutationsRequireFreshApproval() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let commands = [
        SSHCommandSpec(executable: "cp", arguments: ["-f", "/tmp/a", "/etc/passwd"]),
        SSHCommandSpec(executable: "mv", arguments: ["/tmp/a", "/etc/passwd"]),
        SSHCommandSpec(executable: "chmod", arguments: ["000", "/etc/passwd"]),
        SSHCommandSpec(executable: "chown", arguments: ["root", "/etc/passwd"]),
        SSHCommandSpec(executable: "ln", arguments: ["-sf", "/tmp/a", "/etc/passwd"]),
        SSHCommandSpec(executable: "install", arguments: ["/tmp/a", "/etc/passwd"]),
        SSHCommandSpec(executable: "tee", arguments: ["/etc/passwd"])
    ]

    for command in commands {
        let descriptor = SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: [command])
        )
        let decision = engine().evaluate(descriptor, metadata: metadata)
        #expect(decision.authorizationRequirement == .freshApprovalRequired)
    }
}

@Test func indirectInterpreterWrappersAreDeniedEvenWhenStructured() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let commands = [
        SSHCommandSpec(executable: "/usr/bin/env", arguments: ["/bin/sh", "-c", "rm -rf /"]),
        SSHCommandSpec(executable: "sudo", arguments: ["--", "/bin/bash", "-lc", "id"]),
        SSHCommandSpec(executable: "doas", arguments: ["zsh", "-c", "id"]),
        SSHCommandSpec(executable: "command", arguments: ["sh", "-c", "id"]),
        SSHCommandSpec(executable: "xargs", arguments: ["-0", "sh", "-c", "id"])
    ]

    for command in commands {
        let descriptor = SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: [command])
        )
        let decision = engine().evaluate(descriptor, metadata: metadata)
        #expect(decision.risk == .denied)
        #expect(decision.authorizationRequirement == .denied)
        #expect(decision.policyRuleID == "ssh.indirect-interpreter.denied")
    }
}

@Test func directInterpreterCodeExecutionIsDeniedEvenWhenStructured() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let commands = [
        SSHCommandSpec(executable: "python3", arguments: ["-c", "import os; os.system('id')"]),
        SSHCommandSpec(executable: "/usr/bin/python", arguments: ["-c", "print(1)"]),
        SSHCommandSpec(executable: "perl", arguments: ["-e", "exec('id')"]),
        SSHCommandSpec(executable: "ruby", arguments: ["-e", "system('id')"]),
        SSHCommandSpec(executable: "node", arguments: ["-e", "require('child_process')"]),
        SSHCommandSpec(executable: "php", arguments: ["-r", "system('id');"])
    ]

    for command in commands {
        let descriptor = SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: [command])
        )
        let decision = engine().evaluate(descriptor, metadata: metadata)
        #expect(decision.risk == .denied)
        #expect(decision.authorizationRequirement == .denied)
        #expect(decision.policyRuleID == "ssh.interpreter-code.denied")
    }

    // Running a script file is not a code-string invocation; it keeps the
    // unknown-command fresh-approval path instead of being denied outright.
    let scriptFile = SSHCommandSpec(executable: "python3", arguments: ["/opt/tools/report.py"])
    let scriptDecision = engine().evaluate(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: SSHCommandBatch(commands: [scriptFile])
    ), metadata: metadata)
    #expect(scriptDecision.authorizationRequirement == .freshApprovalRequired)
    #expect(scriptDecision.policyRuleID == "ssh.unknown.fresh-approval")
}

@Test func findOnlyKnownReadPredicatesAreSilentButSideEffectsAndUnknownActionsAreNot() throws {
    let classifier = SSHCommandRiskClassifier()
    let readOnly = classifier.classify(spec: SSHCommandSpec(
        executable: "find",
        arguments: ["/share", "-type", "f", "-name", "*.log", "-print"]
    ))
    #expect(readOnly.authorizationRequirement == .none)

    for action in ["-delete", "-fprint", "-fprint0", "-fprintf", "-fls"] {
        let classification = classifier.classify(spec: SSHCommandSpec(
            executable: "find",
            arguments: ["/share", action, "/tmp/results"]
        ))
        #expect(classification.authorizationRequirement == .freshApprovalRequired)
    }

    let execute = classifier.classify(spec: SSHCommandSpec(
        executable: "find",
        arguments: ["/share", "-exec", "rm", "{}", ";"]
    ))
    #expect(execute.authorizationRequirement == .denied)

    let unknown = classifier.classify(spec: SSHCommandSpec(
        executable: "find",
        arguments: ["/share", "-unknown-action"]
    ))
    #expect(unknown.authorizationRequirement == .freshApprovalRequired)
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

@Test func typedHTTPPayloadCannotDisagreeWithLegacyMethodOrUsePublicDestination() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let payload = SecretOperationPayload.http(
        HTTPOperation(
            method: .get,
            auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference)
        )
    )
    let metadata = policyMetadata(reference, destinations: ["8.8.8.8"], protocols: ["http"])

    let conflicting = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "8.8.8.8",
        port: 80,
        protocolType: .http,
        httpMethod: "POST",
        url: "http://8.8.8.8/status",
        payload: payload,
        requestedEffects: ["remote-write"]
    )
    let publicTarget = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "8.8.8.8",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://8.8.8.8/status",
        payload: payload,
        requestedEffects: ["read-only"]
    )

    #expect(engine().evaluate(conflicting, metadata: [metadata]).risk == .denied)
    #expect(engine().evaluate(publicTarget, metadata: [metadata]).risk == .denied)
}

@Test func silentHTTPStillRequiresAnAllowedSecretPolicy() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "qnap.local",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://qnap.local/status"
    )
    let readOnlyMetadata = SecretPolicyMetadata(
        reference: reference,
        policy: .read,
        label: "read-only",
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["https"]
    )

    let decision = engine().evaluate(descriptor, metadata: [readOnlyMetadata])
    #expect(decision.risk == .denied)
    #expect(decision.policyRuleID == "secret-policy.effect-not-allowed")
}

@Test func typedDatabaseAndFilePayloadsMustBindAllCredentialReferences() throws {
    let password = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let username = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    let databasePayload = SecretOperationPayload.database(
        DatabaseOperation(
            engine: .postgres,
            database: "app",
            usernameReference: username,
            passwordReference: password,
            statement: "SELECT 1"
        )
    )
    let database = SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [password],
        destination: "db.local",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: "SELECT 1",
        payload: databasePayload,
        requestedEffects: ["database-read"]
    )

    let filePayload = SecretOperationPayload.fileTransfer(
        FileTransferOperation(
            protocolType: .sftp,
            operation: .list,
            remotePath: "/share",
            usernameReference: username,
            passwordReference: password
        )
    )
    let file = SecretOperationDescriptor(
        actionType: .sftpTransfer,
        secretReferences: [password, username],
        destination: "nas.local",
        port: 22,
        protocolType: .sftp,
        fileOperation: .list,
        payload: filePayload,
        requestedEffects: ["read-only"]
    )

    #expect(engine().evaluate(database, metadata: []).policyRuleID == "operation.payload.reference-mismatch")
    #expect(engine().evaluate(file, metadata: [
        policyMetadata(password, destinations: ["nas.local"], protocols: ["sftp"]),
        policyMetadata(username, destinations: ["nas.local"], protocols: ["sftp"])
    ]).risk == .silent)
}

@Test func unknownSingleLabelAndNumericDestinationsAreNotTrustedAsPrivate() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let metadata = policyMetadata(reference, destinations: ["printer", "2130706433"], protocols: ["http"])
    for destination in ["printer", "2130706433"] {
        let descriptor = SecretOperationDescriptor(
            actionType: .httpRequest,
            secretReferences: [reference],
            destination: destination,
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://\(destination)/status"
        )
        #expect(engine().evaluate(descriptor, metadata: [metadata]).risk == .denied)
    }
}

@Test func databaseSelectIntoIsNeverClassifiedAsReadOnly() throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let descriptor = SecretOperationDescriptor(
        actionType: .databaseQuery,
        secretReferences: [reference],
        destination: "db.local",
        port: 5432,
        protocolType: .postgres,
        databaseStatement: "SELECT id INTO copied_users FROM users"
    )
    let decision = engine().evaluate(descriptor, metadata: [
        policyMetadata(reference, destinations: ["db.local"], protocols: ["postgres"])
    ])
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
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
