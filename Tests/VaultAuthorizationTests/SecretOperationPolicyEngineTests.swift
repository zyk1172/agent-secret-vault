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

    #expect(engine().evaluate(descriptor, metadata: [metadata]).risk == .approvalRequired)
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

@Test func boundHTTPReadIsSilentButWriteNeedsApproval() throws {
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

    #expect(engine().evaluate(read, metadata: [metadata]).risk == .silent)
    #expect(engine().evaluate(write, metadata: [metadata]).risk == .approvalRequired)
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
