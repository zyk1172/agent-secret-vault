import Foundation
import Testing
import VaultCore
@testable import VaultExecution

@Test func sshExecutorKeepsSecretOutOfProcessArgumentsAndRedactsOutput() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let password = Data("ASV_CANARY_AGENT_PASSWORD".utf8)
    let runner = CapturingProcessRunner(
        result: ProcessResult(
            exitCode: 0,
            stdout: Data("connected ASV_CANARY_AGENT_PASSWORD".utf8),
            stderr: Data("warning ASV_CANARY_AGENT_PASSWORD".utf8)
        )
    )
    let executor = LocalSecretOperationExecutor(
        processRunner: runner,
        timeout: .seconds(5)
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        parameters: [
            "passwordRef": reference.description,
            "username": "admin"
        ]
    )

    let output = try await executor.execute(
        descriptor,
        metadata: [],
        resolve: { _ in password }
    )

    let invocation = await runner.invocation
    let stdin = await runner.stdin
    #expect(invocation != nil)
    #expect(!invocation!.arguments.joined(separator: " ").contains("ASV_CANARY_AGENT_PASSWORD"))
    #expect(stdin.range(of: password) != nil)
    #expect(output.stdout == "connected [REDACTED_SECRET]")
    #expect(output.stderr == "warning [REDACTED_SECRET]")
    #expect(output.redacted)
}

private actor CapturingProcessRunner: ProcessRunning {
    let result: ProcessResult
    private(set) var invocation: ProcessInvocation?
    private(set) var stdin = Data()

    init(result: ProcessResult) {
        self.result = result
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout _: Duration,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        self.invocation = invocation
        self.stdin = stdin
        return result
    }
}
