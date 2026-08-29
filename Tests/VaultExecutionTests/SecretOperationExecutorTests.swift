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
    #expect(invocation!.arguments == ["-c", LocalSecretOperationExecutor.expectSSHScript()])
    #expect(!stdin.isEmpty)
    #expect(stdin.range(of: password) == nil)
    #expect(output.stdout == "connected [REDACTED_SECRET]")
    #expect(output.stderr == "warning [REDACTED_SECRET]")
    #expect(output.redacted)
}

@Test func sshExpectTransportReadsFramedStdinWithoutArgv() async throws {
    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/usr/bin/expect",
            arguments: ["-c", LocalSecretOperationExecutor.expectSSHScript()]
        ),
        // An invalid port exits after every framed field has been decoded, so
        // the smoke test never launches SSH or contacts a network host.
        stdin: LocalSecretOperationExecutor.expectSSHInput(
            host: "127.0.0.1",
            port: 0,
            command: "hostname",
            username: "tester",
            password: "ASV_CANARY_EXPECT_SMOKE",
            timeoutSeconds: 1
        ),
        timeout: .seconds(2),
        outputLimitBytes: 16_384
    )

    let output = String(decoding: result.stdout + result.stderr, as: UTF8.self)
    #expect(result.exitCode == 125)
    #expect(!output.contains("can't read \"argv\""))
    #expect(!output.contains("couldn't read file"))
}

@Test func sshExecutorReportsNonzeroExitAsFailed() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = CapturingProcessRunner(
        result: ProcessResult(exitCode: 2, stdout: Data("remote failed".utf8), stderr: Data())
    )
    let executor = LocalSecretOperationExecutor(processRunner: runner)
    let output = try await executor.execute(
        sshDescriptor(reference: reference),
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_EXIT_SECRET".utf8) }
    )

    #expect(output.status == "FAILED")
    #expect(output.exitCode == 2)
}

@Test func sshExecutorReportsProcessTimeoutAndHonorsDescriptorTimeout() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = TimeoutProcessRunner()
    let executor = LocalSecretOperationExecutor(processRunner: runner, timeout: .seconds(30))
    let descriptor = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "admin",
        "timeoutMs": "1200"
    ])

    let output = try await executor.execute(
        descriptor,
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_TIMEOUT_SECRET".utf8) }
    )

    #expect(output.status == "TIMED_OUT")
    #expect(await runner.timeout == .milliseconds(1200))
}

@Test func sshExecutorRejectsSecretUsernameAndInvalidTimeout() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let executor = LocalSecretOperationExecutor(processRunner: CapturingProcessRunner(
        result: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data())
    ))

    let usernameReference = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "usernameRef": reference.description
    ])
    await #expect(throws: SecretOperationExecutionError.invalidParameter) {
        _ = try await executor.execute(usernameReference, metadata: [], resolve: { _ in Data("unused".utf8) })
    }

    let optionLikeUsername = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "-oProxyCommand=echo",
    ])
    await #expect(throws: SecretOperationExecutionError.invalidParameter) {
        _ = try await executor.execute(optionLikeUsername, metadata: [], resolve: { _ in Data("unused".utf8) })
    }

    let invalidTimeout = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "admin",
        "timeoutMs": "30001"
    ])
    await #expect(throws: SecretOperationExecutionError.invalidParameter) {
        _ = try await executor.execute(invalidTimeout, metadata: [], resolve: { _ in Data("unused".utf8) })
    }
}

private func sshDescriptor(
    reference: SecretReference,
    parameters: [String: String]? = nil
) -> SecretOperationDescriptor {
    SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        parameters: parameters ?? [
            "passwordRef": reference.description,
            "username": "admin"
        ]
    )
}

private actor CapturingProcessRunner: ProcessRunning {
    let result: ProcessResult
    private(set) var invocation: ProcessInvocation?
    private(set) var stdin = Data()
    private(set) var timeout: Duration?

    init(result: ProcessResult) {
        self.result = result
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        self.invocation = invocation
        self.stdin = stdin
        self.timeout = timeout
        return result
    }
}

private actor TimeoutProcessRunner: ProcessRunning {
    private(set) var timeout: Duration?

    func run(
        _: ProcessInvocation,
        stdin _: Data,
        timeout: Duration,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        self.timeout = timeout
        throw ProcessRunError.timedOut
    }
}
