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
        // the smoke test proves Tcl reached argument validation without
        // launching SSH or contacting a network host.
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
    #expect(result.exitCode == 123)
    #expect(!output.contains("can't read \"argv\""))
    #expect(!output.contains("couldn't read file"))
}

@Test func sshExpectTransportReportsInvalidHexBeforeArgumentValidation() async throws {
    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/usr/bin/expect",
            arguments: ["-c", LocalSecretOperationExecutor.expectSSHScript()]
        ),
        stdin: Data("GG\n".utf8),
        timeout: .seconds(2),
        outputLimitBytes: 16_384
    )

    #expect(result.exitCode == 122)
}

@Test func sshExpectTransportPreservesControlPathSpaces() async throws {
    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/usr/bin/expect",
            arguments: ["-c", LocalSecretOperationExecutor.expectSSHScript()]
        ),
        stdin: LocalSecretOperationExecutor.expectSSHInput(
            host: "127.0.0.1",
            port: 1,
            command: "printf 'SVLT_SSH_CONTROL_PATH_OK\\n'",
            controlPath: "/private/tmp/SVLT Application Support/s-socket",
            username: "tester",
            password: "ASV_CANARY_CONTROL_PATH",
            timeoutSeconds: 1
        ),
        timeout: .seconds(2),
        outputLimitBytes: 16_384
    )

    let output = String(decoding: result.stdout + result.stderr, as: UTF8.self)
    // Port 1 is intentionally disposable: the SSH client should reach the
    // connection attempt and fail with its normal transport status, not fail
    // while OpenSSH parses a ControlPath containing spaces.
    #expect(result.exitCode == 255)
    #expect(!output.contains("keyword controlpath extra arguments"))
    #expect(!output.contains("spawn id"))
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
    #expect(output.stage == .remoteCommand)
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
    #expect(output.stage == .timeout)
    #expect(await runner.timeout == .milliseconds(1200))
}

@Test func sshExecutorReportsAuthenticationFailureWithoutRetryingTheSecret() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = CapturingProcessRunner(
        result: ProcessResult(exitCode: 126, stdout: Data(), stderr: Data("Permission denied".utf8))
    )
    let executor = LocalSecretOperationExecutor(processRunner: runner)

    let output = try await executor.execute(
        sshDescriptor(reference: reference),
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_AUTH_SECRET".utf8) }
    )

    #expect(output.status == "AUTH_FAILED")
    #expect(output.stage == .authentication)
    #expect(output.exitCode == 126)
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

@Test func sshBatchUsesOneAuthenticatedTransportAndIndependentResults() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let password = Data("ASV_CANARY_BATCH_PASSWORD".utf8)
    let runner = BatchProcessRunner(
        firstResult: ProcessResult(exitCode: 0, stdout: Data("nas\n".utf8), stderr: Data()),
        commandResults: [
            ProcessResult(exitCode: 0, stdout: Data("zyk\n".utf8), stderr: Data()),
            ProcessResult(exitCode: 0, stdout: Data("/share\n".utf8), stderr: Data()),
            ProcessResult(exitCode: 0, stdout: Data("Filesystem\n".utf8), stderr: Data())
        ]
    )
    let resolveCount = AsyncCount()
    let executor = LocalSecretOperationExecutor(processRunner: runner)
    let batch = SSHCommandBatch(commands: [
        SSHCommandSpec(executable: "whoami"),
        SSHCommandSpec(executable: "pwd"),
        SSHCommandSpec(executable: "df", arguments: ["-h", "/share/external/DEV3303_1"])
    ])
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        sshCommandBatch: batch,
        parameters: ["passwordRef": reference.description, "username": "admin"]
    )

    let output = try await executor.execute(
        descriptor,
        metadata: [],
        resolve: { _ in
            await resolveCount.increment()
            return password
        }
    )

    #expect(output.status == "COMPLETED")
    #expect(output.results?.map(\.status) == ["COMPLETED", "COMPLETED", "COMPLETED"])
    #expect(output.results?.map(\.index) == [0, 1, 2])
    #expect(output.sessionID?.hasPrefix("ssh_session_") == true)
    #expect(await resolveCount.value == 1)

    let invocations = await runner.invocations
    #expect(invocations.filter { $0.executable == "/usr/bin/expect" }.count == 1)
    #expect(invocations.filter { $0.executable == "/usr/bin/ssh" && $0.arguments.contains("check") }.count == 3)
    // The first channel is opened by the Expect-backed authentication call;
    // subsequent channels use direct ControlMaster requests.
    #expect(invocations.filter { $0.executable == "/usr/bin/ssh" && !$0.arguments.contains("check") }.count == 2)
    #expect(!invocations.flatMap(\.arguments).contains("ASV_CANARY_BATCH_PASSWORD"))

    let directCommands = invocations
        .filter { $0.executable == "/usr/bin/ssh" && !$0.arguments.contains("check") }
        .compactMap(\.arguments.last)
    #expect(directCommands == [
        try SSHRemoteCommandEncoder.encode(SSHCommandSpec(executable: "pwd")),
        try SSHRemoteCommandEncoder.encode(SSHCommandSpec(executable: "df", arguments: ["-h", "/share/external/DEV3303_1"]))
    ])
}

@Test func sshBatchStopsAfterFirstFailureAndMarksRemainingCommandsNotExecuted() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = BatchProcessRunner(
        firstResult: ProcessResult(exitCode: 0, stdout: Data("ok\n".utf8), stderr: Data()),
        commandResults: [
            ProcessResult(exitCode: 1, stdout: Data(), stderr: Data("remote failed".utf8))
        ]
    )
    let executor = LocalSecretOperationExecutor(processRunner: runner)
    let output = try await executor.execute(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            sshCommandBatch: SSHCommandBatch(commands: [
                SSHCommandSpec(executable: "pwd"),
                SSHCommandSpec(executable: "false"),
                SSHCommandSpec(executable: "hostname")
            ]),
            parameters: ["passwordRef": reference.description, "username": "admin"]
        ),
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_BATCH_PASSWORD".utf8) }
    )

    #expect(output.status == "PARTIAL_FAILED")
    #expect(output.failedIndex == 1)
    #expect(output.results?.map(\.status) == ["COMPLETED", "FAILED", "NOT_EXECUTED"])
    #expect(output.results?[1].stage == .remoteCommand)
    let invocations = await runner.invocations
    #expect(invocations.filter { $0.executable == "/usr/bin/ssh" && $0.arguments.contains("check") }.count == 2)
    // The first command is the Expect-backed authenticated channel and the
    // failing second command is the only direct channel that should run.
    #expect(invocations.filter { $0.executable == "/usr/bin/ssh" && !$0.arguments.contains("check") }.count == 1)
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
        if self.invocation == nil {
            self.invocation = invocation
            self.stdin = stdin
            self.timeout = timeout
        }
        if invocation.arguments.contains("check") {
            return ProcessResult(exitCode: 0, stdout: Data(), stderr: Data())
        }
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

private actor BatchProcessRunner: ProcessRunning {
    private let firstResult: ProcessResult
    private var commandResults: [ProcessResult]
    private(set) var invocations: [ProcessInvocation] = []

    init(firstResult: ProcessResult, commandResults: [ProcessResult]) {
        self.firstResult = firstResult
        self.commandResults = commandResults
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin _: Data,
        timeout _: Duration,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        invocations.append(invocation)
        if invocation.executable == "/usr/bin/expect" {
            return firstResult
        }
        if invocation.arguments.contains("check") {
            return ProcessResult(exitCode: 0, stdout: Data(), stderr: Data())
        }
        guard !commandResults.isEmpty else {
            return ProcessResult(exitCode: 99, stdout: Data(), stderr: Data("unexpected command".utf8))
        }
        return commandResults.removeFirst()
    }
}

private actor AsyncCount {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}
