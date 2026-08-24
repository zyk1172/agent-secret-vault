import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func silentSecretOperationUsesAgentExecutorWithoutApproval() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(fixture.ssh(command: "hostname"))

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 0)
    #expect(await fixture.executor.count == 1)
}

@Test func dangerousSecretOperationWaitsForApprovalAndResumesSameRequest() async throws {
    let fixture = try await OperationServiceFixture(approval: .allow)
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let statuses = await fixture.statusValues()
    #expect(statuses.map(\.approvalPending) == [true, false])
}

@Test func cancelledApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.cancelled, expected: .authorizationCancelled)
}

@Test func deniedApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.denied, expected: .authorizationDenied)
}

@Test func unavailableApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.unavailable, expected: .authorizationUnavailable)
}

private func expectApprovalFailure(
    _ mode: ApprovalMode,
    expected: SecretOperationError
) async throws {
    let fixture = try await OperationServiceFixture(approval: mode)
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))
        Issue.record("Expected \(expected), but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == expected)
    }
    #expect(await fixture.executor.count == 0)
}

@Test func approvalTimeoutDoesNotLaunchExecutor() async throws {
    let fixture = try await OperationServiceFixture(approval: .never, timeout: .milliseconds(20))
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))
        Issue.record("Expected authorization timeout, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .authorizationTimeout)
    }
    #expect(await fixture.executor.count == 0)
}

private enum ApprovalMode: Sendable {
    case allow
    case cancelled
    case denied
    case unavailable
    case never
}

private actor ApprovalRecorder: OperationApproving {
    let mode: ApprovalMode
    private(set) var count = 0

    init(mode: ApprovalMode) {
        self.mode = mode
    }

    func approve(summary _: String) async throws {
        count += 1
        switch mode {
        case .allow:
            return
        case .cancelled:
            throw OperationAuthorizationError.cancelled
        case .denied:
            throw OperationAuthorizationError.denied
        case .unavailable:
            throw OperationAuthorizationError.unavailable
        case .never:
            try await Task.sleep(for: .seconds(10))
        }
    }
}

private actor ExecutorRecorder: SecretOperationExecuting {
    private(set) var count = 0

    func execute(
        _: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        resolve _: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        count += 1
        return SecretOperationOutput(status: "COMPLETED", exitCode: 0, stdout: "hostname", stderr: "")
    }
}

private actor StatusRecorder {
    private(set) var values: [WorkbenchStatus] = []

    func append(_ value: WorkbenchStatus) {
        values.append(value)
    }
}

private struct DummyTextEncryptor: TextEncrypting {
    func encryptText(_: String, label _: String?, policy _: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private final class OperationServiceFixture: @unchecked Sendable {
    let root: URL
    let key: SymmetricKey
    let reference: SecretReference
    let service: VaultAppServices
    let approver: ApprovalRecorder
    let executor: ExecutorRecorder
    let statusRecorder: StatusRecorder

    init(
        approval: ApprovalMode = .allow,
        timeout: Duration = .seconds(1)
    ) async throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-operation-service-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let store = FileRecordStore(baseDirectory: root)
        key = SymmetricKey(data: Data(repeating: 0x44, count: 32))
        reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
        let record = try VaultCipher().encrypt(
            Data("ASV_CANARY_OPERATION_SECRET".utf8),
            id: reference.id,
            version: 1,
            label: "QNAP credential",
            policy: .credential,
            allowedDestinations: ["qnap.local"],
            allowedProtocols: ["ssh"],
            masterKey: key
        )
        try await store.save(record)

        let statuses = StatusRecorder()
        statusRecorder = statuses
        approver = ApprovalRecorder(mode: approval)
        executor = ExecutorRecorder()
        service = VaultAppServices(
            textEncryptor: DummyTextEncryptor(),
            activeRoot: nil,
            recordResolver: VaultRecordResolver(recordStore: store),
            masterKey: key,
            operationApprover: approver,
            operationExecutor: executor,
            operationApprovalTimeout: timeout,
            statusObserver: { status in
                await statuses.append(status)
            }
        )
    }

    func ssh(command: String) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "qnap.local",
            port: 22,
            protocolType: .ssh,
            command: command,
            requestedEffects: [command == "hostname" ? "read-only" : "remote-write"],
            parameters: ["passwordRef": reference.description]
        )
    }

    func statusValues() async -> [WorkbenchStatus] {
        await statusRecorder.values
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}
