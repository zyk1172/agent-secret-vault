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

@Test func eligibleSecretOperationsReuseExecutionAuthorizationUntilExpiry() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 3_000)
    let clock = ServiceTestClock(start)
    let authorizationSession = AuthorizationSession(
        executionTTL: 300,
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        now: { clock.now }
    )
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))
    let firstExpiration = await authorizationSession.executionAuthorizationExpiresAt()

    clock.now = start.addingTimeInterval(299.999)
    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "systemctl restart app"))

    #expect(firstExpiration == start.addingTimeInterval(300))
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 2)
    let authorizationModes = await fixture.auditEntries().compactMap(\.authorizationMode)
    #expect(authorizationModes.contains(.freshLocalApproval))
    #expect(authorizationModes.contains(.executionWindowReuse))

    clock.now = start.addingTimeInterval(300)
    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))

    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 3)
    #expect(await authorizationSession.executionAuthorizationExpiresAt() == start.addingTimeInterval(600))
}

@Test func concurrentEligibleOperationsShareOneApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let outputs = try await withThrowingTaskGroup(of: SecretOperationOutput.self) { group in
        for command in ["reboot", "systemctl restart app", "docker restart api"] {
            group.addTask {
                try await fixture.service.performSecretOperation(
                    fixture.ssh(command: command)
                )
            }
        }

        var outputs: [SecretOperationOutput] = []
        for try await output in group {
            outputs.append(output)
        }
        return outputs
    }

    #expect(outputs.count == 3)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 3)
}

@Test func securityInvalidationCancelsPendingExecutionApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.approver.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }

    #expect(await fixture.approver.count == 1)
    await fixture.service.invalidateSecurityState()

    #expect(await operation.value == .authorizationCancelled)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization() == false)
    #expect(await fixture.executor.count == 0)
}

@Test func executionWindowDoesNotBypassDeniedPolicyOrExactSensitiveApproval() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))

    do {
        _ = try await fixture.service.performSecretOperation(
            fixture.ssh(command: "reboot").replacingDestination("8.8.8.8")
        )
        Issue.record("Expected an unbound public destination to remain denied.")
    } catch let error as SecretOperationError {
        #expect(error == .operationDenied)
    }

    _ = try await fixture.service.performSecretOperation(
        SecretOperationDescriptor(
            actionType: .revealPlaintext,
            secretReferences: [fixture.reference]
        )
    )

    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
}

@Test func policyIsReevaluatedAfterApprovalBeforeExecution() async throws {
    let gate = ApprovalGate()
    let fixture = try await OperationServiceFixture(
        approval: .gated,
        approvalGate: gate
    )
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.approver.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await fixture.approver.count == 1)

    try await fixture.replaceWithReadOnlyRecord()
    await gate.release()

    #expect(await operation.value == .operationDenied)
    #expect(await fixture.executor.count == 0)
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
    case delayed
    case gated
    case cancelled
    case denied
    case unavailable
    case never
}

private actor ApprovalRecorder: OperationApproving {
    let mode: ApprovalMode
    let gate: ApprovalGate?
    private(set) var count = 0

    init(mode: ApprovalMode, gate: ApprovalGate? = nil) {
        self.mode = mode
        self.gate = gate
    }

    func approve(summary _: String) async throws {
        count += 1
        switch mode {
        case .allow:
            return
        case .delayed:
            try await Task.sleep(for: .milliseconds(100))
        case .gated:
            await gate?.waitForRelease()
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

private actor ApprovalGate {
    private var released = false
    private var continuation: CheckedContinuation<Void, Never>?

    func waitForRelease() async {
        guard !released else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func release() {
        released = true
        continuation?.resume()
        continuation = nil
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

private actor AuditRecorder {
    private(set) var entries: [AgentAutomationAuditEntry] = []

    func append(_ entry: AgentAutomationAuditEntry) {
        entries.append(entry)
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
    let authorizationSession: AuthorizationSession
    let store: FileRecordStore
    let auditRecorder: AuditRecorder

    init(
        approval: ApprovalMode = .allow,
        timeout: Duration = .seconds(1),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        approvalGate: ApprovalGate? = nil,
        auditRecorder: AuditRecorder? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) async throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-operation-service-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let store = FileRecordStore(baseDirectory: root)
        self.store = store
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
        approver = ApprovalRecorder(mode: approval, gate: approvalGate)
        executor = ExecutorRecorder()
        self.authorizationSession = authorizationSession
        let auditRecorder = auditRecorder ?? AuditRecorder()
        self.auditRecorder = auditRecorder
        service = VaultAppServices(
            textEncryptor: DummyTextEncryptor(),
            activeRoot: nil,
            recordResolver: VaultRecordResolver(recordStore: store),
            masterKey: key,
            authorizationSession: authorizationSession,
            operationApprover: approver,
            operationExecutor: executor,
            operationApprovalTimeout: timeout,
            now: now,
            statusObserver: { status in
                await statuses.append(status)
            },
            auditObserver: { entry in
                await auditRecorder.append(entry)
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

    func auditEntries() async -> [AgentAutomationAuditEntry] {
        await auditRecorder.entries
    }

    func replaceWithReadOnlyRecord() async throws {
        let record = try VaultCipher().encrypt(
            Data("ASV_CANARY_OPERATION_SECRET_V2".utf8),
            id: reference.id,
            version: 2,
            label: "QNAP credential",
            policy: .read,
            allowedDestinations: ["qnap.local"],
            allowedProtocols: ["ssh"],
            masterKey: key
        )
        try await store.save(record)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private final class ServiceTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date

    init(_ now: Date) {
        storedNow = now
    }

    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }
}
