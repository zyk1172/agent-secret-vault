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

@Test func executionApprovalExplainsItsScopedReuseWindow() async throws {
    let fixture = try await OperationServiceFixture(approval: .allow)
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))

    let summary = await fixture.approver.summaries.first ?? ""
    #expect(summary.contains("复用最多 300 秒"))
    #expect(summary.contains("不会授权其他凭据、目标或协议"))
}

@Test func exportReusesScopedAuthorizationAndFreshKeyAcrossLeafFiles() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 7_000)
    let clock = ServiceTestClock(start)
    let monotonicStart: UInt64 = 90_000_000_000
    clock.monotonicNow = monotonicStart
    let authorizationSession = AuthorizationSession(
        executionTTL: 300,
        monotonicNow: { clock.monotonicNow },
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        usesMasterKeyProvider: true,
        now: { clock.now }
    )
    defer { fixture.remove() }

    let context = RevealContext(
        reason: "Export resolved local file",
        template: "Token: {{0}}",
        ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
    )
    let firstDestination = fixture.exportDirectory.appendingPathComponent("first.md")
    let secondDestination = fixture.exportDirectory.appendingPathComponent("second.md")

    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-exporter")
    ) {
        try await fixture.service.exportResolvedText(
            references: [fixture.reference.description],
            context: context,
            destinationPath: firstDestination.path
        )
    }
    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-exporter")
    ) {
        try await fixture.service.exportResolvedText(
            references: [fixture.reference.description],
            context: context,
            destinationPath: secondDestination.path
        )
    }

    #expect(await fixture.approver.count == 1)
    let keyProvider = try #require(fixture.keyProvider)
    #expect(await keyProvider.freshCount == 1)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(
        for: fixture.exportScope(principal: "agent-exporter")
    ))
    #expect(try String(contentsOf: firstDestination, encoding: .utf8).contains("ASV_CANARY_OPERATION_SECRET"))
    #expect(try String(contentsOf: secondDestination, encoding: .utf8).contains("ASV_CANARY_OPERATION_SECRET"))
}

@Test func failedScopedOperationClearsItsLeaseBeforeTheNextAttempt() async throws {
    let fixture = try await OperationServiceFixture(executorStatus: "FAILED")
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))

    #expect(output.status == "FAILED")
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
    #expect((await fixture.auditEntries()).last?.result == "FAILED")
}

@Test func eligibleSecretOperationsReuseExecutionAuthorizationUntilExpiry() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 3_000)
    let clock = ServiceTestClock(start)
    let monotonicStart: UInt64 = 20_000_000_000
    clock.monotonicNow = monotonicStart
    let authorizationSession = AuthorizationSession(
        executionTTL: 300,
        monotonicNow: { clock.monotonicNow },
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        now: { clock.now }
    )
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    let scope = fixture.executionScope()
    let firstExpiration = await authorizationSession.executionAuthorizationExpiresAt(for: scope)

    clock.now = start.addingTimeInterval(299.999)
    clock.monotonicNow = monotonicStart + 299_999_000_000
    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "touch /share/svlt-test"))

    #expect(firstExpiration == start.addingTimeInterval(300))
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 2)
    let authorizationModes = await fixture.auditEntries().compactMap(\.authorizationMode)
    #expect(authorizationModes.contains(.freshLocalApproval))
    #expect(authorizationModes.contains(.executionWindowReuse))

    clock.now = start.addingTimeInterval(300)
    clock.monotonicNow = monotonicStart + 300_000_000_000
    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test-2"))

    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 3)
    #expect(await authorizationSession.executionAuthorizationExpiresAt(for: scope) == start.addingTimeInterval(600))
}

@Test func destructiveSSHRequiresFreshApprovalWithoutExtendingReusableLease() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 4_000)
    let clock = ServiceTestClock(start)
    let monotonicStart: UInt64 = 40_000_000_000
    clock.monotonicNow = monotonicStart
    let authorizationSession = AuthorizationSession(
        executionTTL: 300,
        monotonicNow: { clock.monotonicNow },
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        now: { clock.now }
    )
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    let scope = fixture.executionScope()
    let originalExpiry = await authorizationSession.executionAuthorizationExpiresAt(for: scope)

    clock.now = start.addingTimeInterval(100)
    clock.monotonicNow = monotonicStart + 100_000_000_000
    let output = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "rm -rf /share/svlt-test")
    )

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.executionAuthorizationExpiresAt(for: scope) == originalExpiry)
}

@Test func concurrentEligibleOperationsShareOneApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let outputs = try await withThrowingTaskGroup(of: SecretOperationOutput.self) { group in
        // Only commands classified as reusableApproval should share the
        // scoped single-flight approval. Broad copy/move/permission commands
        // intentionally take the fresh-approval path.
        for command in ["mkdir /share/svlt-a", "touch /share/svlt-b", "mkdir /share/svlt-c"] {
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

@Test func concurrentOperationsWithDisabledExecutionWindowDoNotShareApproval() async throws {
    let fixture = try await OperationServiceFixture(
        approval: .delayed,
        authorizationSession: AuthorizationSession(executionTTL: 0)
    )
    defer { fixture.remove() }

    let outputs = try await withThrowingTaskGroup(of: SecretOperationOutput.self) { group in
        for command in ["mkdir /share/svlt-a", "touch /share/svlt-b", "cp /share/svlt-a /share/svlt-c"] {
            group.addTask {
                try await fixture.service.performSecretOperation(fixture.ssh(command: command))
            }
        }

        var outputs: [SecretOperationOutput] = []
        for try await output in group {
            outputs.append(output)
        }
        return outputs
    }

    #expect(outputs.count == 3)
    #expect(await fixture.approver.count == 3)
    #expect(await fixture.executor.count == 3)
}

@Test func executionAuthorizationIsBoundToTheCallingAgentPrincipal() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-peer-one")
    ) {
        try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    }
    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-peer-two")
    ) {
        try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    }

    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
}

@Test func unavailableExecutorIsRejectedBeforeApprovalAndCannotPrimeLease() async throws {
    let fixture = try await OperationServiceFixture(
        executorCapability: .unavailable
    )
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected unavailable executor, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .actionExecutorUnavailable)
    }

    #expect(await fixture.approver.count == 0)
    #expect(await fixture.executor.count == 0)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
}

@Test func legacyUnavailableExecutorStatusIsNotAuditedAsCompleted() async throws {
    let fixture = try await OperationServiceFixture(
        executorStatus: "ACTION_EXECUTOR_UNAVAILABLE"
    )
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected unavailable executor, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .actionExecutorUnavailable)
    }

    let entries = await fixture.auditEntries()
    #expect(entries.last?.result == "不可用")
    #expect(entries.last?.authorizationMode == .freshLocalApproval)
}

@Test func securityInvalidationCancelsPendingExecutionApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
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
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
    #expect(await fixture.executor.count == 0)
}

@Test func executionWindowDoesNotBypassDeniedPolicyOrExactSensitiveApproval() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))

    do {
        _ = try await fixture.service.performSecretOperation(
            fixture.ssh(command: "mkdir /share/svlt-test").replacingDestination("8.8.8.8")
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
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
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
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
}

@Test func securityInvalidationCancelsAnInFlightSecretExecutor() async throws {
    let fixture = try await OperationServiceFixture(blockExecution: true)
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.executor.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await fixture.executor.count == 1)

    await fixture.service.invalidateSecurityState()

    #expect(await operation.value == .authorizationCancelled)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
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
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
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
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
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
    private(set) var summaries: [String] = []

    init(mode: ApprovalMode, gate: ApprovalGate? = nil) {
        self.mode = mode
        self.gate = gate
    }

    func approve(summary: String) async throws {
        count += 1
        summaries.append(summary)
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
    let capability: SecretOperationExecutionCapability
    let outputStatus: String
    let blockExecution: Bool
    private(set) var count = 0

    init(
        capability: SecretOperationExecutionCapability = .supported,
        outputStatus: String = "COMPLETED",
        blockExecution: Bool = false
    ) {
        self.capability = capability
        self.outputStatus = outputStatus
        self.blockExecution = blockExecution
    }

    nonisolated func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        capability
    }

    func execute(
        _: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        resolve _: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        count += 1
        if blockExecution {
            try await Task.sleep(for: .seconds(10))
        }
        return SecretOperationOutput(status: outputStatus, exitCode: 0, stdout: "hostname", stderr: "")
    }
}

private actor ScopedKeyProviderRecorder {
    private let key: SymmetricKey
    private(set) var masterCount = 0
    private(set) var freshCount = 0

    init(key: SymmetricKey) {
        self.key = key
    }

    func masterKey() -> SymmetricKey {
        masterCount += 1
        return key
    }

    func freshMasterKey() -> SymmetricKey {
        freshCount += 1
        return key
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
    let exportDirectory: URL
    let keyProvider: ScopedKeyProviderRecorder?

    init(
        approval: ApprovalMode = .allow,
        timeout: Duration = .seconds(1),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        approvalGate: ApprovalGate? = nil,
        auditRecorder: AuditRecorder? = nil,
        executorCapability: SecretOperationExecutionCapability = .supported,
        executorStatus: String = "COMPLETED",
        blockExecution: Bool = false,
        usesMasterKeyProvider: Bool = false,
        now: @escaping @Sendable () -> Date = Date.init
    ) async throws {
        root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("svlt-operation-service-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        exportDirectory = root.appendingPathComponent("Exports", isDirectory: true)
        try FileManager.default.createDirectory(
            at: exportDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
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

        let keyProvider = usesMasterKeyProvider ? ScopedKeyProviderRecorder(key: key) : nil
        self.keyProvider = keyProvider
        let masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
        let freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
        if let keyProvider {
            masterKeyProvider = { _, _ in await keyProvider.masterKey() }
            freshMasterKeyProvider = { _, _ in await keyProvider.freshMasterKey() }
        } else {
            masterKeyProvider = nil
            freshMasterKeyProvider = nil
        }

        let statuses = StatusRecorder()
        statusRecorder = statuses
        approver = ApprovalRecorder(mode: approval, gate: approvalGate)
        executor = ExecutorRecorder(
            capability: executorCapability,
            outputStatus: executorStatus,
            blockExecution: blockExecution
        )
        self.authorizationSession = authorizationSession
        let auditRecorder = auditRecorder ?? AuditRecorder()
        self.auditRecorder = auditRecorder
        service = VaultAppServices(
            textEncryptor: DummyTextEncryptor(),
            activeRoot: nil,
            recordResolver: VaultRecordResolver(recordStore: store),
            masterKey: keyProvider == nil ? key : nil,
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
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
            },
            exportDirectory: exportDirectory
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
            parameters: ["passwordRef": reference.description, "username": "admin"]
        )
    }

    func statusValues() async -> [WorkbenchStatus] {
        await statusRecorder.values
    }

    func auditEntries() async -> [AgentAutomationAuditEntry] {
        await auditRecorder.entries
    }

    func executionScope(
        principal: String = AuditSource.agent.rawValue,
        generation: UInt64 = 0
    ) -> ExecutionAuthorizationScope {
        ExecutionAuthorizationScope(
            principal: principal,
            secretReferenceIDs: [reference.description],
            normalizedDestination: "qnap.local",
            port: 22,
            username: "admin",
            protocolType: SecretOperationProtocol.ssh.rawValue,
            actionFamily: SecretOperationAction.sshCommand.rawValue,
            generation: generation
        )
    }

    func exportScope(
        principal: String = AuditSource.agent.rawValue,
        generation: UInt64 = 0
    ) -> ExecutionAuthorizationScope {
        ExecutionAuthorizationScope(
            principal: principal,
            secretReferenceIDs: [reference.description],
            normalizedDestination: exportDirectory.standardizedFileURL.path,
            port: nil,
            protocolType: SecretOperationProtocol.file.rawValue,
            actionFamily: SecretOperationAction.exportPlaintext.rawValue,
            generation: generation
        )
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
    private var storedMonotonicNow: UInt64 = 0

    init(_ now: Date) {
        storedNow = now
    }

    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }

    var monotonicNow: UInt64 {
        get { lock.withLock { storedMonotonicNow } }
        set { lock.withLock { storedMonotonicNow = newValue } }
    }
}
