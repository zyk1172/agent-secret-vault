import CryptoKit
import Foundation
import os
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

public protocol RevealSessionPresenting: Sendable {
    func present(sessionID: String, store: RevealSessionStore) async
}

public struct NoopRevealSessionPresenter: RevealSessionPresenting {
    public init() {}

    public func present(sessionID: String, store: RevealSessionStore) async {}
}

public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}

public enum VaultAppServicesOrphanScanError: Error, Equatable, Sendable {
    case scanUnavailable
}

public enum VaultAppServicesSavedReferencesError: Error, Equatable, Sendable {
    case listUnavailable
}

public enum VaultAppServicesExportError: Error, Equatable, Sendable {
    case invalidDestination
    case destinationNotAllowed
    case fileAlreadyExists
}

public struct AgentAutomationAuditEntry: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let occurredAt: Date
    public let action: String
    public let target: String
    public let referenceCount: Int
    public let result: String

    public init(
        id: UUID = UUID(),
        occurredAt: Date = Date(),
        action: String,
        target: String,
        referenceCount: Int,
        result: String
    ) {
        self.id = id
        self.occurredAt = occurredAt
        self.action = action
        self.target = target
        self.referenceCount = referenceCount
        self.result = result
    }
}

private struct AgentDecryptAuthorization: Sendable {
    let key: SymmetricKey
    let policy: SecretPolicy
    let destination: String?
    let expiresAt: Date
}

private enum CatalogMutationPhase: String {
    case inputValidation = "input-validation"
    case policy = "policy"
    case agentAuthorization = "agent-authorization"
    case snapshot = "snapshot"
    case model = "model"
    case identifierGeneration = "identifier-generation"
    case store = "store"
}

private enum CatalogWriteAccessState: Sendable {
    case pending
    case authenticating
    case approved
    case consumed
    case denied
    case expired
    case cancelled
}

private enum CatalogSecureInputState: Sendable {
    case awaitingInput
    case submitting
    /// The request has crossed the cancellation linearization point. No
    /// cancellation/expiry request can turn this committed write into a
    /// terminal cancellation after the store call begins.
    case committing
    case completed
    case failed
    case expired
    case cancelled
}

private enum CatalogSecureInputAbortReason: Equatable, Sendable {
    case cancelled
    case expired
}

private enum CatalogSecureInputAbortError: Error, Sendable {
    case cancelled
    case expired
}

/// Non-sensitive, sticky audit-channel health. This is deliberately kept
/// outside the encrypted event stream so the daemon can report an audit gap
/// without acquiring a vault or audit key. The record contains no paths,
/// payloads, references, or credentials.
private struct CatalogAuditHealthRecord: Codable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let lastFailureAt: Date?
    let gapDetected: Bool
    let lastSuccessfulSequence: UInt64
}

private final class CatalogWriteAccessContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?

    func store(_ continuation: CheckedContinuation<Void, Error>) {
        lock.lock()
        defer { lock.unlock() }
        self.continuation = continuation
    }

    func resume(throwing error: Error? = nil) {
        lock.lock()
        defer { lock.unlock() }
        guard let continuation else { return }
        self.continuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}

public actor VaultAppServices: WorkbenchServicing, AppControlServicing {
    private static let catalogMutationLogger = Logger(subsystem: "AgentSecretVault", category: "CatalogMutation")
    private let textEncryptor: any TextEncrypting
    private let activeRoot: URL?
    private let recordLister: (any RecordListing)?
    private let recordDeleter: (any RecordDeleting)?
    private let recordResolver: VaultRecordResolver?
    private let catalogDocumentStore: SensitiveCatalogDocumentStore?
    private let catalogSelectionStore: SecretCatalogSelectionStore?
    private let catalogSearchService: SecretCatalogEntrySearchService
    private let catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization
    private let catalogMutationPolicyEngine: CatalogMutationPolicyEngine
    private let masterKey: SymmetricKey?
    private let masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
    private let freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
    private let clearProtectedKeyState: (@Sendable () async -> Void)?
    private let isUnlockedProvider: (@Sendable () async -> Bool)
    private let revealSessionStore: RevealSessionStore
    private let revealSessionPresenter: any RevealSessionPresenting
    private let authorizationSession: AuthorizationSession
    private let operationPolicyEngine: SecretOperationPolicyEngine
    private let approvalTicketStore: ApprovalTicketStore
    private let operationApprover: any OperationApproving
    private let operationExecutor: any SecretOperationExecuting
    private let operationApprovalTimeout: Duration
    private let agentDecryptAuthorizationTTL: TimeInterval?
    private let credentialAuthorizationTTL: TimeInterval
    private let externalSendAuthorizationTTL: TimeInterval
    private let now: @Sendable () -> Date
    private let orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)?
    private let statusObserver: (@Sendable (WorkbenchStatus) async -> Void)?
    private let auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)?
    private let savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)?
    private let auditLog: EncryptedAuditLog?
    private let auditHealthURL: URL?
    private let exportDirectory: URL
    private let writeAccessNotifier: CatalogAgentWriteAccessNotifier
    private let secureInputNotifier: CatalogAgentSecureInputNotifier
    private var pluginConnectedAt: Date?
    private var agentDecryptAuthorizations: [String: AgentDecryptAuthorization] = [:]
    private var pendingCatalogDrafts: [String: SecretCatalogEntry] = [:]
    private var approvalPending = false
    private var pendingWriteAccessRequests: [UUID: CatalogAgentWriteAccessRequest] = [:]
    private var writeAccessContinuations: [UUID: CatalogWriteAccessContinuationBox] = [:]
    private var writeAccessStates: [UUID: CatalogWriteAccessState] = [:]
    /// The Agent creates the request context; the App later uses the same
    /// correlation/request IDs when it records the device-owner decision.
    private var pendingWriteAuditContexts: [UUID: AuditContext] = [:]
    private var auditAppendFailureAt: Date?
    private var auditAppendGapDetected = false
    private var lastSuccessfulAuditSequence: UInt64 = 0
    private var pendingSecureInputRequests: [UUID: CatalogAgentSecureInputRequest] = [:]
    private var secureInputStates: [UUID: CatalogSecureInputState] = [:]
    private var secureInputStatuses: [UUID: CatalogSecureInputStatus] = [:]
    private var secureInputTerminalAt: [UUID: Date] = [:]
    private var secureInputExpiryTasks: [UUID: Task<Void, Never>] = [:]
    private var secureInputAuditContexts: [UUID: AuditContext] = [:]
    /// Cancellation/expiry is latched while the one-shot authentication or
    /// store call is suspended. The request is not removed during submission;
    /// this prevents a late SecureField callback from committing after the
    /// App has asked the daemon to cancel it.
    private var secureInputAbortReasons: [UUID: CatalogSecureInputAbortReason] = [:]

    public init(
        textEncryptor: any TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        clearProtectedKeyState: (@Sendable () async -> Void)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = NoopRevealSessionPresenter(),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        operationPolicyEngine: SecretOperationPolicyEngine = SecretOperationPolicyEngine(),
        approvalTicketStore: ApprovalTicketStore = ApprovalTicketStore(),
        operationApprover: any OperationApproving = LocalOperationApprover(),
        operationExecutor: any SecretOperationExecuting = LocalSecretOperationExecutor(),
        operationApprovalTimeout: Duration = .seconds(30),
        agentDecryptAuthorizationTTL: TimeInterval? = nil,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init,
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        auditHealthURL: URL? = nil,
        exportDirectory: URL? = nil,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier = CatalogAgentWriteAccessNotifier(),
        secureInputNotifier: CatalogAgentSecureInputNotifier = CatalogAgentSecureInputNotifier()
    ) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
        self.recordLister = recordLister
        self.recordDeleter = recordDeleter
        self.recordResolver = recordResolver
        self.catalogDocumentStore = catalogDocumentStore
        self.catalogSelectionStore = catalogSelectionManifestURL.map(SecretCatalogSelectionStore.init(manifestURL:))
        self.catalogSearchService = SecretCatalogEntrySearchService()
        self.catalogAgentWriteAuthorization = catalogAgentWriteAuthorization ?? CatalogAgentWriteAuthorization(now: now)
        self.catalogMutationPolicyEngine = CatalogMutationPolicyEngine()
        self.masterKey = masterKey
        self.masterKeyProvider = masterKeyProvider
        self.freshMasterKeyProvider = freshMasterKeyProvider
        self.clearProtectedKeyState = clearProtectedKeyState
        self.isUnlockedProvider = isUnlockedProvider
        self.revealSessionStore = revealSessionStore
        self.revealSessionPresenter = revealSessionPresenter
        self.authorizationSession = authorizationSession
        self.operationPolicyEngine = operationPolicyEngine
        self.approvalTicketStore = approvalTicketStore
        self.operationApprover = operationApprover
        self.operationExecutor = operationExecutor
        self.operationApprovalTimeout = operationApprovalTimeout
        self.agentDecryptAuthorizationTTL = agentDecryptAuthorizationTTL
        self.credentialAuthorizationTTL = agentDecryptAuthorizationTTL ?? credentialAuthorizationTTL
        self.externalSendAuthorizationTTL = externalSendAuthorizationTTL
        self.now = now
        self.orphanScanObserver = orphanScanObserver
        self.statusObserver = statusObserver
        self.auditObserver = auditObserver
        self.savedReferencesObserver = savedReferencesObserver
        self.auditLog = auditLog
        self.auditHealthURL = auditHealthURL?.standardizedFileURL
        let persistedAuditHealth = Self.loadAuditHealth(from: auditHealthURL)
        self.auditAppendFailureAt = persistedAuditHealth?.lastFailureAt
        self.auditAppendGapDetected = persistedAuditHealth?.gapDetected ?? false
        self.lastSuccessfulAuditSequence = persistedAuditHealth?.lastSuccessfulSequence ?? 0
        self.exportDirectory = (exportDirectory ?? Self.defaultExportDirectory()).standardizedFileURL
        self.writeAccessNotifier = writeAccessNotifier
        self.secureInputNotifier = secureInputNotifier
    }

    public init(
        encryptSelection: any EncryptSelectionCoordinating & TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        clearProtectedKeyState: (@Sendable () async -> Void)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = NoopRevealSessionPresenter(),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        operationPolicyEngine: SecretOperationPolicyEngine = SecretOperationPolicyEngine(),
        approvalTicketStore: ApprovalTicketStore = ApprovalTicketStore(),
        operationApprover: any OperationApproving = LocalOperationApprover(),
        operationExecutor: any SecretOperationExecuting = LocalSecretOperationExecutor(),
        operationApprovalTimeout: Duration = .seconds(30),
        agentDecryptAuthorizationTTL: TimeInterval? = nil,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init,
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        auditHealthURL: URL? = nil,
        exportDirectory: URL? = nil,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier = CatalogAgentWriteAccessNotifier()
    ) {
        self.init(
            textEncryptor: encryptSelection,
            activeRoot: activeRoot,
            recordLister: recordLister,
            recordDeleter: recordDeleter,
            recordResolver: recordResolver,
            catalogDocumentStore: catalogDocumentStore,
            catalogSelectionManifestURL: catalogSelectionManifestURL,
            catalogAgentWriteAuthorization: catalogAgentWriteAuthorization,
            masterKey: masterKey,
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
            clearProtectedKeyState: clearProtectedKeyState,
            isUnlockedProvider: isUnlockedProvider,
            revealSessionStore: revealSessionStore,
            revealSessionPresenter: revealSessionPresenter,
            authorizationSession: authorizationSession,
            operationPolicyEngine: operationPolicyEngine,
            approvalTicketStore: approvalTicketStore,
            operationApprover: operationApprover,
            operationExecutor: operationExecutor,
            operationApprovalTimeout: operationApprovalTimeout,
            agentDecryptAuthorizationTTL: agentDecryptAuthorizationTTL,
            credentialAuthorizationTTL: credentialAuthorizationTTL,
            externalSendAuthorizationTTL: externalSendAuthorizationTTL,
            now: now,
            orphanScanObserver: orphanScanObserver,
            statusObserver: statusObserver,
            auditObserver: auditObserver,
            savedReferencesObserver: savedReferencesObserver,
            auditLog: auditLog,
            auditHealthURL: auditHealthURL,
            exportDirectory: exportDirectory,
            writeAccessNotifier: writeAccessNotifier
        )
    }

    public func recordPluginActivity() async {
        let wasConnected = isPluginConnected()
        pluginConnectedAt = now()
        if !wasConnected {
            // Connection/status bookkeeping is intentionally not an encrypted
            // Vault audit write. This keeps health checks disk/keychain-free.
            await statusObserver?(status())
        }
    }

    public func status() async -> WorkbenchStatus {
        WorkbenchStatus(
            locked: !(await isUnlockedProvider()),
            ipcAvailable: true,
            available: true,
            ready: true,
            approvalPending: approvalPending,
            activeKnowledgeBaseRoot: activeRoot?.path,
            pluginConnected: isPluginConnected()
        )
    }

    public func clearRevealSessions() async {
        await revealSessionStore.clearAll()
    }

    public func invalidateSecurityState() async {
        await authorizationSession.invalidate()
        for authorization in agentDecryptAuthorizations.values {
            var keyData = authorization.key.withUnsafeBytes { Data($0) }
            keyData.resetBytes(in: 0..<keyData.count)
        }
        agentDecryptAuthorizations.removeAll()
        await clearProtectedKeyState?()
        await statusObserver?(status())
    }

    public func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        let reference = try await textEncryptor.encryptText(
            plaintext,
            label: label,
            policy: policy
        )
        await notifySavedReferencesChanged()
        return reference.description
    }

    public func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    ) async throws -> String {
        let reference: SecretReference
        if let bindingEncryptor = textEncryptor as? any DestinationBindingTextEncrypting {
            reference = try await bindingEncryptor.encryptText(
                plaintext,
                label: label,
                policy: policy,
                allowedDestinations: allowedDestinations,
                allowedProtocols: allowedProtocols
            )
        } else {
            reference = try await textEncryptor.encryptText(
                plaintext,
                label: label,
                policy: policy
            )
        }
        await notifySavedReferencesChanged()
        return reference.description
    }

    public func performSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationOutput {
        if descriptor.actionType == .vaultStatus {
            let currentStatus = await status()
            return SecretOperationOutput(
                status: currentStatus.ready ? "READY" : "UNAVAILABLE"
            )
        }

        let metadata = try await policyMetadata(for: descriptor.secretReferences)
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        guard decision.risk != .denied else {
            await emitAudit(
                action: "智能体操作被本地策略拒绝",
                target: decision.policyRuleID,
                referenceCount: descriptor.secretReferences.count,
                result: "失败"
            )
            throw SecretOperationError.operationDenied
        }

        try await authorizeIfNeeded(
            descriptor,
            metadata: metadata,
            decision: decision
        )

        guard let recordResolver else {
            throw SecretOperationError.actionExecutionFailed
        }

        let key: SymmetricKey
        do {
            key = try await resolvedMasterKey(
                for: authorizationPolicy(for: metadata.map(\.policy)),
                reason: operationReason(for: descriptor),
                allowsAgentDecryptReuse: false,
                destination: decision.normalizedDestination
            )
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }

        do {
            let output = try await operationExecutor.execute(
                descriptor,
                metadata: metadata,
                resolve: { reference in
                    try await recordResolver.resolve(
                        reference: reference.description,
                        masterKey: key
                    )
                }
            )
            await emitAudit(
                action: "智能体专用操作",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: output.status
            )
            return output
        } catch SecretOperationExecutionError.redirectRequiresReview {
            throw SecretOperationError.redirectRequiresReview
        } catch SecretOperationExecutionError.outputQuarantined {
            throw SecretOperationError.outputQuarantined
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
    }

    public func deleteRecord(_ reference: String) async throws {
        let parsed = try SecretReference(reference)
        guard let recordResolver else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }
        guard let recordDeleter else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }

        let metadata = try await recordResolver.metadata(reference: reference)
        let descriptor = SecretOperationDescriptor(
            actionType: .deleteSecret,
            secretReferences: [parsed],
            requestedEffects: ["delete-record"]
        )
        let decision = operationPolicyEngine.evaluate(
            descriptor,
            metadata: [SecretPolicyMetadata(
                reference: parsed,
                policy: metadata.policy,
                label: metadata.label,
                allowedDestinations: metadata.allowedDestinations,
                allowedProtocols: metadata.allowedProtocols
            )]
        )
        guard decision.risk != .denied else {
            throw SecretOperationError.operationDenied
        }
        try await authorizeIfNeeded(
            descriptor,
            metadata: [SecretPolicyMetadata(
                reference: parsed,
                policy: metadata.policy,
                label: metadata.label,
                allowedDestinations: metadata.allowedDestinations,
                allowedProtocols: metadata.allowedProtocols
            )],
            decision: decision
        )
        try await recordDeleter.delete(id: parsed.id)
        await notifySavedReferencesChanged()
        await emitAudit(
            action: "删除本机加密记录",
            target: reference,
            referenceCount: 0,
            result: "已删除"
        )
    }

    public func authorizeHighRisk(reason: String) async throws {
        let descriptor = SecretOperationDescriptor(
            actionType: .changeAuthorizationRules,
            requestedEffects: ["explicit-local-authorization"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: [])
        try await authorizeIfNeeded(descriptor, metadata: [], decision: decision)
    }

    public func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata {
        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }
        let metadata = try await recordResolver.metadata(reference: reference)
        await emitAudit(
            action: "查看引用元数据",
            target: sanitizedReason(reference),
            referenceCount: 1,
            result: "成功"
        )
        return metadata
    }

    public func savedSecretReferences() async throws -> [SecretReferenceMetadata] {
        guard let recordLister, let recordResolver else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }

        let references = try await recordLister.recordIDs()
            .map { "secret://\($0)" }
            .asyncMap { try await recordResolver.metadata(reference: $0) }

        return references.sorted { lhs, rhs in
            if lhs.updatedAt == rhs.updatedAt {
                return lhs.reference < rhs.reference
            }
            return lhs.updatedAt > rhs.updatedAt
        }
    }

    public func searchSecrets(
        query: String,
        field: SecretCatalogField?,
        limit: Int
    ) async throws -> SecretCatalogSearchResult {
        let snapshot = try await catalogSnapshotForAgent()
        let result = catalogSearchService.search(
            query: query,
            field: field,
            limit: limit,
            document: snapshot.document
        )
        await emitAudit(
            action: "搜索本机敏感信息目录",
            target: "catalog-search",
            referenceCount: result.matches.count,
            result: result.status.rawValue
        )
        return result
    }

    public func getCatalogEntry(entryID: String) async throws -> SecretCatalogSearchResult {
        let snapshot = try await catalogSnapshotForAgent()
        return catalogSearchService.get(entryID: entryID, document: snapshot.document)
    }

    public func listCatalogIndexes() async throws -> SecretCatalogIndexListResult {
        let snapshot = try await catalogSnapshotForAgent()
        return SecretCatalogIndexListResult(
            revision: snapshot.revision,
            indices: catalogSearchService.listIndexes(document: snapshot.document)
        )
    }

    public func listCatalogEntries(indexID: String) async throws -> SecretCatalogEntryListResult {
        let snapshot = try await catalogSnapshotForAgent()
        return catalogSearchService.listEntries(
            indexID: indexID,
            document: snapshot.document,
            revision: snapshot.revision
        )
    }

    /// Applies a batch as one semantic transaction: one authoritative read,
    /// one risk decision/approval, one store lock and one revision increment.
    public func applyCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await performCatalogBatch(
            mutation,
            expectedRevision: expectedRevision,
            requireAgentSafeWrite: true
        )
    }

    private func performCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64,
        requireAgentSafeWrite: Bool,
        authorizationOperation: CatalogAgentWriteOperation = .batchMutation,
        resultIndexID: String? = nil,
        resultEntryID: String? = nil
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        guard snapshot.revision == expectedRevision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let next: SecretCatalogDocument
        do {
            next = try mutation.applying(to: snapshot.document)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext: AuditContext
        if requireAgentSafeWrite, !diff.isEmpty {
            let intent = CatalogAgentWriteIntent(
                operation: authorizationOperation,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            )
            operationContext = try await requestAgentCatalogAuthorization(intent, reasonCategory: .bulkImport)
        } else {
            operationContext = agentAuditContext()
        }
        try await authorizeCatalogDiff(
            diff,
            transport: .batchMutation,
            requireAgentSafeWrite: false
        )
        await emitCatalogMutationStarted(
            action: "批量修改目录",
            referenceCount: diff.referencedSecretRefs.count,
            context: operationContext
        )
        do {
            let updated = try await catalogDocumentStore!.applyBatch(mutation, expectedRevision: expectedRevision)
            await emitAudit(
                action: "批量修改目录",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                indexID: resultIndexID,
                entryID: resultEntryID,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(
                action: "批量修改目录",
                referenceCount: diff.referencedSecretRefs.count,
                context: operationContext
            )
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(
                action: "批量修改目录",
                referenceCount: diff.referencedSecretRefs.count,
                context: operationContext
            )
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Agent catalog creation binds approval to the generated index and the
    /// exact candidate semantic digest before committing it.
    public func createCatalogIndex(
        title: String,
        aliases: [String],
        tags: [String]
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        let index: SecretCatalogIndex
        do {
            index = try SecretCatalogIndex.generated(title: title, aliases: aliases, tags: tags)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let next = SecretCatalogDocument(indexes: snapshot.document.indexes + [index], entries: snapshot.document.entries)
        do { try next.validate() } catch { throw SecretCatalogAgentError.invalidOperation }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createIndex,
                indexID: index.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createIndex, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "创建目录分组", referenceCount: 0, context: operationContext)
        do {
            let updated = try await catalogDocumentStore!.createIndex(index, expectedRevision: snapshot.revision)
            await emitAudit(
                action: "创建目录分组",
                target: "catalog",
                referenceCount: 0,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                indexID: index.id,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as VaultCryptoError where error == .randomGenerationFailed {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .identifierGeneration, error: error)
            throw SecretCatalogAgentError.writeFailed
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Creates one Index and all requested safe Entries as one semantic
    /// operation. The caller supplies only client correlation keys; SVLT
    /// generates every opaque ID before the single authorization and atomic
    /// store commit.
    public func createCatalogStructure(
        _ request: CatalogCreateStructureRequest
    ) async throws -> CatalogStructureWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        let expectedRevision = request.expectedRevision ?? snapshot.revision
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }

        var clientKeys = Set<String>()
        for entry in request.entries {
            guard !entry.clientKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  clientKeys.insert(entry.clientKey).inserted,
                  entry.fields.allSatisfy({ field in
                      field.secretRef == nil && !(field.type.isSecret && field.value != nil)
                  })
            else {
                throw SecretCatalogAgentError.invalidOperation
            }
        }

        let index: SecretCatalogIndex
        var generatedEntries: [(clientKey: String, entry: SecretCatalogEntry)] = []
        do {
            index = try SecretCatalogIndex.generated(
                title: request.index.title,
                aliases: request.index.aliases,
                tags: request.index.tags
            )
            generatedEntries.reserveCapacity(request.entries.count)
            for item in request.entries {
                let entry = try SecretCatalogEntry.generated(
                    indexId: index.id,
                    title: item.title,
                    type: item.type,
                    aliases: item.aliases,
                    endpoints: item.endpoints,
                    fields: item.fields,
                    notes: item.notes,
                    tags: item.tags
                )
                generatedEntries.append((clientKey: item.clientKey, entry: entry))
            }
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }

        let mutation = CatalogBatchMutation(
            operations: [.createIndex(index)] + generatedEntries.map { .createEntry($0.entry) }
        )
        let next: SecretCatalogDocument
        do {
            next = try mutation.applying(to: snapshot.document)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createStructure,
                indexID: index.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .bulkImport
        )
        try await authorizeCatalogDiff(diff, transport: .batchMutation, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "创建目录结构", referenceCount: 0, context: operationContext)

        do {
            let updated = try await catalogDocumentStore!.applyBatch(mutation, expectedRevision: expectedRevision)
            await emitAudit(
                action: "创建目录结构",
                target: "catalog",
                referenceCount: 0,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogStructureWriteResult(
                indexID: index.id,
                entries: generatedEntries.map {
                    CatalogStructureEntryResult(clientKey: $0.clientKey, entryID: $0.entry.id)
                },
                revision: updated.revision,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录结构", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-structure", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "创建目录结构", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-structure", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Direct, single-call Agent creation for a safe Entry. Secret fields are
    /// accepted only as empty placeholders. Existing secret references and all
    /// plaintext secret values stay on their separate approval/secure-input
    /// paths.
    public func createCatalogEntry(_ request: CatalogDraftRequest) async throws -> CatalogWriteResult {
        do {
            let containsSecretValue = request.fields.contains { $0.type.isSecret && $0.value != nil }
            for reference in request.fields.compactMap(\.secretRef) {
                guard (try? SecretReference(reference)) != nil else {
                    try catalogMutationPolicyEngine.requireSilent(
                        CatalogMutationDescriptor(kind: .forgedSecretReference)
                    )
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
            if containsSecretValue {
                try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .plaintextSecretInCatalog))
            }
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .inputValidation, error: error)
            throw error
        }

        let snapshot: SensitiveCatalogSnapshot
        do {
            snapshot = try await catalogSnapshotForAgent()
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .snapshot, error: error)
            throw error
        }

        let entry: SecretCatalogEntry
        do {
            entry = try makeCatalogEntry(from: request)
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .model, error: error)
            throw error
        }

        let next: SecretCatalogDocument
        do {
            next = try snapshot.document.insertingEntryInSourceOrder(entry)
            try next.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createEntry,
                indexID: entry.indexId,
                entryID: entry.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createEntry, requireAgentSafeWrite: false)
        let referenceCount = entry.fields.filter { $0.secretRef != nil }.count
        await emitCatalogMutationStarted(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)

        do {
            let updated = try await catalogDocumentStore!.createEntry(entry, expectedRevision: snapshot.revision)
            await emitAudit(
                action: "创建目录条目",
                target: "catalog",
                referenceCount: referenceCount,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry,
                entryID: entry.id,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch let error as SecretCatalogAgentError {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            throw error
        } catch {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func createCatalogDraft(
        _ request: CatalogDraftRequest
    ) async throws -> CatalogDraft {
        let snapshot = try await catalogSnapshotForAgent()
        let containsReference = request.fields.contains { $0.secretRef != nil }
        let containsSecretValue = request.fields.contains { $0.type.isSecret && $0.value != nil }
        for reference in request.fields.compactMap(\.secretRef) {
            guard (try? SecretReference(reference)) != nil else {
                try catalogMutationPolicyEngine.requireSilent(
                    CatalogMutationDescriptor(kind: .forgedSecretReference)
                )
                throw SecretCatalogAgentError.invalidOperation
            }
        }
        if containsSecretValue {
            try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .plaintextSecretInCatalog))
        }
        if containsReference {
            try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .bindExistingSecret))
        }
        guard snapshot.document.indexes.contains(where: { $0.id == request.indexID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let entry = try makeCatalogEntry(from: request)
        let draftID = try SecretCatalogOpaqueID.generate()
        var draftDocument = snapshot.document
        draftDocument = SecretCatalogDocument(
            indexes: draftDocument.indexes,
            entries: draftDocument.entries + [entry]
        )
        try draftDocument.validate()
        pendingCatalogDrafts[draftID] = entry
        guard let match = catalogSearchService.get(entryID: entry.id, document: draftDocument).matches.first else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return CatalogDraft(draftID: draftID, baseRevision: snapshot.revision, entry: match.entry)
    }

    public func patchCatalogMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        guard let oldEntry = snapshot.document.entries.first(where: { $0.id == entryID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let updated = try metadataPatchedEntry(oldEntry, with: patch)
        var entries = snapshot.document.entries
        guard let offset = entries.firstIndex(where: { $0.id == entryID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        entries[offset] = updated
        let next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
        do { try next.validate() } catch { throw SecretCatalogAgentError.invalidOperation }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        try catalogMutationPolicyEngine.requireSilent(
            CatalogMutationDescriptor(kind: .patchMetadata)
        )
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .patchMetadata,
                indexID: updated.indexId,
                entryID: entryID,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .patchMetadata, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
        do {
            let updatedSnapshot = try await catalogDocumentStore!.updateEntry(updated, expectedRevision: expectedRevision)
            await emitAudit(
                action: "修改目录条目元数据",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry,
                entryID: entryID,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        guard let pending = pendingCatalogDrafts[draft.draftID] else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision,
              draft.baseRevision == snapshot.revision,
              draft.entry.id == pending.id,
              draft.entry.indexId == pending.indexId
        else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let next: SecretCatalogDocument
        do {
            next = try snapshot.document.insertingEntryInSourceOrder(pending)
            try next.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .commitDraft,
                indexID: pending.indexId,
                entryID: pending.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        try await authorizeCatalogDiff(diff, transport: .createEntry, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "提交目录条目草稿", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
        do {
            let updatedSnapshot = try await catalogDocumentStore!.createEntry(pending, expectedRevision: expectedRevision)
            pendingCatalogDrafts.removeValue(forKey: draft.draftID)
            await emitAudit(
                action: "提交目录条目草稿",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: pending.id, document: updatedSnapshot.document).matches.first?.entry,
                entryID: pending.id,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "提交目录条目草稿", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "提交目录条目草稿", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let field = SecretCatalogFieldValue(
            key: key,
            label: label,
            type: .secret,
            agentVisible: agentVisible,
            searchable: searchable
        )
        let next: SecretCatalogDocument
        do {
            guard let existingEntry = snapshot.document.entries.first(where: { $0.id == entryID }),
                  !existingEntry.fields.contains(where: { $0.key == key }),
                  let offset = snapshot.document.entries.firstIndex(where: { $0.id == entryID })
            else { throw SecretCatalogAgentError.invalidOperation }
            let candidateEntry = SecretCatalogEntry(
                id: existingEntry.id,
                indexId: existingEntry.indexId,
                title: existingEntry.title,
                type: existingEntry.type,
                aliases: existingEntry.aliases,
                endpoints: existingEntry.endpoints,
                fields: existingEntry.fields + [field],
                notes: existingEntry.notes,
                tags: existingEntry.tags,
                schema: existingEntry.schema
            )
            var entries = snapshot.document.entries
            entries[offset] = candidateEntry
            next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
            try next.validate()
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .addSecretPlaceholder,
                entryID: entryID,
                fieldKey: key,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createSecretPlaceholder, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
        do {
            let updatedSnapshot = try await catalogDocumentStore!.addField(
                field,
                toEntryID: entryID,
                expectedRevision: expectedRevision
            )
            await emitAudit(
                action: "新增目录加密字段占位",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry,
                entryID: entryID,
                validation: await postCommitCatalogValidation()
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func bindCatalogExistingSecret(
        entryID _: String,
        key _: String,
        secretRef: String,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        _ = try await catalogSnapshotForAgent()
        guard (try? SecretReference(secretRef)) != nil else {
            throw SecretCatalogAgentError.invalidOperation
        }
        // Binding an existing secret can change the destination/policy meaning
        // of a catalog entry.  It remains an App-approved operation; an Agent
        // cannot turn a self-reported user request into authorization.
        try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .bindExistingSecret))
        throw SecretCatalogAgentError.approvalRequired
    }

    /// Every successful Agent-controlled Catalog write returns this summary so
    /// callers do not need a second MCP round trip merely to verify the commit.
    /// The store has already validated the candidate before replacing the
    /// document; this follow-up reads the authoritative post-commit state and
    /// preserves any integrity diagnostics without exposing document content.
    private func postCommitCatalogValidation() async -> CatalogValidationResult {
        (try? await validateCatalog()) ?? CatalogValidationResult(status: .unavailable)
    }

    public func validateCatalog() async throws -> CatalogValidationResult {
        do {
            let store = try await selectedCatalogStoreForApp()
            let report = try await store.validationReport()
            return CatalogValidationResult(
                status: report.status,
                revision: report.revision,
                rawSHA256: report.rawSHA256,
                pendingExternalChange: report.pendingExternalChange,
                diagnostics: report.diagnostics
            )
        } catch let error as SecretCatalogAgentError {
            switch error {
            case .unavailable:
                return CatalogValidationResult(status: .unavailable)
            default:
                return CatalogValidationResult(status: .invalidCatalog, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_VALIDATION_FAILED",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "敏感信息目录验证失败。",
                    hint: "请在 SVLT App 中检查目录状态。"
                )])
            }
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .noSelectedDocument:
                return CatalogValidationResult(status: .unavailable)
            case .writeFailed:
                return CatalogValidationResult(status: .unavailable, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_READ_UNAVAILABLE",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "无法读取敏感信息目录。",
                    hint: "请检查 App 选择的目录文件。"
                )])
            default:
                return CatalogValidationResult(status: .invalidCatalog, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_VALIDATION_FAILED",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "敏感信息目录验证失败。",
                    hint: "请在 SVLT App 中检查目录状态。"
                )])
            }
        } catch {
            return CatalogValidationResult(status: .unavailable)
        }
    }

    public func catalogStatus() async throws -> CatalogValidationResult {
        try await validateCatalog()
    }

    public func catalogFilePreflight() async throws -> CatalogFilePreflight {
        try await catalogFilePreflightForAgent()
    }

    public func catalogFormatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        let store = try await selectedCatalogStoreForApp()
        do {
            let plan = try await store.formatRepairPlan()
            await emitAudit(
                action: "检查目录格式",
                target: "catalog-format",
                referenceCount: 0,
                result: {
                    guard let plan else { return "没有选中的目录" }
                    if plan.diagnostics.isEmpty { return "格式正常" }
                    return plan.canRepair ? "发现可修复问题" : "发现需人工处理问题"
                }(),
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .formatCheck
            )
            return plan
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    public func repairCatalogFormat(expectedRawSHA256: String) async throws -> CatalogValidationResult {
        let store = try await selectedCatalogStoreForApp()
        do {
            _ = try await store.repairFormat(expectedRawSHA256: expectedRawSHA256)
            await emitAudit(
                action: "修复目录格式",
                target: "catalog-format",
                referenceCount: 0,
                result: "成功",
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .formatRepair
            )
            return try await validateCatalog()
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    public func catalogRecentAuditEntries(limit: Int) async throws -> [CatalogSecurityAuditEntry] {
        guard let auditLog else { return [] }
        let events = try await auditLog.recent(limit: min(max(limit, 1), 100))
        return events.map(Self.safeAuditEntry)
    }

    /// A deliberately narrow, non-sensitive health signal. It never contains
    /// paths, payloads, reference IDs, or key material.
    public func catalogAuditHealth() async -> String? {
        guard auditAppendGapDetected else { return nil }
        return "AUDIT_APPEND_FAILED"
    }

    public func pendingCatalogSecureInputRequestIDs() async -> [UUID] {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        return pendingSecureInputRequests
            .filter { secureInputStates[$0.key] == .awaitingInput || secureInputStates[$0.key] == .submitting }
            .map(\.value)
            .sorted { $0.createdAt < $1.createdAt }
            .map(\.id)
    }

    public func catalogSecureInputRequest(id: UUID) async throws -> CatalogAgentSecureInputRequest {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        guard let request = pendingSecureInputRequests[id],
              secureInputStates[id] == .awaitingInput || secureInputStates[id] == .submitting
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return request
    }

    public func catalogSecureInputStatus(id: UUID) async -> CatalogSecureInputStatus {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        if let status = secureInputStatuses[id] {
            return status
        }
        if let state = secureInputStates[id] {
            return CatalogSecureInputStatus(
                requestID: id,
                status: secureInputStatusValue(for: state)
            )
        }
        return CatalogSecureInputStatus(
            requestID: id,
            status: .failed,
            errorCode: "SECURE_INPUT_REQUEST_NOT_FOUND"
        )
    }

    public func requestCatalogSecureInputs(
        entryID: String,
        targets: [CatalogSecureInputTargetRequest],
        expectedRevision: UInt64
    ) async throws -> CatalogSecureInputStatus {
        let snapshot = try await catalogSnapshotForAgent()
        guard snapshot.revision == expectedRevision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              !targets.isEmpty,
              Set(targets.map(\.id)).count == targets.count,
              targets.allSatisfy({ $0.entryID == entryID })
        else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let fields = Dictionary(uniqueKeysWithValues: entry.fields.map { ($0.key, $0) })
        let resolvedTargets: [CatalogSecureInputTarget] = try targets.map { target in
            guard let field = fields[target.fieldKey] else {
                throw SecretCatalogAgentError.invalidOperation
            }
            switch target.mode {
            case .fillPlaceholder:
                guard field.type.isSecret && field.secretRef == nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            case .replaceSecret:
                guard field.type.isSecret && field.secretRef != nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            case .convertToSecret:
                guard !field.type.isSecret else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
            return CatalogSecureInputTarget(
                entryID: entryID,
                fieldKey: field.key,
                label: field.label,
                mode: target.mode,
                required: target.required,
                usesExistingValue: target.mode == .convertToSecret && existingCatalogValueIsNonEmpty(field.value)
            )
        }

        let callerContext = AuditContext.current ?? AuditContext(source: .agent)
        // One opaque ID is the sole correlation key for the UI request, the
        // status receipt, the authentication audit, and the final commit.
        let requestID = UUID()
        let operationContext = callerContext.withRequestID(requestID)
        let createdAt = now()
        let request = CatalogAgentSecureInputRequest(
            id: requestID,
            correlationID: callerContext.correlationID,
            requestID: requestID,
            entryID: entryID,
            entryTitle: entry.title,
            expectedRevision: expectedRevision,
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(180),
            targets: resolvedTargets
        )
        pendingSecureInputRequests[request.id] = request
        secureInputStates[request.id] = .awaitingInput
        secureInputAuditContexts[request.id] = operationContext
        secureInputStatuses[request.id] = CatalogSecureInputStatus(
            requestID: request.id,
            status: .pending
        )
        secureInputExpiryTasks[request.id] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(180))
            guard !Task.isCancelled else { return }
            await self?.expireCatalogSecureInputRequest(id: request.id)
        }
        await emitAudit(
            action: "智能体安全输入请求",
            target: "catalog-field",
            referenceCount: resolvedTargets.count,
            result: "请求中",
            context: operationContext,
            operation: .authorization,
            authorizationOutcome: .requested,
            status: .requested
        )
        secureInputNotifier.present(requestID: request.id)
        return CatalogSecureInputStatus(requestID: request.id, status: .pending)
    }

    /// Atomically authenticates, encrypts, evaluates the authoritative final
    /// semantic diff, commits, and records completion for one immutable
    /// request. Plaintext never crosses the generic Catalog mutation API.
    public func submitCatalogSecureInput(
        id: UUID,
        submission: CatalogSecureInputSubmission
    ) async throws -> CatalogSecureInputStatus {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        guard let request = pendingSecureInputRequests[id],
              secureInputStates[id] == .awaitingInput,
              request.expiresAt > now()
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        secureInputStates[id] = .submitting
        var createdReferences: [SecretReference] = []
        do {
            // This is the one device-owner authentication for this request.
            // The request ID remains in the actor state while the authenticator
            // suspends, so a second submit cannot race or reuse the proof.
            await emitAudit(
                action: "智能体安全输入本机认证请求",
                target: "catalog-field",
                referenceCount: request.targets.count,
                result: "请求中",
                context: secureInputAuditContexts[id],
                operation: .authorization,
                authorizationOutcome: .requested,
                status: .requested
            )
            try await approveWithTimeout(summary: secureInputApprovalSummary(for: request))
            await emitAudit(
                action: "智能体安全输入本机认证完成",
                target: "catalog-field",
                referenceCount: request.targets.count,
                result: "成功",
                context: secureInputAuditContexts[id],
                operation: .authorization,
                authorizationOutcome: .approved,
                status: .completed
            )
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)

            let snapshot = try await catalogSnapshotForAgent()
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)
            guard snapshot.revision == request.expectedRevision,
                  let currentEntry = snapshot.document.entries.first(where: { $0.id == request.entryID })
            else {
                throw SecretCatalogAgentError.revisionConflict
            }
            let finalResult = try await makeSecureInputFinalEntry(
                request: request,
                submission: submission,
                currentEntry: currentEntry
            )
            let finalEntry = finalResult.entry
            createdReferences = finalResult.references
            var finalEntries = snapshot.document.entries
            guard let offset = finalEntries.firstIndex(where: { $0.id == request.entryID }) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            finalEntries[offset] = finalEntry
            let finalDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: finalEntries)
            try finalDocument.validate()

            let finalDiff = CatalogSemanticDiff.between(old: snapshot.document, new: finalDocument)
            try await validatePreauthorizedCatalogDiff(finalDiff)
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)
            // This synchronous actor-state transition is the commit
            // linearization point. There is intentionally no await between
            // the active check above and this assignment: cancellation and
            // expiry either win before this point or are rejected after it.
            secureInputStates[id] = .committing
            let updated = try await catalogDocumentStore!.updateEntry(
                finalEntry,
                expectedRevision: request.expectedRevision
            )
            await notifySavedReferencesChanged()
            let status = CatalogSecureInputStatus(
                requestID: request.id,
                status: .completed,
                revision: updated.revision
            )
            await finishSecureInputRequest(
                id: id,
                status: status,
                action: "智能体安全输入完成",
                result: "成功",
                authorizationOutcome: .approved,
                auditStatus: .completed
            )
            return status
        } catch let error as CatalogSecureInputAbortError {
            let status: CatalogSecureInputStatus
            let action: String
            let result: String
            let auditStatus: AuditStatus
            switch error {
            case .cancelled:
                status = CatalogSecureInputStatus(requestID: request.id, status: .cancelled, errorCode: "SECURE_INPUT_CANCELLED")
                action = "智能体安全输入取消"
                result = "已取消"
                auditStatus = .cancelled
            case .expired:
                status = CatalogSecureInputStatus(requestID: request.id, status: .expired, errorCode: "SECURE_INPUT_EXPIRED")
                action = "智能体安全输入过期"
                result = "已过期"
                auditStatus = .expired
            }
            _ = await compensateCreatedReferences(createdReferences)
            await finishSecureInputRequest(
                id: id,
                status: status,
                action: action,
                result: result,
                authorizationOutcome: .cancelled,
                auditStatus: auditStatus
            )
            throw SecretCatalogAgentError.invalidOperation
        } catch let error as SensitiveCatalogDocumentStoreError {
            let mapped = catalogAgentError(for: error)
            let finalError = await compensateCreatedReferences(createdReferences) ?? mapped
            await finishSecureInputRequest(
                id: id,
                status: CatalogSecureInputStatus(requestID: request.id, status: .failed, errorCode: secureInputErrorCode(finalError)),
                action: "智能体安全输入失败",
                result: "失败",
                authorizationOutcome: .denied,
                auditStatus: .failure
            )
            throw finalError
        } catch {
            let finalError = await compensateCreatedReferences(createdReferences) ?? (error as Error)
            let code = secureInputErrorCode(finalError)
            await finishSecureInputRequest(
                id: id,
                status: CatalogSecureInputStatus(requestID: request.id, status: .failed, errorCode: code),
                action: "智能体安全输入失败",
                result: "失败",
                authorizationOutcome: .denied,
                auditStatus: .failure
            )
            throw finalError
        }
    }

    public func cancelCatalogSecureInput(id: UUID) async {
        guard let request = pendingSecureInputRequests[id],
              secureInputStates[id] == .awaitingInput || secureInputStates[id] == .submitting
        else { return }
        if secureInputStates[id] == .submitting {
            secureInputAbortReasons[id] = .cancelled
            secureInputNotifier.notifyQueueChanged(requestID: id)
            return
        }
        await finishSecureInputRequest(
            id: id,
            status: CatalogSecureInputStatus(requestID: request.id, status: .cancelled, errorCode: "SECURE_INPUT_CANCELLED"),
            action: "智能体安全输入取消",
            result: "已取消",
            authorizationOutcome: .cancelled,
            auditStatus: .cancelled
        )
    }

    private func expireCatalogSecureInputRequest(id: UUID) async {
        guard let request = pendingSecureInputRequests[id],
              secureInputStates[id] == .awaitingInput || secureInputStates[id] == .submitting
        else { return }
        if secureInputStates[id] == .submitting {
            secureInputAbortReasons[id] = .expired
            secureInputNotifier.notifyQueueChanged(requestID: id)
            return
        }
        await finishSecureInputRequest(
            id: id,
            status: CatalogSecureInputStatus(requestID: request.id, status: .expired, errorCode: "SECURE_INPUT_EXPIRED"),
            action: "智能体安全输入过期",
            result: "已过期",
            authorizationOutcome: .cancelled,
            auditStatus: .cancelled
        )
    }

    private func expireDueSecureInputRequests() async {
        let due = pendingSecureInputRequests.values
            .filter { $0.expiresAt <= now() }
            .map(\.id)
        for id in due { await expireCatalogSecureInputRequest(id: id) }
    }

    private func pruneSecureInputReceipts() {
        let cutoff = now().addingTimeInterval(-15 * 60)
        for id in secureInputTerminalAt.keys where secureInputTerminalAt[id, default: .distantFuture] < cutoff {
            secureInputTerminalAt.removeValue(forKey: id)
            secureInputStatuses.removeValue(forKey: id)
        }
        if secureInputStatuses.count > 128 {
            let oldest = secureInputTerminalAt
                .sorted { $0.value < $1.value }
                .prefix(max(0, secureInputStatuses.count - 128))
            for (id, _) in oldest {
                secureInputTerminalAt.removeValue(forKey: id)
                secureInputStatuses.removeValue(forKey: id)
            }
        }
    }

    private func secureInputStatusValue(for state: CatalogSecureInputState) -> CatalogSecureInputStatusValue {
        switch state {
        case .awaitingInput, .submitting: return .pending
        case .committing: return .pending
        case .completed: return .completed
        case .failed: return .failed
        case .expired: return .expired
        case .cancelled: return .cancelled
        }
    }

    private func finishSecureInputRequest(
        id: UUID,
        status: CatalogSecureInputStatus,
        action: String,
        result: String,
        authorizationOutcome: AuditAuthorizationOutcome,
        auditStatus: AuditStatus
    ) async {
        guard let request = pendingSecureInputRequests.removeValue(forKey: id) else { return }
        secureInputStates[id] = switch status.status {
        case .completed: .completed
        case .failed: .failed
        case .expired: .expired
        case .cancelled: .cancelled
        case .pending: .submitting
        }
        secureInputStatuses[id] = status
        secureInputTerminalAt[id] = now()
        secureInputAbortReasons.removeValue(forKey: id)
        secureInputExpiryTasks.removeValue(forKey: id)?.cancel()
        let context = secureInputAuditContexts.removeValue(forKey: id)
        secureInputNotifier.notifyQueueChanged(requestID: id)
        await emitAudit(
            action: action,
            target: "catalog-field",
            referenceCount: request.targets.count,
            result: result,
            context: context,
            operation: .authorization,
            authorizationOutcome: authorizationOutcome,
            status: auditStatus
        )
    }

    private func secureInputApprovalSummary(for request: CatalogAgentSecureInputRequest) -> String {
        "为 \(safeDisplayLabel(request.entryTitle)) 写入 \(request.targets.count) 个敏感字段"
    }

    private func ensureSecureInputSubmissionIsStillActive(
        id: UUID,
        request: CatalogAgentSecureInputRequest
    ) throws {
        guard pendingSecureInputRequests[id] != nil,
              secureInputStates[id] == .submitting
        else {
            throw CatalogSecureInputAbortError.cancelled
        }
        if secureInputAbortReasons[id] == .expired || request.expiresAt <= now() {
            throw CatalogSecureInputAbortError.expired
        }
        if secureInputAbortReasons[id] == .cancelled {
            throw CatalogSecureInputAbortError.cancelled
        }
    }

    private func secureInputErrorCode(_ error: Error) -> String {
        if let error = error as? SecretCatalogAgentError {
            switch error {
            case .revisionConflict: return "CATALOG_REVISION_CONFLICT"
            case .invalidOperation: return "CATALOG_INVALID_OPERATION"
            case .writeFailed: return "CATALOG_WRITE_FAILED"
            case .cleanupRequired: return "CATALOG_CLEANUP_REQUIRED"
            default: return "SECURE_INPUT_FAILED"
            }
        }
        if let error = error as? SecretOperationError {
            return error.responseCode
        }
        if let error = error as? OperationAuthorizationError {
            switch error {
            case .cancelled: return "AUTHORIZATION_CANCELLED"
            case .denied: return "AUTHORIZATION_DENIED"
            case .timeout: return "AUTHORIZATION_TIMEOUT"
            case .unavailable: return "AUTHORIZATION_UNAVAILABLE"
            }
        }
        return "SECURE_INPUT_FAILED"
    }

    private func makeSecureInputFinalEntry(
        request: CatalogAgentSecureInputRequest,
        submission: CatalogSecureInputSubmission,
        currentEntry: SecretCatalogEntry
    ) async throws -> (entry: SecretCatalogEntry, references: [SecretReference]) {
        let targetsByID = Dictionary(uniqueKeysWithValues: request.targets.map { ($0.id, $0) })
        let selectedIDs = Set(submission.selectedTargetIDs)
        guard selectedIDs.count == submission.selectedTargetIDs.count,
              !selectedIDs.isEmpty,
              selectedIDs.isSubset(of: Set(targetsByID.keys)),
              request.targets.filter(\.required).allSatisfy({ selectedIDs.contains($0.id) })
        else { throw SecretCatalogAgentError.invalidOperation }
        let selectedKeys = Set(selectedIDs.compactMap { targetsByID[$0]?.fieldKey })
        let inputKeys: Set<String> = Set(selectedIDs.compactMap { id in
            guard let target = targetsByID[id], !target.usesExistingValue else { return nil }
            return target.fieldKey
        })
        guard Set(submission.plaintextByFieldKey.keys) == inputKeys,
              selectedKeys.count == selectedIDs.count
        else { throw SecretCatalogAgentError.invalidOperation }

        var encryptedReferences: [String: String] = [:]
        var createdReferences: [SecretReference] = []
        do {
            for id in selectedIDs {
                guard let target = targetsByID[id],
                      let field = currentEntry.fields.first(where: { $0.key == target.fieldKey }),
                      let plaintext = secureInputPlaintext(
                        for: target,
                        field: field,
                        submission: submission
                      ),
                      !plaintext.isEmpty
                else { throw SecretCatalogAgentError.invalidOperation }
                let reference = try await textEncryptor.encryptText(
                    plaintext,
                    label: field.label,
                    policy: .credential
                )
                createdReferences.append(reference)
                encryptedReferences[target.fieldKey] = reference.description
            }
        } catch {
            if let cleanupError = await compensateCreatedReferences(createdReferences) {
                throw cleanupError
            }
            throw error
        }

        let updatedFields = currentEntry.fields.map { field in
            guard let target = request.targets.first(where: { $0.fieldKey == field.key }),
                  selectedIDs.contains(target.id),
                  let reference = encryptedReferences[field.key]
            else { return field }
            return SecretCatalogFieldValue(
                key: field.key,
                label: field.label,
                type: target.mode == .convertToSecret ? .secret : field.type,
                agentVisible: field.agentVisible,
                searchable: field.searchable,
                value: nil,
                secretRef: reference
            )
        }
        let entry = SecretCatalogEntry(
            id: currentEntry.id,
            indexId: currentEntry.indexId,
            title: currentEntry.title,
            type: currentEntry.type,
            aliases: currentEntry.aliases,
            endpoints: currentEntry.endpoints,
            fields: updatedFields,
            notes: currentEntry.notes,
            tags: currentEntry.tags,
            schema: currentEntry.schema
        )
        return (entry, createdReferences)
    }

    private func existingCatalogValueIsNonEmpty(_ value: SecretCatalogValue?) -> Bool {
        guard let value else { return false }
        switch value {
        case .string(let string):
            return !string.isEmpty
        case .number, .boolean:
            return true
        case .list(let values):
            return !values.isEmpty
        }
    }

    private func secureInputPlaintext(
        for target: CatalogSecureInputTarget,
        field: SecretCatalogFieldValue,
        submission: CatalogSecureInputSubmission
    ) -> String? {
        if target.usesExistingValue {
            guard target.mode == .convertToSecret else { return nil }
            switch field.value {
            case .string(let value): return value
            case .number(let value): return String(value)
            case .boolean(let value): return value ? "true" : "false"
            case .list(let values): return values.joined(separator: "\n")
            case nil: return nil
            }
        }
        return submission.plaintextByFieldKey[target.fieldKey]
    }

    private func validatePreauthorizedCatalogDiff(_ diff: CatalogSemanticDiff) async throws {
        guard !diff.isEmpty,
              catalogMutationPolicyEngine.evaluate(diff, transport: .directManagedFileWrite) != .denied
        else { throw SecretCatalogAgentError.invalidOperation }
        let references: [SecretReference]
        do { references = try diff.referencedSecretRefs.map(SecretReference.init) }
        catch { throw SecretCatalogAgentError.invalidOperation }
        if !references.isEmpty {
            let metadata = try await policyMetadata(for: references)
            let descriptor = SecretOperationDescriptor(
                actionType: diff.changesSecretTarget ? .changeDestinationBinding : .changeSecretPolicy,
                secretReferences: references,
                requestedEffects: ["secure-input-final-diff"]
            )
            let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
            guard decision.risk != .denied else { throw SecretOperationError.operationDenied }
        }
    }

    public func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        let store = try await selectedCatalogStoreForApp()
        do {
            let snapshot = try await store.adoptExternalV2()
            return CatalogValidationResult(status: .found, revision: snapshot.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .legacyCatalogUnsupported:
                throw SecretCatalogAgentError.legacyCatalogUnsupported
            case .integrityMissing:
                throw SecretCatalogAgentError.integrityMissing
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
            case .pendingExternalChange:
                throw SecretCatalogAgentError.pendingExternalChange
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        }
    }

    public func adoptCatalogExternalV3() async throws -> CatalogValidationResult {
        let store = try await selectedCatalogStoreForApp()
        do {
            let candidate = try await store.externalV3AdoptionCandidate()
            let references = candidate.semanticDiff.referencedSecretRefs
            if !references.isEmpty {
                guard recordResolver != nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                for reference in references {
                    do {
                        _ = try await inspectReference(reference)
                    } catch {
                        // A syntactically valid secret:// handle is not enough
                        // to adopt a catalog. Every binding must point at a
                        // real local record before approval is presented.
                        throw SecretCatalogAgentError.invalidOperation
                    }
                }
                try await authorizeCatalogDiff(
                    candidate.semanticDiff,
                    transport: .bindExistingSecret,
                    requireAgentSafeWrite: false
                )
            }
            let snapshot = try await store.adoptExternalV3(
                expectedRawSHA256: candidate.rawSHA256,
                expectedSemanticSHA256: candidate.semanticSHA256
            )
            return CatalogValidationResult(status: .found, revision: snapshot.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    /// Approves the currently pending high-risk external semantic change.
    /// The Markdown already exists on disk; approval only moves its semantic
    /// snapshot into the accepted state and never rewrites user formatting.
    public func approveCatalogExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> CatalogValidationResult {
        let store = try await selectedCatalogStoreForApp()
        do {
            let pending = try await store.pendingExternalChange()
            guard pending.acceptedRevision == expectedRevision,
                  pending.rawSHA256 == expectedRawSHA256,
                  pending.semanticSHA256 == expectedSemanticSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            try await authorizeCatalogDiff(
                pending.semanticDiff,
                transport: .directManagedFileWrite,
                requireAgentSafeWrite: false
            )
            let accepted = try await store.acceptPendingExternalChange(
                expectedRevision: expectedRevision,
                expectedRawSHA256: expectedRawSHA256,
                expectedSemanticSHA256: expectedSemanticSHA256
            )
            return CatalogValidationResult(status: .found, revision: accepted.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    public func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        if mode == .disabled {
            await catalogAgentWriteAuthorization.revoke()
            return await catalogAgentWriteAuthorization.status()
        }
        // Retain this wire case for older clients, but never let it create a
        // global lease. Every non-disabled Agent write must arrive through the
        // operation-bound request path below.
        _ = duration
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    public func revokeCatalogAgentWrite() async {
        await catalogAgentWriteAuthorization.revoke()
    }

    public func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus {
        await catalogAgentWriteAuthorization.status()
    }

    public func requestCatalogWriteAccess(
        source: CatalogAgentWriteRequestSource,
        reasonCategory: CatalogAgentWriteReasonCategory,
        duration: CatalogAgentWriteAccessDuration
    ) async throws {
        // This is the legacy generic request API. It cannot prove which
        // mutation the user is approving, so fail closed instead of creating
        // a reusable permission. Agent mutations call the private method with
        // an exact intent.
        _ = (source, reasonCategory, duration)
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    private func requestAgentCatalogAuthorization(
        _ intent: CatalogAgentWriteIntent,
        reasonCategory: CatalogAgentWriteReasonCategory
    ) async throws -> AuditContext {
        let requestID = UUID()
        // IPCRequestHandler installs the trusted Agent context. The explicit
        // fallback exists only for legacy in-process callers/tests that invoke
        // this service directly; it is not used by the production transport.
        let callerContext = AuditContext.current ?? AuditContext(source: .agent)
        let operationContext = callerContext.withRequestID(requestID)
        let createdAt = now()
        let expiry = createdAt.addingTimeInterval(CatalogAgentWriteAuthorization.ticketLifetime)
        let request = CatalogAgentWriteAccessRequest(
            id: requestID,
            source: .mcpClient,
            reasonCategory: reasonCategory,
            duration: .singleUse,
            createdAt: iso8601String(createdAt),
            intent: intent.bound(to: requestID),
            expiresAt: iso8601String(expiry),
            verifiedSource: nil
        )
        pendingWriteAccessRequests[request.id] = request
        writeAccessStates[request.id] = .pending
        pendingWriteAuditContexts[request.id] = operationContext
        let continuationBox = CatalogWriteAccessContinuationBox()
        writeAccessContinuations[request.id] = continuationBox
        await emitAudit(
            action: "智能体目录写入授权请求",
            target: "catalog-write",
            referenceCount: 0,
            result: "请求中",
            context: operationContext,
            operation: .authorization,
            authorizationOutcome: .requested,
            status: .requested
        )

        var timeoutTask: Task<Void, Never>?
        defer {
            timeoutTask?.cancel()
            pendingWriteAccessRequests.removeValue(forKey: request.id)
            writeAccessContinuations.removeValue(forKey: request.id)
            pendingWriteAuditContexts.removeValue(forKey: request.id)
            pruneWriteAccessStates()
        }
        do {
            try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { continuation in
                    continuationBox.store(continuation)
                    timeoutTask = Task { [weak self] in
                        try? await Task.sleep(for: .seconds(CatalogAgentWriteAuthorization.ticketLifetime))
                        guard !Task.isCancelled else { return }
                        await self?.expireCatalogWriteAccessRequest(id: request.id)
                    }
                    writeAccessNotifier.present(request)
                }
            }, onCancel: { [weak self] in
                Task { await self?.cancelCatalogWriteAccessRequest(id: request.id) }
            })
            guard let boundIntent = pendingWriteAccessRequests[request.id]?.intent else {
                throw SecretCatalogAgentError.agentWriteNotAllowed
            }
            try await catalogAgentWriteAuthorization.consume(
                requestID: request.id,
                intent: boundIntent
            )
            writeAccessStates[request.id] = .consumed
        } catch {
            await catalogAgentWriteAuthorization.revoke(requestID: request.id)
            if error is CancellationError {
                writeAccessStates[request.id] = .cancelled
                await emitAudit(action: "智能体目录写入授权取消", target: "catalog-write", referenceCount: 0, result: "已取消", context: operationContext, operation: .authorization, authorizationOutcome: .cancelled, status: .cancelled)
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            if writeAccessStates[request.id] == .expired {
                await emitAudit(action: "智能体目录写入授权超时", target: "catalog-write", referenceCount: 0, result: "已超时", context: operationContext, operation: .authorization, authorizationOutcome: .expired, status: .expired)
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            if error is VaultAppServicesRevealError || error is OperationAuthorizationError {
                await emitAudit(action: "智能体目录写入授权失败", target: "catalog-write", referenceCount: 0, result: "失败", context: operationContext, operation: .authorization, authorizationOutcome: .denied, status: .failure)
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            await emitAudit(action: "智能体目录写入授权失败", target: "catalog-write", referenceCount: 0, result: "失败", context: operationContext, operation: .authorization, authorizationOutcome: .denied, status: .failure)
            throw error
        }
        return operationContext
    }

    public func pendingCatalogWriteAccessRequest(id: UUID) async throws -> CatalogAgentWriteAccessRequest {
        guard let request = pendingWriteAccessRequests[id],
              writeAccessStates[id] == .pending || writeAccessStates[id] == .authenticating
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return request
    }

    /// App cold-start/foreground discovery. The DistributedNotification path
    /// is only a live accelerator; pending requests remain authoritative in
    /// the Agent until they expire, are denied, or are consumed.
    public func pendingCatalogWriteAccessRequestIDs() async throws -> [UUID] {
        pendingWriteAccessRequests.keys
            .filter { writeAccessStates[$0] == .pending || writeAccessStates[$0] == .authenticating }
            .sorted { lhs, rhs in
                (pendingWriteAccessRequests[lhs]?.createdAt ?? "") <
                    (pendingWriteAccessRequests[rhs]?.createdAt ?? "")
            }
    }

    public func respondToCatalogWriteAccessRequest(id: UUID, approved: Bool) async throws {
        guard let request = pendingWriteAccessRequests[id],
              writeAccessStates[id] == .pending,
              let continuation = writeAccessContinuations[id]
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let originalContext = pendingWriteAuditContexts[id]
        let approvalContext = AuditContext(
            source: .app,
            correlationID: originalContext?.correlationID ?? AuditContext.current?.correlationID ?? UUID(),
            requestID: id
        )
        guard approved else {
            writeAccessStates[id] = .denied
            continuation.resume(throwing: SecretCatalogAgentError.agentWriteNotAllowed)
            await emitAudit(action: "智能体目录写入授权拒绝", target: "catalog-write", referenceCount: 0, result: "已拒绝", context: approvalContext, operation: .authorization, authorizationOutcome: .denied, status: .failure)
            return
        }

        writeAccessStates[id] = .authenticating
        do {
            try await approveWithTimeout(summary: catalogWriteApprovalSummary(request))
            guard writeAccessStates[id] == .authenticating,
                  let intent = request.intent
            else {
                throw OperationAuthorizationError.cancelled
            }
            _ = await catalogAgentWriteAuthorization.approve(requestID: id, intent: intent)
            writeAccessStates[id] = .approved
            continuation.resume()
            await emitAudit(action: "智能体目录写入授权完成", target: "catalog-write", referenceCount: 0, result: "成功", context: approvalContext, operation: .authorization, authorizationOutcome: .approved)
        } catch let error as OperationAuthorizationError {
            writeAccessStates[id] = .denied
            await catalogAgentWriteAuthorization.revoke(requestID: id)
            continuation.resume(throwing: error)
            let outcome: AuditAuthorizationOutcome = error == .cancelled ? .cancelled : (error == .timeout ? .expired : .denied)
            let result = error == .cancelled ? "已取消" : (error == .timeout ? "已超时" : "已拒绝")
            let auditStatus: AuditStatus = error == .cancelled ? .cancelled : (error == .timeout ? .expired : .failure)
            await emitAudit(action: "智能体目录写入授权结束", target: "catalog-write", referenceCount: 0, result: result, context: approvalContext, operation: .authorization, authorizationOutcome: outcome, status: auditStatus)
            throw SecretCatalogAgentError.agentWriteApprovalUnavailable
        } catch {
            writeAccessStates[id] = .denied
            await catalogAgentWriteAuthorization.revoke(requestID: id)
            continuation.resume(throwing: SecretCatalogAgentError.agentWriteApprovalUnavailable)
            await emitAudit(action: "智能体目录写入授权失败", target: "catalog-write", referenceCount: 0, result: "失败", context: approvalContext, operation: .authorization, authorizationOutcome: .denied, status: .failure)
            throw SecretCatalogAgentError.agentWriteApprovalUnavailable
        }
    }

    private func catalogWriteApprovalSummary(_ request: CatalogAgentWriteAccessRequest) -> String {
        let operation = request.intent?.operation.rawValue ?? "unknown-operation"
        return "SVLT 需要本机身份认证来完成一次目录操作：\(operation)"
    }

    private func iso8601String(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    private func expireCatalogWriteAccessRequest(id: UUID) {
        guard writeAccessStates[id] == .pending || writeAccessStates[id] == .authenticating else { return }
        writeAccessStates[id] = .expired
        Task { await catalogAgentWriteAuthorization.revoke(requestID: id) }
        writeAccessNotifier.notifyQueueChanged(requestID: id)
        writeAccessContinuations[id]?.resume(throwing: VaultAppServicesRevealError.revealUnavailable)
    }

    private func cancelCatalogWriteAccessRequest(id: UUID) {
        guard writeAccessStates[id] == .pending || writeAccessStates[id] == .authenticating else { return }
        writeAccessStates[id] = .cancelled
        Task { await catalogAgentWriteAuthorization.revoke(requestID: id) }
        writeAccessNotifier.notifyQueueChanged(requestID: id)
        writeAccessContinuations[id]?.resume(throwing: CancellationError())
    }

    private func pruneWriteAccessStates() {
        guard writeAccessStates.count > 128 else { return }
        let terminal = writeAccessStates.filter {
            switch $0.value {
            case .approved, .consumed, .denied, .expired, .cancelled: return true
            case .pending, .authenticating: return false
            }
        }
        for id in terminal.keys.prefix(writeAccessStates.count - 128) {
            writeAccessStates.removeValue(forKey: id)
        }
    }

    public func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let store = try await selectedCatalogStoreForApp()
        do {
            let snapshot = try await store.createIndex(
                title: title,
                aliases: aliases,
                tags: tags,
                expectedRevision: expectedRevision
            )
            let result = CatalogWriteResult(revision: snapshot.revision)
            await emitAudit(action: "创建目录分组", target: "catalog", referenceCount: 0, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                throw catalogAgentError(for: error)
            }
            do {
                let current = try await store.snapshot()
                let snapshot = try await store.createIndex(
                    title: title,
                    aliases: aliases,
                    tags: tags,
                    expectedRevision: current.revision
                )
                let result = CatalogWriteResult(revision: snapshot.revision)
                await emitAudit(action: "创建目录分组", target: "catalog", referenceCount: 0, result: "成功", operation: .catalogMutation)
                return result
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: retryError)
            }
        }
    }

    public func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let store = try await selectedCatalogStoreForApp()
        if request.fields.contains(where: { $0.type.isSecret && $0.value != nil }) {
            try catalogMutationPolicyEngine.requireSilent(
                CatalogMutationDescriptor(kind: .plaintextSecretInCatalog)
            )
        }
        for reference in request.fields.compactMap(\.secretRef) {
            guard (try? SecretReference(reference)) != nil else {
                try catalogMutationPolicyEngine.requireSilent(
                    CatalogMutationDescriptor(kind: .forgedSecretReference)
                )
                throw SecretCatalogAgentError.invalidOperation
            }
        }
        guard request.fields.allSatisfy({ $0.secretRef == nil }) else {
            throw SecretCatalogAgentError.approvalRequired
        }
        let entry = try SecretCatalogEntry.generated(
            indexId: request.indexID,
            title: request.title,
            type: request.type,
            aliases: request.aliases,
            endpoints: request.endpoints,
            fields: request.fields,
            notes: request.notes,
            tags: request.tags
        )
        do {
            let snapshot = try await store.createEntry(entry, expectedRevision: expectedRevision)
            let result = CatalogWriteResult(
                revision: snapshot.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
            )
            await emitAudit(action: "创建目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                throw catalogAgentError(for: error)
            }
            do {
                let current = try await store.snapshot()
                let snapshot = try await store.createEntry(entry, expectedRevision: current.revision)
                let result = CatalogWriteResult(
                    revision: snapshot.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
                )
                await emitAudit(action: "创建目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
                return result
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: retryError)
            }
        }
    }

    public func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        guard snapshot.document.entries.contains(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }

        var entries = snapshot.document.entries
        guard let offset = entries.firstIndex(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        entries[offset] = entry
        let next: SecretCatalogDocument
        do {
            next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
            try next.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        try await authorizeCatalogDiff(
            diff,
            transport: .directManagedFileWrite,
            requireAgentSafeWrite: false
        )

        do {
            let updated = try await catalogDocumentStore!.updateEntry(entry, expectedRevision: expectedRevision)
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
            await emitAudit(action: "修改目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    /// Commit one App entry edit together with any newly entered secret
    /// values. Plaintext is consumed here and never becomes a Catalog value;
    /// newly-created records are deleted again if the catalog commit fails.
    public func catalogCommitEntryEdit(
        _ entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        // A request-owned Secure Input transaction is the only path allowed
        // to consume plaintext for its Entry. Blocking the generic editor for
        // the lifetime of the request closes the stale-Sheet race.
        guard !pendingSecureInputRequests.values.contains(where: { $0.entryID == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let snapshot = try await catalogSnapshotForAgent()
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        guard let currentEntry = snapshot.document.entries.first(where: { $0.id == entry.id }),
              currentEntry.indexId == entry.indexId
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        var inputsByKey: [String: CatalogSecretInput] = [:]
        for input in secretInputs {
            guard !input.key.isEmpty,
                  !input.label.isEmpty,
                  !input.plaintext.isEmpty,
                  inputsByKey[input.key] == nil
            else {
                throw SecretCatalogAgentError.invalidOperation
            }
            inputsByKey[input.key] = input
        }

        guard Set(entry.fields.map(\.key)).count == entry.fields.count else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let currentFields = Dictionary(uniqueKeysWithValues: currentEntry.fields.map { ($0.key, $0) })
        let candidateFields = Dictionary(uniqueKeysWithValues: entry.fields.map { ($0.key, $0) })
        for input in secretInputs {
            guard let candidateField = candidateFields[input.key],
                  candidateField.type.isSecret
            else {
                // Filling, converting, and replacing all require a local
                // plaintext input; an opaque reference can never be smuggled
                // through this transaction.
                throw SecretCatalogAgentError.invalidOperation
            }
        }

        for field in entry.fields {
            let oldReference = currentFields[field.key]?.secretRef
            if field.secretRef != oldReference {
                if field.secretRef != nil && inputsByKey[field.key] == nil {
                    // A new opaque reference must be created by this request,
                    // never smuggled in as ordinary Entry metadata.
                    throw SecretCatalogAgentError.invalidOperation
                }
                if oldReference != nil && inputsByKey[field.key] == nil {
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
        }

        let draftFields = entry.fields.map { field in
            guard inputsByKey[field.key] != nil else { return field }
            return SecretCatalogFieldValue(
                key: field.key,
                label: field.label,
                type: field.type,
                agentVisible: field.agentVisible,
                searchable: field.searchable,
                secretRef: nil
            )
        }
        let draftEntry = SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: entry.title,
            type: entry.type,
            aliases: entry.aliases,
            endpoints: entry.endpoints,
            fields: draftFields,
            notes: entry.notes,
            tags: entry.tags,
            schema: entry.schema
        )
        var draftEntries = snapshot.document.entries
        guard let entryOffset = draftEntries.firstIndex(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        draftEntries[entryOffset] = draftEntry
        let draftDocument: SecretCatalogDocument
        do {
            draftDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: draftEntries)
            try draftDocument.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }

        let draftDiff = CatalogSemanticDiff.between(old: snapshot.document, new: draftDocument)
        try await authorizeCatalogDiff(
            draftDiff,
            transport: .directManagedFileWrite,
            requireAgentSafeWrite: false
        )

        guard !secretInputs.isEmpty else {
            guard !pendingSecureInputRequests.values.contains(where: { $0.entryID == entry.id }) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            do {
                let updated = try await catalogDocumentStore!.updateEntry(entry, expectedRevision: expectedRevision)
                let result = CatalogWriteResult(
                    revision: updated.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
                )
                await emitAudit(action: "修改目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
                return result
            } catch let error as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: error)
            }
        }

        guard recordDeleter != nil else {
            throw SecretCatalogAgentError.invalidOperation
        }

        var createdReferences: [SecretReference] = []
        do {
            for input in secretInputs {
                let reference = try await textEncryptor.encryptText(
                    input.plaintext,
                    label: input.label,
                    policy: .credential
                )
                createdReferences.append(reference)
            }

            // Match generated references to input keys by position rather than
            // exposing any plaintext in a temporary model or error.
            let referencesByKey = Dictionary(uniqueKeysWithValues: zip(secretInputs.map(\.key), createdReferences).map { ($0.0, $0.1) })
            let boundFields = entry.fields.map { field in
                guard let reference = referencesByKey[field.key] else { return field }
                return SecretCatalogFieldValue(
                    key: field.key,
                    label: field.label,
                    type: field.type,
                    agentVisible: field.agentVisible,
                    searchable: field.searchable,
                    secretRef: reference.description
                )
            }
            let finalEntry = SecretCatalogEntry(
                id: entry.id,
                indexId: entry.indexId,
                title: entry.title,
                type: entry.type,
                aliases: entry.aliases,
                endpoints: entry.endpoints,
                fields: boundFields,
                notes: entry.notes,
                tags: entry.tags,
                schema: entry.schema
            )
            var finalEntries = snapshot.document.entries
            finalEntries[entryOffset] = finalEntry
            let finalDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: finalEntries)
            try finalDocument.validate()

            // The actor may have been re-entered while authorizing or
            // encrypting. Re-check immediately before the store call so a
            // Secure Input request that began in that window cannot be
            // bypassed by this generic plaintext-consuming editor.
            guard !pendingSecureInputRequests.values.contains(where: { $0.entryID == entry.id }) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            let updated = try await catalogDocumentStore!.updateEntry(finalEntry, expectedRevision: expectedRevision)
            await notifySavedReferencesChanged()
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
            await emitAudit(
                action: "修改目录条目并写入凭据",
                target: "catalog",
                referenceCount: createdReferences.count,
                result: "成功",
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .catalogMutation
            )
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            if let cleanupError = await compensateCreatedReferences(createdReferences) {
                throw cleanupError
            }
            throw catalogAgentError(for: error)
        } catch {
            if let cleanupError = await compensateCreatedReferences(createdReferences) {
                throw cleanupError
            }
            throw error
        }
    }

    public func catalogApplyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await performCatalogBatch(
            mutation,
            expectedRevision: expectedRevision,
            requireAgentSafeWrite: false
        )
    }

    public func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let parsed: SecretReference
        do {
            parsed = try SecretReference(secretRef)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }

        let metadata: [SecretPolicyMetadata]
        do {
            metadata = try await policyMetadata(for: [parsed])
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let descriptor = SecretOperationDescriptor(
            actionType: .changeDestinationBinding,
            secretReferences: [parsed],
            requestedEffects: ["bind-catalog-entry"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)

        let snapshot = try await catalogSnapshotForAgent()
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        do {
            let updated = try await catalogDocumentStore!.bindSecret(
                parsed.description,
                toFieldKey: key,
                entryID: entryID,
                expectedRevision: expectedRevision
            )
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updated.document).matches.first?.entry
            )
            await emitAudit(action: "绑定目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .writeFailed:
                throw SecretCatalogAgentError.writeFailed
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        }
    }

    public func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64) {
        guard !plaintext.isEmpty else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let snapshot = try await catalogSnapshotForAgent()
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              let field = entry.fields.first(where: { $0.key == key }),
              field.type.isSecret
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let secret = try await textEncryptor.encryptText(plaintext, label: label, policy: policy)
        do {
            if field.secretRef != nil {
                let replacementFields = entry.fields.map { currentField in
                    guard currentField.key == key else { return currentField }
                    return SecretCatalogFieldValue(
                        key: currentField.key,
                        label: currentField.label,
                        type: currentField.type,
                        agentVisible: currentField.agentVisible,
                        searchable: currentField.searchable,
                        value: nil,
                        secretRef: secret.description
                    )
                }
                var candidateEntries = snapshot.document.entries
                guard let entryOffset = candidateEntries.firstIndex(where: { $0.id == entry.id }) else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                candidateEntries[entryOffset] = SecretCatalogEntry(
                    id: entry.id,
                    indexId: entry.indexId,
                    title: entry.title,
                    type: entry.type,
                    aliases: entry.aliases,
                    endpoints: entry.endpoints,
                    fields: replacementFields,
                    notes: entry.notes,
                    tags: entry.tags,
                    schema: entry.schema
                )
                let candidate = SecretCatalogDocument(
                    indexes: snapshot.document.indexes,
                    entries: candidateEntries
                )
                try candidate.validate()
                let diff = CatalogSemanticDiff.between(old: snapshot.document, new: candidate)
                guard diff.changes.contains(where: {
                    $0.kind == .replaceSecret
                        && $0.entryID == entryID
                        && $0.fieldKey == key
                        && $0.oldSecretRef == field.secretRef
                        && $0.newSecretRef == secret.description
                }) else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                try await authorizeCatalogDiff(
                    diff,
                    transport: .directManagedFileWrite,
                    requireAgentSafeWrite: false,
                    requestedEffect: "catalog-replace-secret"
                )
            }

            let updated = try await catalogDocumentStore!.bindSecret(
                secret.description,
                toFieldKey: key,
                entryID: entryID,
                expectedRevision: snapshot.revision
            )
            await emitAudit(action: "写入目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
            return (secret.description, updated.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                if let cleanupError = await compensateCreatedReferences([secret]) {
                    throw cleanupError
                }
                throw catalogAgentError(for: error)
            }

            // Filling an empty placeholder is safe to retry with the same
            // already-encrypted reference. Never overwrite a concurrent bind.
            let current: SensitiveCatalogSnapshot
            do {
                current = try await catalogSnapshotForAgent()
            } catch {
                if let cleanupError = await compensateCreatedReferences([secret]) {
                    throw cleanupError
                }
                throw error
            }
            guard let currentEntry = current.document.entries.first(where: { $0.id == entryID }),
                  let currentField = currentEntry.fields.first(where: { $0.key == key }),
                  currentField.type.isSecret,
                  currentField.secretRef == nil
            else {
                if let cleanupError = await compensateCreatedReferences([secret]) {
                    throw cleanupError
                }
                throw SecretCatalogAgentError.revisionConflict
            }
            do {
                let updated = try await catalogDocumentStore!.bindSecret(
                    secret.description,
                    toFieldKey: key,
                    entryID: entryID,
                    expectedRevision: current.revision
                )
                await emitAudit(action: "写入目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
                return (secret.description, updated.revision)
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                if let cleanupError = await compensateCreatedReferences([secret]) {
                    throw cleanupError
                }
                throw catalogAgentError(for: retryError)
            }
        } catch {
            if let cleanupError = await compensateCreatedReferences([secret]) {
                throw cleanupError
            }
            throw error
        }
    }

    /// Reveals one catalog secret field to the local App only.  The field
    /// identity is resolved from the current verified catalog; callers cannot
    /// provide an arbitrary reference or ask the MCP channel for plaintext.
    /// Every reveal goes through the normal device-owner approval path and
    /// resolves the record with fresh key material when the production key
    /// provider is in use.
    public func catalogRevealField(entryID: String, key: String) async throws -> String {
        let snapshot = try await catalogSnapshotForAgent()
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              let field = entry.fields.first(where: { $0.key == key }),
              field.type.isSecret,
              let secretRef = field.secretRef
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let context = RevealContext(
            reason: "查看敏感信息目录密码字段",
            template: "{{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")],
            destination: "local-app"
        )
        let (descriptor, metadata) = try await plaintextOperation(
            action: .revealPlaintext,
            references: [secretRef],
            context: context,
            effects: ["display-to-local-user"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)

        // Keep the one-field result in the App's caller memory only. The
        // audit event contains no reference ID or resolved value.
        let plaintext = try await resolveReferences(
            references: [secretRef],
            context: context,
            forceFreshAuthorization: true
        )
        await emitAudit(
            action: "本机显示目录凭据",
            target: "catalog-field",
            referenceCount: 1,
            result: "已显示",
            context: AuditContext.current ?? AuditContext(source: .app),
            operation: .reveal,
            authorizationOutcome: .approved,
            status: .displayedToUser
        )
        return plaintext
    }

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .revealPlaintext,
            references: references,
            context: context,
            effects: ["display-to-local-user"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let resolvedParagraph = try await resolveReferencesWithValues(references: references, context: context)
        let sessionID = await revealSessionStore.create(resolvedParagraph: resolvedParagraph)
        await revealSessionPresenter.present(sessionID: sessionID, store: revealSessionStore)
        await emitAudit(
            action: "本机显示明文",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "已显示"
        )
        return sessionID
    }

    public func pendingRevealSessionIDs() async throws -> [String] {
        await revealSessionStore.sessionIDs()
    }

    public func revealSessionData(sessionID: String) async throws -> RestoredParagraph {
        guard let restoredParagraph = await revealSessionStore.restoredParagraph(id: sessionID) else {
            throw VaultAppServicesRevealError.sessionNotFound
        }
        return restoredParagraph
    }

    public func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .copyPlaintext,
            references: references,
            context: context,
            effects: ["local-write-back"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let restored = try await resolveReferencesWithValues(references: references, context: context)
        await emitAudit(
            action: "本机脱密使用",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "成功",
            operation: .credentialUse
        )
        return restored.text
    }

    public func restoreReferencesWithValues(
        references: [String],
        context: RevealContext
    ) async throws -> RestoredParagraph {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .copyPlaintext,
            references: references,
            context: context,
            effects: ["local-write-back"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let restored = try await resolveReferencesWithValues(references: references, context: context)
        await emitAudit(
            action: "本机脱密使用",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "成功",
            operation: .credentialUse
        )
        return restored
    }

    public func exportResolvedText(
        references: [String],
        context: RevealContext,
        destinationPath: String
    ) async throws -> String {
        let destination = try validatedExportDestination(destinationPath)
        let operationContext = RevealContext(
            reason: context.reason,
            template: context.template,
            ranges: context.ranges,
            destination: destination.path
        )
        let (descriptor, metadata) = try await plaintextOperation(
            action: .exportPlaintext,
            references: references,
            context: operationContext,
            effects: ["write-local-file"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let resolvedText = try await resolveReferences(
            references: references,
            context: operationContext,
            forceFreshAuthorization: true
        )
        try resolvedText.write(to: destination, atomically: true, encoding: .utf8)
        await emitAudit(
            action: "写入本地文件",
            target: "local-export",
            referenceCount: references.count,
            result: "成功"
        )
        return destination.path
    }

    private func policyMetadata(
        for references: [SecretReference]
    ) async throws -> [SecretPolicyMetadata] {
        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        var metadata: [SecretPolicyMetadata] = []
        metadata.reserveCapacity(references.count)
        for reference in references {
            let recordMetadata = try await recordResolver.metadata(reference: reference.description)
            metadata.append(
                SecretPolicyMetadata(
                    reference: reference,
                    policy: recordMetadata.policy,
                    label: recordMetadata.label,
                    allowedDestinations: recordMetadata.allowedDestinations,
                    allowedProtocols: recordMetadata.allowedProtocols
                )
            )
        }
        return metadata
    }

    private func plaintextOperation(
        action: SecretOperationAction,
        references: [String],
        context: RevealContext,
        effects: [String]
    ) async throws -> (SecretOperationDescriptor, [SecretPolicyMetadata]) {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let parsedReferences: [SecretReference]
        do {
            parsedReferences = try references.map(SecretReference.init)
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }
        try validateRevealContext(context, referenceCount: parsedReferences.count)
        let metadata = try await policyMetadata(for: parsedReferences)
        let descriptor = SecretOperationDescriptor(
            actionType: action,
            secretReferences: parsedReferences,
            destination: context.destination,
            requestedEffects: effects,
            agentAssessment: context.agentAssessment
        )
        return (descriptor, metadata)
    }

    private func authorizeIfNeeded(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision
    ) async throws {
        switch decision.risk {
        case .silent:
            return
        case .denied:
            throw SecretOperationError.operationDenied
        case .approvalRequired:
            break
        }

        await emitAudit(
            action: "本机授权请求",
            target: decision.normalizedDestination ?? "local",
            referenceCount: descriptor.secretReferences.count,
            result: "请求中",
            operation: .authorization,
            authorizationOutcome: .requested,
            status: .requested
        )
        let ticket = await approvalTicketStore.issue(for: descriptor, now: now())
        let summary = approvalSummary(descriptor: descriptor, metadata: metadata, decision: decision)
        approvalPending = true
        await statusObserver?(status())

        do {
            try await approveWithTimeout(summary: summary)
            guard await approvalTicketStore.consume(ticket, for: descriptor, now: now()) else {
                throw SecretOperationError.operationDenied
            }
            await emitAudit(
                action: "本机授权完成",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "成功",
                operation: .authorization,
                authorizationOutcome: .approved
            )
        } catch let error as SecretOperationError {
            approvalPending = false
            await statusObserver?(status())
            await emitAudit(
                action: "本机授权失败",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .authorization,
                authorizationOutcome: .denied,
                status: .failure
            )
            throw error
        } catch let error as OperationAuthorizationError {
            approvalPending = false
            await statusObserver?(status())
            switch error {
            case .cancelled:
                await emitAudit(action: "本机授权取消", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已取消", operation: .authorization, authorizationOutcome: .cancelled, status: .cancelled)
                throw SecretOperationError.authorizationCancelled
            case .denied:
                await emitAudit(action: "本机授权拒绝", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已拒绝", operation: .authorization, authorizationOutcome: .denied, status: .failure)
                throw SecretOperationError.authorizationDenied
            case .timeout:
                await emitAudit(action: "本机授权超时", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已超时", operation: .authorization, authorizationOutcome: .expired, status: .expired)
                throw SecretOperationError.authorizationTimeout
            case .unavailable:
                await emitAudit(action: "本机授权不可用", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "失败", operation: .authorization, authorizationOutcome: .denied, status: .failure)
                throw SecretOperationError.authorizationUnavailable
            }
        } catch {
            approvalPending = false
            await statusObserver?(status())
            await emitAudit(
                action: "本机授权失败",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .authorization,
                authorizationOutcome: .denied,
                status: .failure
            )
            throw SecretOperationError.authorizationDenied
        }

        approvalPending = false
        await statusObserver?(status())
    }

    private func approveWithTimeout(summary: String) async throws {
        let approver = operationApprover
        let timeout = operationApprovalTimeout
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await approver.approve(summary: summary)
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw OperationAuthorizationError.timeout
            }
            defer { group.cancelAll() }
            try await group.next()
        }
    }

    private func authorizeCatalogDiff(
        _ diff: CatalogSemanticDiff,
        transport: CatalogMutationKind,
        requireAgentSafeWrite: Bool = true,
        requestedEffect: String = "catalog-semantic-approval"
    ) async throws {
        let catalogDecision = catalogMutationPolicyEngine.evaluate(diff, transport: transport)
        switch catalogDecision {
        case .denied:
            throw SecretOperationError.operationDenied
        case .silent:
            if requireAgentSafeWrite {
                // A caller that still asks for the removed global gate is a
                // legacy path. It must not silently inherit an approved
                // ticket; every Agent mutation is authorized above with an
                // exact intent.
                throw SecretCatalogAgentError.agentWriteNotAllowed
            }
        case .approvalRequired:
            let references: [SecretReference]
            do {
                references = try diff.referencedSecretRefs.map(SecretReference.init)
            } catch {
                throw SecretCatalogAgentError.invalidOperation
            }

            let descriptor: SecretOperationDescriptor
            let metadata: [SecretPolicyMetadata]
            if references.isEmpty {
                descriptor = SecretOperationDescriptor(
                    actionType: .changeAuthorizationRules,
                    requestedEffects: [requestedEffect]
                )
                metadata = []
            } else {
                do {
                    metadata = try await policyMetadata(for: references)
                } catch {
                    throw SecretCatalogAgentError.invalidOperation
                }
                descriptor = SecretOperationDescriptor(
                    actionType: diff.changesSecretTarget ? .changeDestinationBinding : .changeSecretPolicy,
                    secretReferences: references,
                    requestedEffects: [requestedEffect]
                )
            }
            let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
            try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        }
    }

    private func approvalSummary(
        descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision
    ) -> String {
        let labels = metadata.compactMap(\.label)
            .map(safeDisplayLabel)
            .filter { !$0.isEmpty }
        let labelText = labels.isEmpty ? "未命名凭据" : labels.prefix(3).joined(separator: "、")
        let target = safeDisplayLabel(decision.normalizedDestination ?? "本机")
        let detail = safeDisplayLabel(operationDetail(for: descriptor))
        return "SVLT 请求本机审批：\(displayName(for: descriptor))；操作：\(detail)；目标：\(target)；凭据：\(labelText)"
    }

    private func displayName(for descriptor: SecretOperationDescriptor) -> String {
        if descriptor.requestedEffects.contains("catalog-replace-secret") {
            return "替换目录密码"
        }
        return displayName(for: descriptor.actionType)
    }

    private func operationDetail(for descriptor: SecretOperationDescriptor) -> String {
        switch descriptor.actionType {
        case .sshCommand:
            return descriptor.command ?? "未提供命令"
        case .httpRequest, .apiRequest, .browserLogin:
            let method = (descriptor.httpMethod ?? "GET").uppercased()
            return "\(method) \(descriptor.normalizedPath ?? "/")"
        case .databaseQuery:
            return descriptor.databaseStatement?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" })
                .first
                .map(String.init) ?? "数据库查询"
        case .sftpTransfer:
            return "\(descriptor.fileOperation?.rawValue ?? "transfer") \(descriptor.fileTarget ?? "远程目标")"
        case .localAppFill:
            return descriptor.localAppBundleID ?? "本地 App 表单"
        default:
            return "受保护操作"
        }
    }

    private func displayName(for action: SecretOperationAction) -> String {
        switch action {
        case .revealPlaintext:
            return "显示明文"
        case .copyPlaintext:
            return "本机写回明文"
        case .exportPlaintext:
            return "导出明文"
        case .deleteSecret:
            return "删除加密记录"
        case .changeSecretPolicy, .changeDestinationBinding, .changeAllowlist,
             .changeAuthorizationRules, .changeKeychain:
            return "修改安全设置"
        case .sshCommand:
            return "执行 SSH 操作"
        case .httpRequest, .apiRequest:
            return "发送 HTTP/API 请求"
        case .databaseQuery:
            return "执行数据库操作"
        case .sftpTransfer:
            return "执行 SFTP 操作"
        default:
            return "执行受保护操作"
        }
    }

    private func safeDisplayLabel(_ value: String) -> String {
        String(value
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .prefix(80))
    }

    private func operationReason(for descriptor: SecretOperationDescriptor) -> String {
        switch descriptor.actionType {
        case .sshCommand:
            return "智能体 SSH 操作"
        case .httpRequest, .apiRequest:
            return "智能体 HTTP/API 操作"
        case .databaseQuery:
            return "智能体数据库操作"
        case .sftpTransfer:
            return "智能体 SFTP 操作"
        default:
            return "智能体受保护操作"
        }
    }

    private func resolveReferences(
        references: [String],
        context: RevealContext,
        forceFreshAuthorization: Bool = false
    ) async throws -> String {
        try await resolveReferencesWithValues(
            references: references,
            context: context,
            forceFreshAuthorization: forceFreshAuthorization
        ).text
    }

    private func resolveReferencesWithValues(
        references: [String],
        context: RevealContext,
        forceFreshAuthorization: Bool = false
    ) async throws -> RestoredParagraph {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let validatedReferences: [String]
        do {
            validatedReferences = try references.map { try SecretReference($0).description }
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }

        try validateRevealContext(context, referenceCount: validatedReferences.count)

        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        var metadata: [SecretReferenceMetadata] = []
        metadata.reserveCapacity(validatedReferences.count)
        for reference in validatedReferences {
            metadata.append(try await recordResolver.metadata(reference: reference))
        }
        let operationPolicy = authorizationPolicy(for: metadata.map(\.policy))
        let operationMasterKey = try await resolvedMasterKey(
            for: operationPolicy,
            reason: context.reason,
            allowsAgentDecryptReuse: !forceFreshAuthorization,
            destination: context.destination,
            forceFresh: forceFreshAuthorization
        )

        var plaintexts: [String] = []
        plaintexts.reserveCapacity(validatedReferences.count)
        for reference in validatedReferences {
            let data = try await recordResolver.resolve(reference: reference, masterKey: operationMasterKey)
            guard let plaintext = String(data: data, encoding: .utf8) else {
                throw VaultAppServicesRevealError.invalidResolvedPlaintext
            }
            plaintexts.append(plaintext)
        }

        return RestoredParagraph(
            text: try resolveTemplate(context.template, ranges: context.ranges, plaintexts: plaintexts),
            values: plaintexts
        )
    }

    private func authorizationPolicy(for policies: [SecretPolicy]) -> SecretPolicy {
        if policies.contains(.credential) {
            return .credential
        }
        if policies.contains(.externalSend) {
            return .externalSend
        }
        return .read
    }

    private func resolvedMasterKey(
        for policy: SecretPolicy,
        reason: String,
        allowsAgentDecryptReuse: Bool = false,
        destination: String? = nil,
        forceFresh: Bool = false
    ) async throws -> SymmetricKey {
        if let masterKey {
            return masterKey
        }

        if allowsAgentDecryptReuse,
           !forceFresh,
           let cacheKey = authorizationCacheKey(policy: policy, destination: destination),
           let cached = cachedAgentDecryptAuthorization(cacheKey: cacheKey),
           await consumeCachedAuthorization(policy: policy, destination: destination) {
            return cached.key
        }

        let key: SymmetricKey
        if forceFresh, let freshMasterKeyProvider {
            key = try await freshMasterKeyProvider(policy, reason)
        } else if let masterKeyProvider {
            key = try await masterKeyProvider(policy, reason)
        } else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        if allowsAgentDecryptReuse,
           !forceFresh,
           let cacheKey = authorizationCacheKey(policy: policy, destination: destination) {
            await authorizeCachedOperation(policy: policy, destination: destination)
            cacheAgentDecryptAuthorization(
                key: key,
                policy: policy,
                destination: destination,
                cacheKey: cacheKey
            )
        }
        return key
    }

    private func freshMasterKey(
        for policy: SecretPolicy,
        reason: String
    ) async throws -> SymmetricKey {
        if let masterKey {
            return masterKey
        }
        if let freshMasterKeyProvider {
            return try await freshMasterKeyProvider(policy, reason)
        }
        guard let masterKeyProvider else {
            throw VaultAppServicesRevealError.revealUnavailable
        }
        return try await masterKeyProvider(policy, reason)
    }

    private func authorizationCacheKey(
        policy: SecretPolicy,
        destination: String?
    ) -> String? {
        switch policy {
        case .read:
            return "read"
        case .credential:
            return "credential"
        case .externalSend:
            guard let destination, !destination.isEmpty else {
                return nil
            }
            return "externalSend:\(destination)"
        }
    }

    private func consumeCachedAuthorization(
        policy: SecretPolicy,
        destination: String?
    ) async -> Bool {
        switch policy {
        case .read:
            return await authorizationSession.consumeAuthorization(for: .read)
        case .credential:
            return await authorizationSession.consumeCredential()
        case .externalSend:
            guard let destination else {
                return false
            }
            return await authorizationSession.consumeExternalSend(destination: destination)
        }
    }

    private func authorizeCachedOperation(
        policy: SecretPolicy,
        destination: String?
    ) async {
        switch policy {
        case .read:
            await authorizationSession.authorizeRead()
        case .credential:
            await authorizationSession.authorizeCredential()
        case .externalSend:
            if let destination {
                await authorizationSession.authorizeExternalSend(destination: destination)
            }
        }
    }

    private func cachedAgentDecryptAuthorization(cacheKey: String) -> AgentDecryptAuthorization? {
        guard let authorization = agentDecryptAuthorizations[cacheKey] else {
            return nil
        }
        guard now() < authorization.expiresAt else {
            agentDecryptAuthorizations[cacheKey] = nil
            return nil
        }
        return authorization
    }

    private func cacheAgentDecryptAuthorization(
        key: SymmetricKey,
        policy: SecretPolicy,
        destination: String?,
        cacheKey: String
    ) {
        let expiresAt: Date
        switch policy {
        case .read:
            expiresAt = agentDecryptAuthorizationTTL.map {
                now().addingTimeInterval($0)
            } ?? .distantFuture
        case .credential:
            guard credentialAuthorizationTTL > 0 else {
                agentDecryptAuthorizations[cacheKey] = nil
                return
            }
            expiresAt = now().addingTimeInterval(credentialAuthorizationTTL)
        case .externalSend:
            guard externalSendAuthorizationTTL > 0 else {
                agentDecryptAuthorizations[cacheKey] = nil
                return
            }
            expiresAt = now().addingTimeInterval(externalSendAuthorizationTTL)
        }
        agentDecryptAuthorizations[cacheKey] = AgentDecryptAuthorization(
            key: key,
            policy: policy,
            destination: destination,
            expiresAt: expiresAt
        )
    }

    private func isPluginConnected() -> Bool {
        guard let pluginConnectedAt else {
            return false
        }
        return now().timeIntervalSince(pluginConnectedAt) < 15
    }

    private func notifySavedReferencesChanged() async {
        guard let savedReferencesObserver,
              let references = try? await savedSecretReferences()
        else {
            return
        }
        await savedReferencesObserver(references)
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        guard let recordLister else {
            throw VaultAppServicesOrphanScanError.scanUnavailable
        }

        let markdownReferenceSet = Set(markdownReferences.compactMap(Self.canonicalReference))
        let storedReferenceSet = Set(try await recordLister.recordIDs().map { "secret://\($0)" })

        let result = OrphanScanResult(
            missingRecords: Array(markdownReferenceSet.subtracting(storedReferenceSet)).sorted(),
            unreferencedRecords: Array(storedReferenceSet.subtracting(markdownReferenceSet)).sorted()
        )
        await orphanScanObserver?(result)
        await emitAudit(
            action: "扫描知识库引用",
            target: "当前知识库",
            referenceCount: markdownReferenceSet.count,
            result: "成功"
        )
        return result
    }

    /// Retries durable compensation entries. The returned IDs are still
    /// unresolved and remain persisted for a later run; no secret value is
    /// loaded or included in the result.
    public func reconcilePendingCatalogSecretCleanup() async throws -> [String] {
        guard let catalogDocumentStore else {
            throw SecretCatalogAgentError.unavailable
        }
        let pending = try await catalogDocumentStore.pendingSecretCleanupReferenceIDs()
        guard !pending.isEmpty else { return [] }

        // Cleanup metadata is authenticated, but it is still only a recovery
        // hint. Re-read the current accepted Catalog before every deletion
        // pass and refuse to delete a record that has since become referenced.
        // A pending external change makes the accepted state unavailable, so
        // snapshot() fails closed and no deletion is attempted.
        let current = try await catalogDocumentStore.snapshot()
        let referencedIDs = Set(current.document.entries.flatMap { entry in
            entry.fields.compactMap { field in
                field.secretRef.flatMap { try? SecretReference($0).id }
            }
        })
        let referencedPending = pending.filter { referencedIDs.contains($0) }
        var orphanPending = pending.filter { !referencedIDs.contains($0) }
        var resolved = referencedPending

        guard let recordDeleter else {
            if !resolved.isEmpty {
                try await catalogDocumentStore.clearPendingSecretCleanup(referenceIDs: resolved)
            }
            return orphanPending
        }

        var remaining: [String] = []
        for id in orphanPending {
            do {
                try await recordDeleter.delete(id: id)
                resolved.append(id)
            } catch {
                remaining.append(id)
            }
        }
        if !resolved.isEmpty {
            try await catalogDocumentStore.clearPendingSecretCleanup(referenceIDs: resolved)
        }
        await notifySavedReferencesChanged()
        orphanPending = remaining
        return orphanPending
    }

    private static func canonicalReference(_ reference: String) -> String? {
        try? SecretReference(reference).description
    }

    private func validatedExportDestination(_ destinationPath: String) throws -> URL {
        guard destinationPath.hasPrefix("/") else {
            throw VaultAppServicesExportError.invalidDestination
        }

        let destination = URL(fileURLWithPath: destinationPath).standardizedFileURL
        let exportRoot = exportDirectory.standardizedFileURL
        let allowedExtensions = Set(["md", "txt"])
        let fileExtension = destination.pathExtension.lowercased()
        let fileName = destination.lastPathComponent

        guard !fileName.isEmpty,
              fileName != ".",
              fileName != "..",
              allowedExtensions.contains(fileExtension)
        else {
            throw VaultAppServicesExportError.invalidDestination
        }

        guard destination.deletingLastPathComponent().standardizedFileURL.path == exportRoot.path else {
            throw VaultAppServicesExportError.destinationNotAllowed
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: exportRoot.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            throw VaultAppServicesExportError.invalidDestination
        }

        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw VaultAppServicesExportError.fileAlreadyExists
        }

        return destination
    }

    private static func defaultExportDirectory() -> URL {
        FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop", isDirectory: true)
    }

    private func emitAudit(
        action: String,
        target: String,
        referenceCount: Int,
        result: String,
        context: AuditContext? = nil,
        operation: AuditOperation? = nil,
        authorizationOutcome: AuditAuthorizationOutcome = .notRequired,
        status: AuditStatus? = nil
    ) async {
        let entry = AgentAutomationAuditEntry(
            action: action,
            target: target,
            referenceCount: referenceCount,
            result: result
        )
        await auditObserver?(entry)
        // A production request always arrives through one of the two IPC
        // handlers, which installs AuditContext.current. Do not infer `.agent`
        // here: an unscoped event cannot be safely attributed to a caller.
        guard let auditContext = context ?? AuditContext.current else {
            return
        }
        guard let auditLog else {
            return
        }
        let event = AuditEvent(
            timestamp: entry.occurredAt,
            source: auditContext.source,
            integration: auditContext.source == .app ? "agent-secret-vault-app-control" : "agent-secret-vault-mcp",
            correlationID: auditContext.correlationID,
            requestID: auditContext.requestID,
            referenceID: nil,
            referenceCount: referenceCount,
            operation: operation ?? auditOperation(for: action),
            risk: 0,
            authorizationOutcome: authorizationOutcome,
            declaredTarget: sanitizedAuditTarget(entry.target),
            status: status ?? auditStatus(for: result),
            exitCode: nil
        )
        do {
            // The production daemon supplies an independent Keychain audit key.
            // This call must never go through resolvedMasterKey().
            try await auditLog.append(event)
            recordAuditAppendSuccess()
            CatalogSecurityAuditNotifier.notify()
        } catch {
            // Explicit test callers may have supplied an already-held
            // master key. Never acquire one merely to record a failed audit.
            if let masterKey {
                do {
                    try await auditLog.append(event, masterKey: masterKey)
                    recordAuditAppendSuccess()
                    CatalogSecurityAuditNotifier.notify()
                } catch {
                    // Audit persistence must not make the user operation fail.
                    recordAuditAppendFailure()
                    Self.logAuditAppendFailure()
                }
            }
            if masterKey == nil {
                recordAuditAppendFailure()
                Self.logAuditAppendFailure()
            }
        }
    }

    private func recordAuditAppendFailure() {
        auditAppendGapDetected = true
        if auditAppendFailureAt == nil {
            auditAppendFailureAt = now()
        }
        persistAuditHealth()
    }

    private func recordAuditAppendSuccess() {
        lastSuccessfulAuditSequence &+= 1
        persistAuditHealth()
    }

    private func persistAuditHealth() {
        guard let auditHealthURL else { return }
        let record = CatalogAuditHealthRecord(
            schemaVersion: CatalogAuditHealthRecord.currentSchemaVersion,
            lastFailureAt: auditAppendFailureAt,
            gapDetected: auditAppendGapDetected,
            lastSuccessfulSequence: lastSuccessfulAuditSequence
        )
        do {
            let parentURL = auditHealthURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: parentURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: parentURL.path
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(record)
            try data.write(to: auditHealthURL, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: auditHealthURL.path
            )
        } catch {
            Logger(subsystem: "com.agent-secret-vault.SVLT", category: "audit")
                .error("AUDIT_HEALTH_PERSIST_FAILED")
        }
    }

    private static func loadAuditHealth(from url: URL?) -> CatalogAuditHealthRecord? {
        guard let url,
              let data = try? Data(contentsOf: url),
              let record = try? JSONDecoder().decode(CatalogAuditHealthRecord.self, from: data),
              record.schemaVersion == CatalogAuditHealthRecord.currentSchemaVersion
        else {
            return nil
        }
        return record
    }

    private static func logAuditAppendFailure() {
        // Stable, path-free diagnostics make the failure observable without
        // turning the audit channel into a sensitive-data channel.
        Logger(subsystem: "com.agent-secret-vault.SVLT", category: "audit")
            .error("AUDIT_APPEND_FAILED")
    }

    private func agentAuditContext() -> AuditContext {
        AuditContext.current ?? AuditContext(source: .agent)
    }

    private func appAuditContext() -> AuditContext {
        AuditContext.current ?? AuditContext(source: .app)
    }

    private func emitCatalogMutationStarted(
        action: String,
        referenceCount: Int,
        context: AuditContext
    ) async {
        await emitAudit(
            action: action,
            target: "catalog",
            referenceCount: referenceCount,
            result: "开始",
            context: context,
            operation: .catalogMutation,
            authorizationOutcome: context.requestID == nil ? .notRequired : .approved,
            status: .requested
        )
    }

    private func emitCatalogMutationFailed(
        action: String,
        referenceCount: Int,
        context: AuditContext
    ) async {
        await emitAudit(
            action: action,
            target: "catalog",
            referenceCount: referenceCount,
            result: "失败",
            context: context,
            operation: .catalogMutation,
            authorizationOutcome: context.requestID == nil ? .notRequired : .approved,
            status: .failure
        )
    }

    private func auditOperation(for action: String) -> AuditOperation {
        if action.contains("格式") {
            return action.contains("修复") ? .formatRepair : .formatCheck
        }
        if action.contains("目录") || action.contains("分组") || action.contains("条目") {
            return .catalogMutation
        }
        if action.contains("凭据") || action.contains("密码") {
            return .credentialUse
        }
        if action.contains("显示") || action.contains("脱密") || action.contains("文件") {
            return .reveal
        }
        if action.contains("扫描") || action.contains("连接") || action.contains("元数据") {
            return .status
        }
        return .secureExecute
    }

    private func auditStatus(for result: String) -> AuditStatus {
        if result.contains("显示") {
            return .displayedToUser
        }
        if result.contains("失败") {
            return .failure
        }
        return .completed
    }

    private static func safeAuditEntry(_ event: AuditEvent) -> CatalogSecurityAuditEntry {
        CatalogSecurityAuditEntry(
            id: event.id,
            timestamp: event.timestamp,
            source: event.source,
            operation: event.operation,
            authorizationOutcome: event.authorizationOutcome,
            result: event.status,
            target: safeAuditTarget(event.declaredTarget),
            referenceCount: event.referenceCount
        )
    }

    private func sanitizedAuditTarget(_ target: String) -> String {
        Self.safeAuditTarget(target)
    }

    private static func safeAuditTarget(_ target: String?) -> String {
        guard let target, !target.isEmpty else { return "本机" }
        let normalized = target
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lowercased = normalized.lowercased()
        if lowercased.contains("secret://") || lowercased.contains("token") ||
            lowercased.contains("password") || lowercased.contains("cookie") ||
            lowercased.contains("authorization") || normalized.contains("密码") {
            return "敏感记录"
        }
        if normalized.contains("/") || normalized.contains("\\") ||
            lowercased.contains("http") || lowercased.contains("api") {
            return "受保护目标"
        }
        return String(normalized.prefix(80))
    }

    private func selectedCatalogStoreForApp() async throws -> SensitiveCatalogDocumentStore {
        guard let catalogDocumentStore else {
            throw SecretCatalogAgentError.unavailable
        }
        do {
            let selectedURL: URL?
            if let catalogSelectionStore {
                selectedURL = try catalogSelectionStore.selectedDocumentURL()
            } else {
                selectedURL = await catalogDocumentStore.selectedDocumentURL()
            }
            guard let selectedURL else {
                throw SecretCatalogAgentError.unavailable
            }
            try await catalogDocumentStore.selectDocument(at: selectedURL)
            return catalogDocumentStore
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch let error as SensitiveCatalogDocumentStoreError {
            Self.logCatalogMutationFailure(operation: "catalog-snapshot", phase: .snapshot, error: error)
            switch error {
            case .legacyCatalogUnsupported:
                throw SecretCatalogAgentError.legacyCatalogUnsupported
            case .integrityMissing:
                throw SecretCatalogAgentError.integrityMissing
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
            case .pendingExternalChange:
                throw SecretCatalogAgentError.pendingExternalChange
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    /// Keep App-control errors stable so the UI can distinguish a stale
    /// revision from an invalid document and retry only the safe case.
    private func catalogAgentError(
        for error: SensitiveCatalogDocumentStoreError
    ) -> SecretCatalogAgentError {
        switch error {
        case .noSelectedDocument:
            return .unavailable
        case .legacyCatalogUnsupported:
            return .legacyCatalogUnsupported
        case .integrityMissing:
            return .integrityMissing
        case .externalModification:
            return .externalModification
        case .pendingExternalChange:
            return .pendingExternalChange
        case .revisionConflict:
            return .revisionConflict
        case .formatRepairConflict:
            return .formatRepairConflict
        case .invalidOperation:
            return .invalidOperation
        case .writeFailed, .recoveryRollbackBackupInvalid:
            return .writeFailed
        case .malformedDocument, .symlinkRejected, .invalidIntegrity,
             .referenceSetChanged:
            return .invalidCatalog
        }
    }

    /// Compensate records created before a Catalog commit. Deletion is
    /// attempted for every ID so a multi-secret transaction does not abandon
    /// the remaining records after the first failure. Any failure is made
    /// explicit to the caller and persisted as opaque cleanup metadata.
    private func compensateCreatedReferences(
        _ references: [SecretReference]
    ) async -> SecretCatalogAgentError? {
        guard !references.isEmpty else { return nil }
        guard let recordDeleter else {
            guard let catalogDocumentStore else {
                return .cleanupRequired
            }
            do {
                try await catalogDocumentStore.recordPendingSecretCleanup(
                    referenceIDs: references.map(\.id)
                )
            } catch {
                return .cleanupRequired
            }
            return .cleanupRequired
        }

        var failedIDs: [String] = []
        for reference in references {
            do {
                try await recordDeleter.delete(id: reference.id)
            } catch {
                failedIDs.append(reference.id)
            }
        }
        guard !failedIDs.isEmpty else {
            await notifySavedReferencesChanged()
            return nil
        }

        // The cleanup record contains only opaque IDs. If its write itself
        // fails, the operation still reports cleanupRequired; the caller must
        // not mistake a best-effort compensation failure for a clean rollback.
        guard let catalogDocumentStore else {
            return .cleanupRequired
        }
        do {
            try await catalogDocumentStore.recordPendingSecretCleanup(referenceIDs: failedIDs)
        } catch {
            return .cleanupRequired
        }
        await notifySavedReferencesChanged()
        return .cleanupRequired
    }

    private func catalogSnapshotForAgent() async throws -> SensitiveCatalogSnapshot {
        guard let catalogDocumentStore else {
            throw SecretCatalogAgentError.unavailable
        }

        do {
            let selectedURL: URL?
            if let catalogSelectionStore {
                selectedURL = try catalogSelectionStore.selectedDocumentURL()
            } else {
                selectedURL = await catalogDocumentStore.selectedDocumentURL()
            }
            guard let selectedURL else {
                throw SecretCatalogAgentError.unavailable
            }
            try await catalogDocumentStore.selectDocument(at: selectedURL)
            let snapshot = try await catalogDocumentStore.snapshot()
            guard snapshot.integrity == .verified else {
                throw SecretCatalogAgentError.unavailable
            }
            return snapshot
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .legacyCatalogUnsupported:
                throw SecretCatalogAgentError.legacyCatalogUnsupported
            case .integrityMissing:
                throw SecretCatalogAgentError.integrityMissing
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
            case .pendingExternalChange:
                throw SecretCatalogAgentError.pendingExternalChange
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .formatRepairConflict:
                throw SecretCatalogAgentError.formatRepairConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .noSelectedDocument, .malformedDocument,
                 .invalidIntegrity, .symlinkRejected, .referenceSetChanged:
                throw SecretCatalogAgentError.invalidCatalog
            case .writeFailed, .recoveryRollbackBackupInvalid:
                throw SecretCatalogAgentError.writeFailed
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    /// Resolves the selected document through the same manifest and Store
    /// instance used by MCP mutations, then runs only the non-destructive file
    /// access probe. This deliberately does not use the App process or a test
    /// temporary directory as a permission substitute.
    private func catalogFilePreflightForAgent() async throws -> CatalogFilePreflight {
        guard let catalogDocumentStore else {
            throw SecretCatalogAgentError.unavailable
        }
        let selectedURL: URL?
        if let catalogSelectionStore {
            selectedURL = try catalogSelectionStore.selectedDocumentURL()
        } else {
            selectedURL = await catalogDocumentStore.selectedDocumentURL()
        }
        guard let selectedURL else {
            throw SecretCatalogAgentError.unavailable
        }
        try await catalogDocumentStore.selectDocument(at: selectedURL)
        return try await catalogDocumentStore.preflightFileAccess()
    }

    private func validateSafeCatalogMutation(_ kind: CatalogMutationKind) async throws {
        do {
            try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: kind))
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-mutation", phase: .policy, error: error)
            throw error
        }
        // The old global safe-write gate was intentionally removed. Callers
        // must use requestAgentCatalogAuthorization with a candidate digest.
    }

    private static func logCatalogMutationFailure(
        operation: String,
        phase: CatalogMutationPhase,
        error: Error
    ) {
        // Only a fixed operation/phase and the error type are logged. Never
        // interpolate request values, paths, Markdown, secret references, or
        // plaintext into the local diagnostic stream.
        let errorType = String(reflecting: type(of: error))
        let errorCode = safeCatalogMutationErrorCode(error)
        catalogMutationLogger.error(
            "SVLT Catalog mutation failure: operation=\(operation, privacy: .public) phase=\(phase.rawValue, privacy: .public) error=\(errorType, privacy: .public) code=\(errorCode, privacy: .public)"
        )
    }

    private static func safeCatalogMutationErrorCode(_ error: Error) -> String {
        // These enums have no associated values. Their case names are fixed
        // diagnostic vocabulary and cannot contain request data, paths,
        // Markdown, secret references, or plaintext. Unknown errors remain
        // deliberately opaque.
        if let error = error as? SecretCatalogValidationError {
            return String(describing: error)
        }
        if let error = error as? SensitiveCatalogDocumentStoreError {
            return String(describing: error)
        }
        if let error = error as? SecretCatalogAgentError {
            return String(describing: error)
        }
        return "unknown"
    }

    private func makeCatalogEntry(from request: CatalogDraftRequest) throws -> SecretCatalogEntry {
        try SecretCatalogEntry.generated(
            indexId: request.indexID,
            title: request.title,
            type: request.type,
            aliases: request.aliases,
            endpoints: request.endpoints,
            fields: request.fields,
            notes: request.notes,
            tags: request.tags
        )
    }

    private func validateCatalogPatchMutation(
        from oldEntry: SecretCatalogEntry,
        to newEntry: SecretCatalogEntry
    ) async throws {
        let hasSecretReference = oldEntry.fields.contains { $0.secretRef != nil }
        let changesTarget = oldEntry.endpoints != newEntry.endpoints && hasSecretReference
        let changesSecretSemantics = catalogSensitiveChangeNeedsApproval(from: oldEntry, to: newEntry)
        let descriptor = CatalogMutationDescriptor(
            kind: changesSecretSemantics ? .changeSecretType : .patchMetadata,
            touchesExistingSecret: changesSecretSemantics,
            changesSecretTarget: changesTarget
        )
        try catalogMutationPolicyEngine.requireSilent(descriptor)
    }

    private func metadataPatchedEntry(
        _ entry: SecretCatalogEntry,
        with patch: CatalogMetadataPatch
    ) throws -> SecretCatalogEntry {
        var fields = entry.fields
        if let incomingFields = patch.fields {
            for incoming in incomingFields {
                if let offset = fields.firstIndex(where: { $0.key == incoming.key }) {
                    let current = fields[offset]
                    guard !current.type.isSecret,
                          !incoming.type.isSecret,
                          current.secretRef == nil,
                          incoming.secretRef == nil
                    else {
                        throw SecretCatalogAgentError.approvalRequired
                    }
                    fields[offset] = incoming
                } else {
                    if incoming.type.isSecret {
                        guard incoming.value == nil, incoming.secretRef == nil else {
                            throw SecretCatalogAgentError.approvalRequired
                        }
                    } else {
                        guard incoming.secretRef == nil else {
                            throw SecretCatalogAgentError.approvalRequired
                        }
                    }
                    fields.append(incoming)
                }
            }
        }

        return SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: patch.title ?? entry.title,
            type: entry.type,
            aliases: patch.aliases ?? entry.aliases,
            endpoints: patch.endpoints ?? entry.endpoints,
            fields: fields,
            notes: patch.notes ?? entry.notes,
            tags: patch.tags ?? entry.tags,
            schema: entry.schema
        )
    }

    private func catalogSensitiveChangeNeedsApproval(
        from oldEntry: SecretCatalogEntry,
        to newEntry: SecretCatalogEntry
    ) -> Bool {
        let oldFields = Dictionary(uniqueKeysWithValues: oldEntry.fields.map { ($0.key, $0) })
        let newFields = Dictionary(uniqueKeysWithValues: newEntry.fields.map { ($0.key, $0) })
        for key in Set(oldFields.keys).union(newFields.keys) {
            let oldField = oldFields[key]
            let newField = newFields[key]
            if oldField == nil, newField?.type.isSecret == true, newField?.secretRef == nil {
                // A new empty placeholder is intentionally silent; the user
                // fills its value through the secure App-control form later.
                continue
            }
            if oldField?.type.isSecret == true || newField?.type.isSecret == true {
                guard let oldField, let newField else { return true }
                if oldField.type != newField.type || oldField.secretRef != newField.secretRef {
                    return true
                }
            }
        }
        return false
    }

    private func sanitizedReason(_ reason: String) -> String {
        // Reasons arrive from local MCP clients and are not trusted log data.
        // Keep only a stable category; never persist the caller's free-form
        // text, which could contain a secret despite redaction heuristics.
        let normalized = reason.lowercased()
        if normalized.contains("ssh") {
            return "local-ssh"
        }
        if normalized.contains("http") || normalized.contains("api") {
            return "local-api"
        }
        if normalized.contains("export") || normalized.contains("file") {
            return "local-file"
        }
        if normalized.contains("delete") || normalized.contains("删除") {
            return "record-delete"
        }
        return "local-operation"
    }

    private func resolveTemplate(_ template: String, ranges: [ReferenceRange], plaintexts: [String]) throws -> String {
        var replacements: [String: String] = [:]

        for range in ranges {
            guard plaintexts.indices.contains(range.index), !range.placeholder.isEmpty else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            guard replacements[range.placeholder] == nil else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            replacements[range.placeholder] = plaintexts[range.index]
        }

        return replacePlaceholders(in: template, replacements: replacements)
    }

    private func validateRevealContext(_ context: RevealContext, referenceCount: Int) throws {
        guard context.ranges.count == referenceCount else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        var seenIndices: Set<Int> = []
        var seenPlaceholders: Set<String> = []

        for range in context.ranges {
            guard 0..<referenceCount ~= range.index,
                  !range.placeholder.isEmpty,
                  seenIndices.insert(range.index).inserted,
                  seenPlaceholders.insert(range.placeholder).inserted
            else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }

            guard countOccurrences(of: range.placeholder, in: context.template) == 1 else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
        }

        let placeholders = Array(seenPlaceholders)
        for lhsIndex in placeholders.indices {
            for rhsIndex in placeholders.indices where lhsIndex != rhsIndex {
                guard !placeholders[lhsIndex].contains(placeholders[rhsIndex]) else {
                    throw VaultAppServicesRevealError.invalidRevealContext
                }
            }
        }
    }

    private func countOccurrences(of needle: String, in haystack: String) -> Int {
        var count = 0
        var searchRange = haystack.startIndex..<haystack.endIndex

        while let range = haystack.range(of: needle, range: searchRange) {
            count += 1
            searchRange = range.upperBound..<haystack.endIndex
        }

        return count
    }

    private func replacePlaceholders(in template: String, replacements: [String: String]) -> String {
        var result = ""
        var remaining = template[...]
        let placeholders = replacements.keys.sorted { lhs, rhs in
            if lhs.count == rhs.count {
                return lhs < rhs
            }
            return lhs.count > rhs.count
        }

        while !remaining.isEmpty {
            let nextMatch = placeholders.compactMap { placeholder -> (String, Range<String.Index>)? in
                guard let range = remaining.range(of: placeholder) else {
                    return nil
                }
                return (placeholder, range)
            }
            .min { lhs, rhs in
                if lhs.1.lowerBound == rhs.1.lowerBound {
                    return lhs.0.count > rhs.0.count
                }
                return lhs.1.lowerBound < rhs.1.lowerBound
            }

            guard let nextMatch else {
                result.append(contentsOf: remaining)
                break
            }

            result.append(contentsOf: remaining[..<nextMatch.1.lowerBound])
            result.append(replacements[nextMatch.0] ?? "")
            remaining = remaining[nextMatch.1.upperBound...]
        }

        return result
    }
}

public enum VaultAppServicesRevealError: Error, Equatable, Sendable {
    case invalidReference
    case sessionNotFound
    case invalidRevealContext
    case invalidResolvedPlaintext
    case revealUnavailable
}

private extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async throws -> [T] {
        var values: [T] = []
        values.reserveCapacity(underestimatedCount)
        for element in self {
            try await values.append(transform(element))
        }
        return values
    }
}

private extension SecretPolicy {
    var decryptAuthorizationRank: Int {
        switch self {
        case .read:
            return 0
        case .externalSend:
            return 1
        case .credential:
            return 2
        }
    }

    func canAuthorizeDecrypt(for requestedPolicy: SecretPolicy) -> Bool {
        decryptAuthorizationRank >= requestedPolicy.decryptAuthorizationRank
    }
}
