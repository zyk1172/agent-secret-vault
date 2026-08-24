import CryptoKit
import Foundation
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

public actor VaultAppServices: WorkbenchServicing, AppControlServicing {
    private let textEncryptor: any TextEncrypting
    private let activeRoot: URL?
    private let recordLister: (any RecordListing)?
    private let recordDeleter: (any RecordDeleting)?
    private let recordResolver: VaultRecordResolver?
    private let catalogService: SecretCatalogService?
    private let catalogDocumentStore: SensitiveCatalogDocumentStore?
    private let catalogSelectionStore: SecretCatalogSelectionStore?
    private let catalogSearchService: SecretCatalogEntrySearchService
    private let catalogLeaseManager: CatalogWriteLeaseManager
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
    private let exportDirectory: URL
    private var pluginConnectedAt: Date?
    private var agentDecryptAuthorizations: [String: AgentDecryptAuthorization] = [:]
    private var pendingCatalogDrafts: [String: SecretCatalogEntry] = [:]
    private var approvalPending = false

    public init(
        textEncryptor: any TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogService: SecretCatalogService? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogLeaseManager: CatalogWriteLeaseManager = CatalogWriteLeaseManager(),
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
        exportDirectory: URL? = nil
    ) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
        self.recordLister = recordLister
        self.recordDeleter = recordDeleter
        self.recordResolver = recordResolver
        self.catalogService = catalogService
        self.catalogDocumentStore = catalogDocumentStore
        self.catalogSelectionStore = catalogSelectionManifestURL.map(SecretCatalogSelectionStore.init(manifestURL:))
        self.catalogSearchService = SecretCatalogEntrySearchService()
        self.catalogLeaseManager = catalogLeaseManager
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
        self.exportDirectory = (exportDirectory ?? Self.defaultExportDirectory()).standardizedFileURL
    }

    public init(
        encryptSelection: any EncryptSelectionCoordinating & TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogService: SecretCatalogService? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogLeaseManager: CatalogWriteLeaseManager = CatalogWriteLeaseManager(),
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
        exportDirectory: URL? = nil
    ) {
        self.init(
            textEncryptor: encryptSelection,
            activeRoot: activeRoot,
            recordLister: recordLister,
            recordDeleter: recordDeleter,
            recordResolver: recordResolver,
            catalogService: catalogService,
            catalogDocumentStore: catalogDocumentStore,
            catalogSelectionManifestURL: catalogSelectionManifestURL,
            catalogLeaseManager: catalogLeaseManager,
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
            exportDirectory: exportDirectory
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
                action: "Agent 操作被本地策略拒绝",
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
                action: "Agent 专用操作",
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
            action: "搜索本机 Secret 目录",
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

    public func createCatalogDraft(
        _ request: CatalogDraftRequest,
        lease: CatalogWriteLease
    ) async throws -> CatalogDraft {
        try await validateLease(lease, requiredScope: .structure)
        let snapshot = try await catalogSnapshotForAgent()
        guard snapshot.document.indexes.contains(where: { $0.id == request.indexID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard request.fields.allSatisfy({ $0.secretRef == nil }) else {
            // Existing secret binding has a separate App-approved operation.
            // A draft must not smuggle an opaque reference past that boundary.
            throw SecretCatalogAgentError.approvalRequired
        }

        let entry = try SecretCatalogEntry.generated(
            indexId: request.indexID,
            title: request.title,
            type: request.type,
            aliases: request.aliases,
            fields: request.fields,
            tags: request.tags
        )
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
        expectedRevision: UInt64,
        lease: CatalogWriteLease
    ) async throws -> CatalogWriteResult {
        try await validateLease(lease, requiredScope: .metadata)
        let snapshot = try await catalogSnapshotForAgent()
        guard let oldEntry = snapshot.document.entries.first(where: { $0.id == entryID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let updated = try metadataPatchedEntry(oldEntry, with: patch)
        let updatedSnapshot = try await catalogDocumentStore!.updateEntry(updated, expectedRevision: expectedRevision)
        return CatalogWriteResult(
            revision: updatedSnapshot.revision,
            entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry
        )
    }

    public func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64,
        lease: CatalogWriteLease
    ) async throws -> CatalogWriteResult {
        try await validateLease(lease, requiredScope: .structure)
        guard let pending = pendingCatalogDrafts[draft.draftID] else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let snapshot = try await catalogSnapshotForAgent()
        guard expectedRevision == snapshot.revision,
              draft.baseRevision == snapshot.revision,
              draft.entry.id == pending.id,
              draft.entry.indexId == pending.indexId
        else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let updatedSnapshot = try await catalogDocumentStore!.createEntry(pending, expectedRevision: expectedRevision)
        pendingCatalogDrafts.removeValue(forKey: draft.draftID)
        return CatalogWriteResult(
            revision: updatedSnapshot.revision,
            entry: catalogSearchService.get(entryID: pending.id, document: updatedSnapshot.document).matches.first?.entry
        )
    }

    public func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64,
        lease: CatalogWriteLease
    ) async throws -> CatalogWriteResult {
        try await validateLease(lease, requiredScope: .structure)
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
        let updatedSnapshot = try await catalogDocumentStore!.addField(
            field,
            toEntryID: entryID,
            expectedRevision: expectedRevision
        )
        return CatalogWriteResult(
            revision: updatedSnapshot.revision,
            entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry
        )
    }

    public func bindCatalogExistingSecret(
        entryID _: String,
        key _: String,
        secretRef _: String,
        expectedRevision _: UInt64,
        lease _: CatalogWriteLease
    ) async throws -> CatalogWriteResult {
        // Binding an existing secret can change the destination/policy meaning
        // of a catalog entry.  It remains an App-approved operation; an Agent
        // cannot turn a self-reported user request into authorization.
        throw SecretCatalogAgentError.approvalRequired
    }

    public func validateCatalog() async throws -> CatalogValidationResult {
        do {
            let snapshot = try await catalogSnapshotForAgent()
            return CatalogValidationResult(status: .found, revision: snapshot.revision)
        } catch let error as SecretCatalogAgentError {
            switch error {
            case .migrationRequired:
                return CatalogValidationResult(status: .migrationRequired)
            case .externalModification:
                return CatalogValidationResult(status: .externalModification)
            case .invalidCatalog:
                return CatalogValidationResult(status: .invalidCatalog)
            case .unavailable:
                return CatalogValidationResult(status: .unavailable)
            default:
                throw error
            }
        }
    }

    public func issueCatalogLease(
        scope: CatalogWriteScope,
        duration: TimeInterval?
    ) async throws -> CatalogWriteLease {
        try await catalogLeaseManager.issue(scope: scope, duration: duration)
    }

    public func revokeCatalogLease(nonce: String) async {
        await catalogLeaseManager.revoke(nonce: nonce)
    }

    public func catalogStatus() async throws -> CatalogValidationResult {
        try await validateCatalog()
    }

    public func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let store = try await selectedCatalogStoreForApp()
        let snapshot = try await store.createIndex(
            title: title,
            aliases: aliases,
            tags: tags,
            expectedRevision: expectedRevision
        )
        return CatalogWriteResult(revision: snapshot.revision)
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
            return CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updated.document).matches.first?.entry
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
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
        let snapshot = try await catalogSnapshotForAgent()
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              let field = entry.fields.first(where: { $0.key == key }),
              field.type.isSecret
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let secret = try await textEncryptor.encryptText(plaintext, label: label, policy: policy)
        let updated = try await catalogDocumentStore!.bindSecret(
            secret.description,
            toFieldKey: key,
            entryID: entryID,
            expectedRevision: snapshot.revision
        )
        return (secret.description, updated.revision)
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
            result: "成功"
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
            result: "成功"
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

        let ticket = await approvalTicketStore.issue(for: descriptor, now: now())
        let summary = approvalSummary(descriptor: descriptor, metadata: metadata, decision: decision)
        approvalPending = true
        await statusObserver?(status())

        do {
            try await approveWithTimeout(summary: summary)
            guard await approvalTicketStore.consume(ticket, for: descriptor, now: now()) else {
                throw SecretOperationError.operationDenied
            }
        } catch let error as SecretOperationError {
            approvalPending = false
            await statusObserver?(status())
            throw error
        } catch let error as OperationAuthorizationError {
            approvalPending = false
            await statusObserver?(status())
            switch error {
            case .cancelled:
                throw SecretOperationError.authorizationCancelled
            case .denied:
                throw SecretOperationError.authorizationDenied
            case .timeout:
                throw SecretOperationError.authorizationTimeout
            case .unavailable:
                throw SecretOperationError.authorizationUnavailable
            }
        } catch {
            approvalPending = false
            await statusObserver?(status())
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

    private func approvalSummary(
        descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision
    ) -> String {
        let labels = metadata.compactMap(\.label)
            .map(safeDisplayLabel)
            .filter { !$0.isEmpty }
        let labelText = labels.isEmpty ? "未命名 Secret" : labels.prefix(3).joined(separator: "、")
        let target = safeDisplayLabel(decision.normalizedDestination ?? "本机")
        let detail = safeDisplayLabel(operationDetail(for: descriptor))
        return "SVLT 请求本机审批：\(displayName(for: descriptor.actionType))；操作：\(detail)；目标：\(target)；Secret：\(labelText)"
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
            return "删除 Secret"
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
            return "Agent SSH 操作"
        case .httpRequest, .apiRequest:
            return "Agent HTTP/API 操作"
        case .databaseQuery:
            return "Agent 数据库操作"
        case .sftpTransfer:
            return "Agent SFTP 操作"
        default:
            return "Agent 受保护操作"
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
        result: String
    ) async {
        let entry = AgentAutomationAuditEntry(
            action: action,
            target: target,
            referenceCount: referenceCount,
            result: result
        )
        await auditObserver?(entry)
        guard let auditLog else {
            return
        }
        let event = AuditEvent(
            timestamp: entry.occurredAt,
            integration: "agent-secret-vault-mcp",
            referenceID: nil,
            operation: auditOperation(for: action),
            risk: 0,
            authorizationOutcome: .notRequired,
            declaredTarget: entry.target,
            status: auditStatus(for: result),
            exitCode: nil
        )
        do {
            // The production daemon supplies an independent Keychain audit key.
            // This call must never go through resolvedMasterKey().
            try await auditLog.append(event)
        } catch {
            // Explicit migration/test callers may have supplied an already-held
            // master key. Never acquire one merely to record a failed audit.
            if let masterKey {
                try? await auditLog.append(event, masterKey: masterKey)
            }
        }
    }

    private func auditOperation(for action: String) -> AuditOperation {
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
            switch error {
            case .migrationRequired:
                throw SecretCatalogAgentError.migrationRequired
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
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
            case .migrationRequired:
                throw SecretCatalogAgentError.migrationRequired
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .noSelectedDocument, .integrityMissing, .malformedDocument,
                 .invalidIntegrity, .symlinkRejected, .writeFailed, .referenceSetChanged:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    private func validateLease(
        _ lease: CatalogWriteLease,
        requiredScope: CatalogWriteScope
    ) async throws {
        do {
            try await catalogLeaseManager.validate(lease, requiredScope: requiredScope)
        } catch CatalogWriteLeaseError.expired {
            throw SecretCatalogAgentError.leaseExpired
        } catch CatalogWriteLeaseError.insufficientScope {
            throw SecretCatalogAgentError.insufficientLeaseScope
        } catch {
            throw SecretCatalogAgentError.invalidLease
        }
    }

    private func metadataPatchedEntry(
        _ entry: SecretCatalogEntry,
        with patch: CatalogMetadataPatch
    ) throws -> SecretCatalogEntry {
        var fields = entry.fields
        if let incomingFields = patch.fields {
            for incoming in incomingFields {
                guard let offset = fields.firstIndex(where: { $0.key == incoming.key }) else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                let current = fields[offset]
                guard !current.type.isSecret,
                      !incoming.type.isSecret,
                      current.secretRef == nil,
                      incoming.secretRef == nil
                else {
                    throw SecretCatalogAgentError.approvalRequired
                }
                fields[offset] = incoming
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
