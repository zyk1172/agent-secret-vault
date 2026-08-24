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
        exportDirectory: URL? = nil
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
        self.exportDirectory = (exportDirectory ?? Self.defaultExportDirectory()).standardizedFileURL
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
        exportDirectory: URL? = nil
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
        requireAgentSafeWrite: Bool
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
        try await authorizeCatalogDiff(
            diff,
            transport: .batchMutation,
            requireAgentSafeWrite: requireAgentSafeWrite
        )
        do {
            let updated = try await catalogDocumentStore!.applyBatch(mutation, expectedRevision: expectedRevision)
            return CatalogWriteResult(revision: updated.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
    }

    /// Safe Agent catalog creation reads the authoritative revision inside the
    /// service actor. It never trusts a UI snapshot or asks for a structure
    /// lease; the App-controlled safe-write preference is the only Agent gate.
    public func createCatalogIndex(
        title: String,
        aliases: [String],
        tags: [String]
    ) async throws -> CatalogWriteResult {
        try await validateSafeCatalogMutation(.createIndex)
        let snapshot = try await catalogSnapshotForAgent()
        let updated = try await catalogDocumentStore!.createIndex(
            title: title,
            aliases: aliases,
            tags: tags,
            expectedRevision: snapshot.revision
        )
        return CatalogWriteResult(revision: updated.revision)
    }

    /// Direct, single-call Agent creation for a safe Entry. Secret fields are
    /// accepted only as empty placeholders. Existing secret references and all
    /// plaintext secret values stay on their separate approval/secure-input
    /// paths.
    public func createCatalogEntry(_ request: CatalogDraftRequest) async throws -> CatalogWriteResult {
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
        try await validateSafeCatalogMutation(.createEntry)
        let snapshot = try await catalogSnapshotForAgent()
        let entry = try makeCatalogEntry(from: request)
        let updated = try await catalogDocumentStore!.createEntry(entry, expectedRevision: snapshot.revision)
        return CatalogWriteResult(
            revision: updated.revision,
            entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
        )
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
        try await validateSafeCatalogMutation(.createEntry)
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
        try await validateCatalogPatchMutation(from: oldEntry, to: updated)
        let updatedSnapshot = try await catalogDocumentStore!.updateEntry(updated, expectedRevision: expectedRevision)
        return CatalogWriteResult(
            revision: updatedSnapshot.revision,
            entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry
        )
    }

    public func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        try await validateSafeCatalogMutation(.createEntry)
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
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent()
        try await validateSafeCatalogMutation(.createSecretPlaceholder)
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

    public func validateCatalog() async throws -> CatalogValidationResult {
        do {
            let snapshot = try await catalogSnapshotForAgent()
            return CatalogValidationResult(status: .found, revision: snapshot.revision)
        } catch let error as SecretCatalogAgentError {
            switch error {
            case .legacyCatalogUnsupported:
                return CatalogValidationResult(status: .legacyCatalogUnsupported)
            case .integrityMissing:
                return CatalogValidationResult(status: .integrityMissing)
            case .externalModification:
                return CatalogValidationResult(status: .externalModification)
            case .pendingExternalChange:
                guard let store = catalogDocumentStore,
                      let pending = try? await store.pendingExternalChange()
                else {
                    return CatalogValidationResult(status: .pendingExternalChange)
                }
                return CatalogValidationResult(
                    status: .pendingExternalChange,
                    revision: pending.acceptedRevision,
                    pendingExternalChange: CatalogPendingExternalChange(
                        acceptedRevision: pending.acceptedRevision,
                        rawSHA256: pending.rawSHA256,
                        semanticSHA256: pending.semanticSHA256
                    )
                )
            case .invalidCatalog:
                return CatalogValidationResult(status: .invalidCatalog)
            case .unavailable:
                return CatalogValidationResult(status: .unavailable)
            default:
                throw error
            }
        }
    }

    public func catalogStatus() async throws -> CatalogValidationResult {
        try await validateCatalog()
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
        do {
            return try await catalogAgentWriteAuthorization.enable(
                mode: mode,
                duration: duration ?? CatalogAgentWriteAuthorization.maximumLifetime
            )
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
    }

    public func revokeCatalogAgentWrite() async {
        await catalogAgentWriteAuthorization.revoke()
    }

    public func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus {
        await catalogAgentWriteAuthorization.status()
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
            return CatalogWriteResult(revision: snapshot.revision)
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
                return CatalogWriteResult(revision: snapshot.revision)
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
            return CatalogWriteResult(
                revision: snapshot.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                throw catalogAgentError(for: error)
            }
            do {
                let current = try await store.snapshot()
                let snapshot = try await store.createEntry(entry, expectedRevision: current.revision)
                return CatalogWriteResult(
                    revision: snapshot.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
                )
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
            return CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
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
                  candidateField.type.isSecret,
                  candidateField.secretRef == nil
            else {
                // Replacing an already-bound secret stays on the explicit
                // approval path; this transaction only creates new records.
                throw SecretCatalogAgentError.invalidOperation
            }
            if currentFields[input.key]?.secretRef != nil {
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
                if oldReference != nil && inputsByKey[field.key] != nil {
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
            do {
                let updated = try await catalogDocumentStore!.updateEntry(entry, expectedRevision: expectedRevision)
                return CatalogWriteResult(
                    revision: updated.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
                )
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

            let updated = try await catalogDocumentStore!.updateEntry(finalEntry, expectedRevision: expectedRevision)
            await notifySavedReferencesChanged()
            return CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
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

        if let existingReference = field.secretRef {
            let parsedReference: SecretReference
            do {
                parsedReference = try SecretReference(existingReference)
            } catch {
                throw SecretCatalogAgentError.invalidOperation
            }
            let metadata = try await policyMetadata(for: [parsedReference])
            let descriptor = SecretOperationDescriptor(
                actionType: .changeSecretPolicy,
                secretReferences: [parsedReference],
                requestedEffects: ["replace-catalog-secret"]
            )
            let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
            try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        }

        let secret = try await textEncryptor.encryptText(plaintext, label: label, policy: policy)
        do {
            let updated = try await catalogDocumentStore!.bindSecret(
                secret.description,
                toFieldKey: key,
                entryID: entryID,
                expectedRevision: snapshot.revision
            )
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

    private func authorizeCatalogDiff(
        _ diff: CatalogSemanticDiff,
        transport: CatalogMutationKind,
        requireAgentSafeWrite: Bool = true
    ) async throws {
        let catalogDecision = catalogMutationPolicyEngine.evaluate(diff, transport: transport)
        switch catalogDecision {
        case .denied:
            throw SecretOperationError.operationDenied
        case .silent:
            if requireAgentSafeWrite {
                try await catalogAgentWriteAuthorization.validateSafeWrite()
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
                    requestedEffects: ["catalog-semantic-approval"]
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
                    requestedEffects: ["catalog-semantic-approval"]
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
        return "SVLT 请求本机审批：\(displayName(for: descriptor.actionType))；操作：\(detail)；目标：\(target)；凭据：\(labelText)"
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
        guard let recordDeleter else { return pending }

        var remaining: [String] = []
        var resolved: [String] = []
        for id in pending {
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
        return remaining
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
            // Explicit test callers may have supplied an already-held
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
        case .invalidOperation:
            return .invalidOperation
        case .malformedDocument, .symlinkRejected, .invalidIntegrity,
             .referenceSetChanged, .writeFailed:
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
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .noSelectedDocument, .malformedDocument,
                 .invalidIntegrity, .symlinkRejected, .writeFailed, .referenceSetChanged:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    private func validateSafeCatalogMutation(_ kind: CatalogMutationKind) async throws {
        try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: kind))
        try await catalogAgentWriteAuthorization.validateSafeWrite()
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
        try await catalogAgentWriteAuthorization.validateSafeWrite()
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
