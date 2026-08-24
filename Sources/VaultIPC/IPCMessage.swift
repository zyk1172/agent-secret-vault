import Foundation
import VaultCore
import VaultExecution

public enum CapabilityTokenError: Error, Equatable, Sendable {
    case invalidEncoding
    case invalidLength(actualBytes: Int)
}

public struct CapabilityToken: Codable, Equatable, Sendable {
    public static let byteCount = 32

    public let rawValue: String

    private init(uncheckedRawValue: String) {
        self.rawValue = uncheckedRawValue
    }

    public init(base64Encoded rawValue: String) throws {
        guard let decoded = Data(base64Encoded: rawValue) else {
            throw CapabilityTokenError.invalidEncoding
        }
        guard decoded.count == Self.byteCount else {
            throw CapabilityTokenError.invalidLength(actualBytes: decoded.count)
        }

        self.rawValue = rawValue
    }

    public static func random() -> CapabilityToken {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<byteCount).map { _ in
            UInt8.random(in: UInt8.min ... UInt8.max, using: &generator)
        }
        return CapabilityToken(uncheckedRawValue: Data(bytes).base64EncodedString())
    }

    public func constantTimeEquals(_ other: CapabilityToken) -> Bool {
        guard let lhs = Data(base64Encoded: rawValue),
              let rhs = Data(base64Encoded: other.rawValue),
              lhs.count == rhs.count
        else {
            return false
        }

        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(base64Encoded: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum IPCRequest: Codable, Equatable, Sendable {
    case status
    case workbenchStatus
    case savedReferences
    /// Compatibility spelling for older in-process callers.  It still emits
    /// the v2 Entry-centric payload and never returns the old flat shape.
    case searchCatalog(query: String, field: SecretCatalogField?, limit: Int)
    case catalogSearch(query: String, field: SecretCatalogField?, limit: Int)
    case catalogGet(entryID: String)
    case catalogCreateIndex(title: String, aliases: [String], tags: [String])
    case catalogCreateEntry(request: CatalogDraftRequest)
    case catalogCreateDraft(request: CatalogDraftRequest)
    case catalogPatchMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    )
    case catalogCommit(
        draft: CatalogDraft,
        expectedRevision: UInt64
    )
    case catalogAddSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64
    )
    case catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    )
    case catalogValidate
    case pendingRevealSessions
    case inspectReference(reference: String)
    case deleteRecord(reference: String)
    case authorizeHighRisk(reason: String)
    case lock
    case clearRevealSessions
    case revealSessionData(sessionID: String)
    case reveal(reference: String, reason: String)
    case encrypt(label: String?, policy: SecretPolicy)
    case encryptText(plaintext: String, label: String?, policy: SecretPolicy)
    case encryptBound(
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    )
    case revealReferences(references: [String], context: RevealContext)
    case restoreReferences(references: [String], context: RevealContext)
    case exportResolvedText(references: [String], context: RevealContext, destinationPath: String)
    case scanOrphans(markdownReferences: [String])
    case execute(ExecutionRequest)
    case executeSecretOperation(SecretOperationDescriptor)

    private enum CodingKeys: String, CodingKey {
        case type
        case plaintext
        case reference
        case references
        case reason
        case sessionID
        case query
        case field
        case limit
        case entryID
        case request
        case title
        case aliases
        case tags
        case patch
        case draft
        case expectedRevision
        case key
        case secretRef
        case agentVisible
        case searchable
        case label
        case policy
        case allowedDestinations
        case allowedProtocols
        case context
        case destinationPath
        case markdownReferences
        case descriptor
    }

    private enum RequestType: String, Codable {
        case status
        case workbenchStatus
        case savedReferences
        case searchCatalog
        case catalogSearch
        case catalogGet
        case catalogCreateIndex
        case catalogCreateEntry
        case catalogCreateDraft
        case catalogPatchMetadata
        case catalogCommit
        case catalogAddSecretPlaceholder
        case catalogBindExistingSecret
        case catalogValidate
        case pendingRevealSessions
        case inspectReference
        case deleteRecord
        case authorizeHighRisk
        case lock
        case clearRevealSessions
        case revealSessionData
        case reveal
        case encrypt
        case encryptText
        case encryptBound
        case revealReferences
        case restoreReferences
        case exportResolvedText
        case scanOrphans
        case execute
        case executeSecretOperation
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .status:
            self = .status
        case .workbenchStatus:
            self = .workbenchStatus
        case .savedReferences:
            self = .savedReferences
        case .searchCatalog:
            self = .searchCatalog(
                query: try container.decode(String.self, forKey: .query),
                field: try container.decodeIfPresent(SecretCatalogField.self, forKey: .field),
                limit: try container.decode(Int.self, forKey: .limit)
            )
        case .catalogSearch:
            self = .catalogSearch(
                query: try container.decode(String.self, forKey: .query),
                field: try container.decodeIfPresent(SecretCatalogField.self, forKey: .field),
                limit: try container.decode(Int.self, forKey: .limit)
            )
        case .catalogGet:
            self = .catalogGet(entryID: try container.decode(String.self, forKey: .entryID))
        case .catalogCreateIndex:
            self = .catalogCreateIndex(
                title: try container.decode(String.self, forKey: .title),
                aliases: try container.decode([String].self, forKey: .aliases),
                tags: try container.decode([String].self, forKey: .tags)
            )
        case .catalogCreateEntry:
            self = .catalogCreateEntry(
                request: try container.decode(CatalogDraftRequest.self, forKey: .request)
            )
        case .catalogCreateDraft:
            self = .catalogCreateDraft(
                request: try container.decode(CatalogDraftRequest.self, forKey: .request)
            )
        case .catalogPatchMetadata:
            self = .catalogPatchMetadata(
                entryID: try container.decode(String.self, forKey: .entryID),
                patch: try container.decode(CatalogMetadataPatch.self, forKey: .patch),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogCommit:
            self = .catalogCommit(
                draft: try container.decode(CatalogDraft.self, forKey: .draft),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogAddSecretPlaceholder:
            self = .catalogAddSecretPlaceholder(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                label: try container.decode(String.self, forKey: .label),
                agentVisible: try container.decode(Bool.self, forKey: .agentVisible),
                searchable: try container.decode(Bool.self, forKey: .searchable),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogBindExistingSecret:
            self = .catalogBindExistingSecret(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                secretRef: try container.decode(String.self, forKey: .secretRef),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogValidate:
            self = .catalogValidate
        case .pendingRevealSessions:
            self = .pendingRevealSessions
        case .inspectReference:
            self = .inspectReference(
                reference: try container.decode(String.self, forKey: .reference)
            )
        case .deleteRecord:
            self = .deleteRecord(
                reference: try container.decode(String.self, forKey: .reference)
            )
        case .authorizeHighRisk:
            self = .authorizeHighRisk(
                reason: try container.decode(String.self, forKey: .reason)
            )
        case .lock:
            self = .lock
        case .clearRevealSessions:
            self = .clearRevealSessions
        case .revealSessionData:
            self = .revealSessionData(
                sessionID: try container.decode(String.self, forKey: .sessionID)
            )
        case .reveal:
            self = .reveal(
                reference: try container.decode(String.self, forKey: .reference),
                reason: try container.decode(String.self, forKey: .reason)
            )
        case .encrypt:
            self = .encrypt(
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        case .encryptText:
            self = .encryptText(
                plaintext: try container.decode(String.self, forKey: .plaintext),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        case .encryptBound:
            self = .encryptBound(
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy),
                allowedDestinations: try container.decode([String].self, forKey: .allowedDestinations),
                allowedProtocols: try container.decode([String].self, forKey: .allowedProtocols)
            )
        case .revealReferences:
            self = .revealReferences(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context)
            )
        case .restoreReferences:
            self = .restoreReferences(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context)
            )
        case .exportResolvedText:
            self = .exportResolvedText(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context),
                destinationPath: try container.decode(String.self, forKey: .destinationPath)
            )
        case .scanOrphans:
            self = .scanOrphans(
                markdownReferences: try container.decode([String].self, forKey: .markdownReferences)
            )
        case .execute:
            self = .execute(try container.decode(ExecutionRequest.self, forKey: .request))
        case .executeSecretOperation:
            self = .executeSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode(RequestType.status, forKey: .type)
        case .workbenchStatus:
            try container.encode(RequestType.workbenchStatus, forKey: .type)
        case .savedReferences:
            try container.encode(RequestType.savedReferences, forKey: .type)
        case let .searchCatalog(query, field, limit):
            try container.encode(RequestType.searchCatalog, forKey: .type)
            try container.encode(query, forKey: .query)
            try container.encodeIfPresent(field, forKey: .field)
            try container.encode(limit, forKey: .limit)
        case let .catalogSearch(query, field, limit):
            try container.encode(RequestType.catalogSearch, forKey: .type)
            try container.encode(query, forKey: .query)
            try container.encodeIfPresent(field, forKey: .field)
            try container.encode(limit, forKey: .limit)
        case let .catalogGet(entryID):
            try container.encode(RequestType.catalogGet, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
        case let .catalogCreateIndex(title, aliases, tags):
            try container.encode(RequestType.catalogCreateIndex, forKey: .type)
            try container.encode(title, forKey: .title)
            try container.encode(aliases, forKey: .aliases)
            try container.encode(tags, forKey: .tags)
        case let .catalogCreateEntry(request):
            try container.encode(RequestType.catalogCreateEntry, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .catalogCreateDraft(request):
            try container.encode(RequestType.catalogCreateDraft, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .catalogPatchMetadata(entryID, patch, expectedRevision):
            try container.encode(RequestType.catalogPatchMetadata, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(patch, forKey: .patch)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogCommit(draft, expectedRevision):
            try container.encode(RequestType.catalogCommit, forKey: .type)
            try container.encode(draft, forKey: .draft)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogAddSecretPlaceholder(entryID, key, label, agentVisible, searchable, expectedRevision):
            try container.encode(RequestType.catalogAddSecretPlaceholder, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encode(label, forKey: .label)
            try container.encode(agentVisible, forKey: .agentVisible)
            try container.encode(searchable, forKey: .searchable)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
            try container.encode(RequestType.catalogBindExistingSecret, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encode(secretRef, forKey: .secretRef)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case .catalogValidate:
            try container.encode(RequestType.catalogValidate, forKey: .type)
        case .pendingRevealSessions:
            try container.encode(RequestType.pendingRevealSessions, forKey: .type)
        case let .inspectReference(reference):
            try container.encode(RequestType.inspectReference, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .deleteRecord(reference):
            try container.encode(RequestType.deleteRecord, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .authorizeHighRisk(reason):
            try container.encode(RequestType.authorizeHighRisk, forKey: .type)
            try container.encode(reason, forKey: .reason)
        case .lock:
            try container.encode(RequestType.lock, forKey: .type)
        case .clearRevealSessions:
            try container.encode(RequestType.clearRevealSessions, forKey: .type)
        case let .revealSessionData(sessionID):
            try container.encode(RequestType.revealSessionData, forKey: .type)
            try container.encode(sessionID, forKey: .sessionID)
        case let .reveal(reference, reason):
            try container.encode(RequestType.reveal, forKey: .type)
            try container.encode(reference, forKey: .reference)
            try container.encode(reason, forKey: .reason)
        case let .encrypt(label, policy):
            try container.encode(RequestType.encrypt, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .encryptText(plaintext, label, policy):
            try container.encode(RequestType.encryptText, forKey: .type)
            try container.encode(plaintext, forKey: .plaintext)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .encryptBound(label, policy, allowedDestinations, allowedProtocols):
            try container.encode(RequestType.encryptBound, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
            try container.encode(allowedDestinations, forKey: .allowedDestinations)
            try container.encode(allowedProtocols, forKey: .allowedProtocols)
        case let .revealReferences(references, context):
            try container.encode(RequestType.revealReferences, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
        case let .restoreReferences(references, context):
            try container.encode(RequestType.restoreReferences, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
        case let .exportResolvedText(references, context, destinationPath):
            try container.encode(RequestType.exportResolvedText, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
            try container.encode(destinationPath, forKey: .destinationPath)
        case let .scanOrphans(markdownReferences):
            try container.encode(RequestType.scanOrphans, forKey: .type)
            try container.encode(markdownReferences, forKey: .markdownReferences)
        case let .execute(request):
            try container.encode(RequestType.execute, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .executeSecretOperation(descriptor):
            try container.encode(RequestType.executeSecretOperation, forKey: .type)
            try container.encode(descriptor, forKey: .descriptor)
        }
    }
}

public struct WorkbenchStatus: Codable, Equatable, Sendable {
    /// Kept for wire compatibility only. Agent workflows must use ready and
    /// approvalPending instead of treating this field as a global gate.
    public let locked: Bool
    public let ipcAvailable: Bool
    public let available: Bool
    public let ready: Bool
    public let approvalPending: Bool
    public let activeKnowledgeBaseRoot: String?
    public let pluginConnected: Bool

    private enum CodingKeys: String, CodingKey {
        case locked
        case ipcAvailable
        case available
        case ready
        case approvalPending
        case activeKnowledgeBaseRoot
        case pluginConnected
    }

    public init(
        locked: Bool,
        ipcAvailable: Bool,
        available: Bool = true,
        ready: Bool = true,
        approvalPending: Bool = false,
        activeKnowledgeBaseRoot: String?,
        pluginConnected: Bool
    ) {
        self.locked = locked
        self.ipcAvailable = ipcAvailable
        self.available = available
        self.ready = ready
        self.approvalPending = approvalPending
        self.activeKnowledgeBaseRoot = activeKnowledgeBaseRoot
        self.pluginConnected = pluginConnected
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            locked: try container.decode(Bool.self, forKey: .locked),
            ipcAvailable: try container.decode(Bool.self, forKey: .ipcAvailable),
            available: try container.decodeIfPresent(Bool.self, forKey: .available) ?? true,
            ready: try container.decodeIfPresent(Bool.self, forKey: .ready) ?? true,
            approvalPending: try container.decodeIfPresent(Bool.self, forKey: .approvalPending) ?? false,
            activeKnowledgeBaseRoot: try container.decodeIfPresent(String.self, forKey: .activeKnowledgeBaseRoot),
            pluginConnected: try container.decode(Bool.self, forKey: .pluginConnected)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(locked, forKey: .locked)
        try container.encode(ipcAvailable, forKey: .ipcAvailable)
        try container.encode(available, forKey: .available)
        try container.encode(ready, forKey: .ready)
        try container.encode(approvalPending, forKey: .approvalPending)
        if let activeKnowledgeBaseRoot {
            try container.encode(activeKnowledgeBaseRoot, forKey: .activeKnowledgeBaseRoot)
        } else {
            try container.encodeNil(forKey: .activeKnowledgeBaseRoot)
        }
        try container.encode(pluginConnected, forKey: .pluginConnected)
    }
}

public struct ReferenceRange: Codable, Equatable, Sendable {
    public let index: Int
    public let placeholder: String

    public init(index: Int, placeholder: String) {
        self.index = index
        self.placeholder = placeholder
    }
}

public struct OrphanScanResult: Codable, Equatable, Sendable {
    public let missingRecords: [String]
    public let unreferencedRecords: [String]

    public init(missingRecords: [String], unreferencedRecords: [String]) {
        self.missingRecords = missingRecords
        self.unreferencedRecords = unreferencedRecords
    }
}

public struct SecretReferenceMetadata: Codable, Equatable, Sendable {
    public let reference: String
    public let policy: SecretPolicy
    public let label: String?
    public let allowedDestinations: [String]
    public let allowedProtocols: [String]
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        reference: String,
        policy: SecretPolicy,
        label: String?,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = [],
        createdAt: Date,
        updatedAt: Date
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.allowedDestinations = allowedDestinations
        self.allowedProtocols = allowedProtocols
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case reference
        case policy
        case label
        case allowedDestinations
        case allowedProtocols
        case createdAt
        case updatedAt
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            reference: try container.decode(String.self, forKey: .reference),
            policy: try container.decode(SecretPolicy.self, forKey: .policy),
            label: try container.decodeIfPresent(String.self, forKey: .label),
            allowedDestinations: try container.decodeIfPresent([String].self, forKey: .allowedDestinations) ?? [],
            allowedProtocols: try container.decodeIfPresent([String].self, forKey: .allowedProtocols) ?? [],
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(reference, forKey: .reference)
        try container.encode(policy, forKey: .policy)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encode(allowedDestinations, forKey: .allowedDestinations)
        try container.encode(allowedProtocols, forKey: .allowedProtocols)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
    }
}

public enum IPCResponse: Codable, Equatable, Sendable {
    case status(locked: Bool)
    case workbenchStatus(WorkbenchStatus)
    case savedReferences([SecretReferenceMetadata])
    case catalogSearchResult(SecretCatalogSearchResult)
    case catalogDraft(CatalogDraft)
    case catalogWriteResult(CatalogWriteResult)
    case catalogValidation(status: SecretCatalogSearchStatus, revision: UInt64?)
    case revealSessionIDs([String])
    case referenceMetadata(SecretReferenceMetadata)
    case displayedToUser
    case operationCompleted
    case authorizationApproved
    case revealSessionData(RestoredParagraph)
    case created(reference: String)
    case revealSessionOpened(sessionID: String)
    case restoredText(String)
    case exported(path: String)
    case orphanScan(OrphanScanResult)
    case execution(SanitizedExecutionResult)
    case secretOperation(SecretOperationOutput)
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case locked
        case status
        case references
        case result
        case draft
        case revision
        case catalogStatus
        case sessionIDs
        case metadata
        case reference
        case sessionID
        case paragraph
        case text
        case path
        case output
        case code
    }

    private enum ResponseType: String, Codable {
        case status
        case workbenchStatus
        case savedReferences
        case catalogSearchResult
        case catalogDraft
        case catalogWriteResult
        case catalogValidation
        case revealSessionIDs
        case referenceMetadata
        case displayedToUser
        case operationCompleted
        case authorizationApproved
        case revealSessionData
        case created
        case revealSessionOpened
        case restoredText
        case exported
        case orphanScan
        case execution
        case secretOperation
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .status:
            self = .status(locked: try container.decode(Bool.self, forKey: .locked))
        case .workbenchStatus:
            self = .workbenchStatus(try container.decode(WorkbenchStatus.self, forKey: .status))
        case .savedReferences:
            self = .savedReferences(try container.decode([SecretReferenceMetadata].self, forKey: .references))
        case .catalogSearchResult:
            self = .catalogSearchResult(try container.decode(SecretCatalogSearchResult.self, forKey: .result))
        case .catalogDraft:
            self = .catalogDraft(try container.decode(CatalogDraft.self, forKey: .draft))
        case .catalogWriteResult:
            self = .catalogWriteResult(try container.decode(CatalogWriteResult.self, forKey: .result))
        case .catalogValidation:
            self = .catalogValidation(
                status: try container.decode(SecretCatalogSearchStatus.self, forKey: .catalogStatus),
                revision: try container.decodeIfPresent(UInt64.self, forKey: .revision)
            )
        case .revealSessionIDs:
            self = .revealSessionIDs(try container.decode([String].self, forKey: .sessionIDs))
        case .referenceMetadata:
            self = .referenceMetadata(try container.decode(SecretReferenceMetadata.self, forKey: .metadata))
        case .displayedToUser:
            self = .displayedToUser
        case .operationCompleted:
            self = .operationCompleted
        case .authorizationApproved:
            self = .authorizationApproved
        case .revealSessionData:
            self = .revealSessionData(try container.decode(RestoredParagraph.self, forKey: .paragraph))
        case .created:
            self = .created(reference: try container.decode(String.self, forKey: .reference))
        case .revealSessionOpened:
            self = .revealSessionOpened(sessionID: try container.decode(String.self, forKey: .sessionID))
        case .restoredText:
            self = .restoredText(try container.decode(String.self, forKey: .text))
        case .exported:
            self = .exported(path: try container.decode(String.self, forKey: .path))
        case .orphanScan:
            self = .orphanScan(try container.decode(OrphanScanResult.self, forKey: .result))
        case .execution:
            self = .execution(try container.decode(SanitizedExecutionResult.self, forKey: .result))
        case .secretOperation:
            self = .secretOperation(try container.decode(SecretOperationOutput.self, forKey: .output))
        case .failure:
            self = .failure(code: try container.decode(String.self, forKey: .code))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .status(locked):
            try container.encode(ResponseType.status, forKey: .type)
            try container.encode(locked, forKey: .locked)
        case let .workbenchStatus(status):
            try container.encode(ResponseType.workbenchStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .savedReferences(references):
            try container.encode(ResponseType.savedReferences, forKey: .type)
            try container.encode(references, forKey: .references)
        case let .catalogSearchResult(result):
            try container.encode(ResponseType.catalogSearchResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogDraft(draft):
            try container.encode(ResponseType.catalogDraft, forKey: .type)
            try container.encode(draft, forKey: .draft)
        case let .catalogWriteResult(result):
            try container.encode(ResponseType.catalogWriteResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogValidation(status, revision):
            try container.encode(ResponseType.catalogValidation, forKey: .type)
            try container.encode(status, forKey: .catalogStatus)
            try container.encodeIfPresent(revision, forKey: .revision)
        case let .revealSessionIDs(sessionIDs):
            try container.encode(ResponseType.revealSessionIDs, forKey: .type)
            try container.encode(sessionIDs, forKey: .sessionIDs)
        case let .referenceMetadata(metadata):
            try container.encode(ResponseType.referenceMetadata, forKey: .type)
            try container.encode(metadata, forKey: .metadata)
        case .displayedToUser:
            try container.encode(ResponseType.displayedToUser, forKey: .type)
        case .operationCompleted:
            try container.encode(ResponseType.operationCompleted, forKey: .type)
        case .authorizationApproved:
            try container.encode(ResponseType.authorizationApproved, forKey: .type)
        case let .revealSessionData(paragraph):
            try container.encode(ResponseType.revealSessionData, forKey: .type)
            try container.encode(paragraph, forKey: .paragraph)
        case let .created(reference):
            try container.encode(ResponseType.created, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .revealSessionOpened(sessionID):
            try container.encode(ResponseType.revealSessionOpened, forKey: .type)
            try container.encode(sessionID, forKey: .sessionID)
        case let .restoredText(text):
            try container.encode(ResponseType.restoredText, forKey: .type)
            try container.encode(text, forKey: .text)
        case let .exported(path):
            try container.encode(ResponseType.exported, forKey: .type)
            try container.encode(path, forKey: .path)
        case let .orphanScan(result):
            try container.encode(ResponseType.orphanScan, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .execution(result):
            try container.encode(ResponseType.execution, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .secretOperation(output):
            try container.encode(ResponseType.secretOperation, forKey: .type)
            try container.encode(output, forKey: .output)
        case let .failure(code):
            try container.encode(ResponseType.failure, forKey: .type)
            try container.encode(code, forKey: .code)
        }
    }
}

public struct AuthenticatedIPCRequest: Codable, Equatable, Sendable {
    public let capabilityToken: CapabilityToken
    public let request: IPCRequest

    public init(capabilityToken: CapabilityToken, request: IPCRequest) {
        self.capabilityToken = capabilityToken
        self.request = request
    }
}

public enum IPCAuthenticationError: Error, Equatable, Sendable {
    case invalidCapabilityToken
}

public struct IPCAuthenticator: Sendable {
    public let expectedToken: CapabilityToken

    public init(expectedToken: CapabilityToken) {
        self.expectedToken = expectedToken
    }

    public func authenticate(_ request: AuthenticatedIPCRequest) throws -> IPCRequest {
        guard request.capabilityToken.constantTimeEquals(expectedToken) else {
            throw IPCAuthenticationError.invalidCapabilityToken
        }
        return request.request
    }
}
