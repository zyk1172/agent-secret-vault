import Foundation

public enum SecretCatalogAgentError: Error, Equatable, Sendable {
    case unavailable
    case legacyCatalogUnsupported
    case integrityMissing
    case externalModification
    case pendingExternalChange
    case invalidCatalog
    case agentWriteNotAllowed
    case revisionConflict
    case invalidOperation
    case approvalRequired
    /// The managed document or its integrity sidecar could not be committed.
    /// Callers receive only a stable diagnostic code, never a path, Markdown
    /// body, or underlying filesystem detail.
    case writeFailed
    case agentWriteApprovalUnavailable
    /// The selected formatting repair plan no longer describes the current
    /// bytes. Callers must check the file again before retrying.
    case formatRepairConflict
    /// The Catalog write failed and at least one newly-created opaque record
    /// could not be deleted. The ID is persisted in cleanup metadata for a
    /// later orphan scan/reconciliation; plaintext is never included.
    case cleanupRequired
}

/// The user-facing App-control setting for Agent catalog writes.  The
/// authorization state stays in the App/Agent control plane; MCP callers never
/// supply or manufacture a token, nonce, or lease.
public enum CatalogAgentWriteMode: String, Codable, CaseIterable, Sendable {
    case disabled
    /// Safe catalog editing is always a bounded user grant; it is never a
    /// persistent preference.
    case safe
    /// Kept for wire compatibility with older clients. New mutations must use
    /// CatalogMutationPolicyEngine instead of treating these as global gates.
    case metadata
    case structure

    public var displayName: String {
        switch self {
        case .disabled: return "禁止 Agent 修改"
        case .safe: return "允许安全目录编辑"
        case .metadata: return "仅允许普通元数据"
        case .structure: return "允许结构修改"
        }
    }

    public func permits(_ required: CatalogAgentWriteScope) -> Bool {
        switch self {
        case .disabled: return false
        case .safe: return true
        case .metadata: return required == .metadata
        case .structure: return true
        }
    }
}

public struct CatalogAgentWriteAuthorizationStatus: Codable, Equatable, Sendable {
    public let mode: CatalogAgentWriteMode
    public let expiresAt: Date?
    public let remainingUses: Int?

    public init(mode: CatalogAgentWriteMode, expiresAt: Date? = nil, remainingUses: Int? = nil) {
        self.mode = mode
        self.expiresAt = expiresAt
        self.remainingUses = remainingUses
    }

    public func isActive(at date: Date = Date()) -> Bool {
        guard mode != .disabled else { return false }
        guard let expiresAt else { return false }
        return expiresAt > date
    }
}

public enum CatalogAgentWriteAccessDuration: String, Codable, CaseIterable, Sendable {
    case singleUse = "single-use"
    /// Deprecated wire values. They remain decodable for old clients, but the
    /// service must reject them instead of creating a reusable grant.
    @available(*, deprecated, message: "Agent catalog authorization is bound to one semantic operation")
    case tenMinutes = "10-minutes"
    @available(*, deprecated, message: "Agent catalog authorization is bound to one semantic operation")
    case thirtyMinutes = "30-minutes"

    public static let allCases: [Self] = [.singleUse]

    public var displayName: String {
        switch self {
        case .singleUse: return "单次"
        case .tenMinutes: return "10 分钟"
        case .thirtyMinutes: return "30 分钟"
        }
    }

    public var lifetime: TimeInterval {
        switch self {
        case .singleUse: return 60
        case .tenMinutes: return 600
        case .thirtyMinutes: return 1800
        }
    }
}

public enum CatalogAgentWriteRequestSource: String, Codable, CaseIterable, Sendable {
    case codex
    case claude
    case openclaw
    case mcpClient = "mcp-client"

    public var displayName: String {
        // This is self-reported by an MCP caller and is only a display hint.
        "MCP 智能体"
    }
}

public enum CatalogAgentWriteOperation: String, Codable, CaseIterable, Sendable {
    case createIndex
    case createEntry
    case patchMetadata
    case commitDraft
    case addSecretPlaceholder
    case batchMutation

    public var displayName: String {
        switch self {
        case .createIndex: return "新建分组"
        case .createEntry: return "新建条目"
        case .patchMetadata: return "修改条目元数据"
        case .commitDraft: return "提交条目草稿"
        case .addSecretPlaceholder: return "新增加密字段占位"
        case .batchMutation: return "批量修改目录"
        }
    }
}

/// Exact, non-secret binding material for one Agent Catalog mutation.
public struct CatalogAgentWriteIntent: Codable, Equatable, Sendable {
    public let requestID: UUID?
    public let operation: CatalogAgentWriteOperation
    public let indexID: String?
    public let entryID: String?
    public let fieldKey: String?
    public let acceptedRevision: UInt64
    public let candidateSemanticSHA256: String

    public init(
        requestID: UUID? = nil,
        operation: CatalogAgentWriteOperation,
        indexID: String? = nil,
        entryID: String? = nil,
        fieldKey: String? = nil,
        acceptedRevision: UInt64,
        candidateSemanticSHA256: String
    ) {
        self.requestID = requestID
        self.operation = operation
        self.indexID = indexID
        self.entryID = entryID
        self.fieldKey = fieldKey
        self.acceptedRevision = acceptedRevision
        self.candidateSemanticSHA256 = candidateSemanticSHA256
    }

    public func bound(to requestID: UUID) -> Self {
        Self(
            requestID: requestID,
            operation: operation,
            indexID: indexID,
            entryID: entryID,
            fieldKey: fieldKey,
            acceptedRevision: acceptedRevision,
            candidateSemanticSHA256: candidateSemanticSHA256
        )
    }

    public func matches(_ other: Self) -> Bool {
        operation == other.operation
            && indexID == other.indexID
            && entryID == other.entryID
            && fieldKey == other.fieldKey
            && acceptedRevision == other.acceptedRevision
            && candidateSemanticSHA256 == other.candidateSemanticSHA256
    }
}

public enum CatalogAgentWriteReasonCategory: String, Codable, CaseIterable, Sendable {
    case knowledgeMaintenance = "knowledge-maintenance"
    case catalogRepair = "catalog-repair"
    case bulkImport = "bulk-import"
    case other

    public var displayName: String {
        switch self {
        case .knowledgeMaintenance: return "知识库维护"
        case .catalogRepair: return "目录修复"
        case .bulkImport: return "批量整理"
        case .other: return "其他目录维护"
        }
    }
}

public struct CatalogAgentWriteAccessRequest: Codable, Equatable, Identifiable, Sendable {
    public static let notificationName = Notification.Name(
        "com.agent-secret-vault.catalog.write-access-request"
    )

    public let id: UUID
    public let source: CatalogAgentWriteRequestSource
    public let reasonCategory: CatalogAgentWriteReasonCategory
    public let duration: CatalogAgentWriteAccessDuration
    public let createdAt: String
    /// Optional for decoding a legacy generic request. New service-created
    /// requests always carry an exact operation-bound intent.
    public let intent: CatalogAgentWriteIntent?
    public let expiresAt: String?
    /// Populated only by a trusted transport. MCP self-reporting leaves it nil.
    public let verifiedSource: String?

    public init(
        id: UUID = UUID(),
        source: CatalogAgentWriteRequestSource,
        reasonCategory: CatalogAgentWriteReasonCategory,
        duration: CatalogAgentWriteAccessDuration = .singleUse,
        createdAt: String = ISO8601DateFormatter().string(from: Date()),
        intent: CatalogAgentWriteIntent? = nil,
        expiresAt: String? = nil,
        verifiedSource: String? = nil
    ) {
        self.id = id
        self.source = source
        self.reasonCategory = reasonCategory
        self.duration = duration
        self.createdAt = createdAt
        self.intent = intent
        self.expiresAt = expiresAt
        self.verifiedSource = verifiedSource
    }

    public var displayName: String {
        verifiedSource ?? "未验证的 MCP 客户端"
    }
}

/// The smallest unit of authority checked by the Agent catalog service.
/// Structure authority is intentionally a superset of metadata authority;
/// callers never carry a token or nonce for this scope.
public enum CatalogAgentWriteScope: String, Codable, CaseIterable, Sendable {
    case metadata
    case structure

    public func permits(_ required: CatalogAgentWriteScope) -> Bool {
        self == .structure || self == required
    }
}

/// Metadata-only patch accepted by the Agent catalog service.  The service
/// rejects secret transitions and secret-bearing values on this path; secret
/// binding has a separate operation and approval boundary.
public struct CatalogMetadataPatch: Codable, Equatable, Sendable {
    public let title: String?
    public let aliases: [String]?
    public let tags: [String]?
    public let endpoints: [CatalogEndpoint]?
    public let notes: String?
    public let fields: [SecretCatalogFieldValue]?

    public init(
        title: String? = nil,
        aliases: [String]? = nil,
        tags: [String]? = nil,
        endpoints: [CatalogEndpoint]? = nil,
        notes: String? = nil,
        fields: [SecretCatalogFieldValue]? = nil
    ) {
        self.title = title
        self.aliases = aliases
        self.tags = tags
        self.endpoints = endpoints
        self.notes = notes
        self.fields = fields
    }
}

public struct CatalogDraftRequest: Codable, Equatable, Sendable {
    public let indexID: String
    public let title: String
    public let type: String
    public let aliases: [String]
    public let tags: [String]
    public let endpoints: [CatalogEndpoint]
    public let notes: String?
    public let fields: [SecretCatalogFieldValue]

    public init(
        indexID: String,
        title: String,
        type: String = "credential",
        aliases: [String] = [],
        tags: [String] = [],
        endpoints: [CatalogEndpoint] = [],
        notes: String? = nil,
        fields: [SecretCatalogFieldValue] = []
    ) {
        self.indexID = indexID
        self.title = title
        self.type = type
        self.aliases = aliases
        self.tags = tags
        self.endpoints = endpoints
        self.notes = notes
        self.fields = fields
    }
}

public struct CatalogDraft: Codable, Equatable, Sendable {
    public let draftID: String
    public let baseRevision: UInt64
    public let entry: SecretCatalogEntryMatch

    public init(draftID: String, baseRevision: UInt64, entry: SecretCatalogEntryMatch) {
        self.draftID = draftID
        self.baseRevision = baseRevision
        self.entry = entry
    }
}

/// Plaintext supplied only for the duration of an App-controlled Entry edit.
/// It is never a Catalog value and is consumed by the service before the
/// resulting opaque reference is written to Markdown.
public struct CatalogSecretInput: Codable, Equatable, Sendable {
    public let key: String
    public let label: String
    public let plaintext: String

    public init(key: String, label: String, plaintext: String) {
        self.key = key
        self.label = label
        self.plaintext = plaintext
    }
}

public struct CatalogWriteResult: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let entry: SecretCatalogEntryMatch?
    /// Opaque reference returned only by the App-controlled secure-input
    /// flow. It is never plaintext and is optional so existing catalog write
    /// responses remain wire-compatible.
    public let secretReference: String?

    public init(
        revision: UInt64,
        entry: SecretCatalogEntryMatch? = nil,
        secretReference: String? = nil
    ) {
        self.revision = revision
        self.entry = entry
        self.secretReference = secretReference
    }
}

/// Safe diagnostics produced by the running SVLTAgent for the selected
/// Catalog document. These values deliberately contain no path, document
/// bytes, title, reference, or plaintext. They are useful for local
/// installation diagnostics only; Catalog mutations still expose the stable
/// CATALOG_WRITE_FAILED code to IPC/MCP callers.
public struct CatalogFilePreflight: Codable, Equatable, Sendable {
    public let read: String
    public let parentTempCreate: String
    public let parentTempFsync: String
    public let parentRename: String
    public let parentFsync: String

    public init(
        read: String,
        parentTempCreate: String,
        parentTempFsync: String,
        parentRename: String,
        parentFsync: String
    ) {
        self.read = read
        self.parentTempCreate = parentTempCreate
        self.parentTempFsync = parentTempFsync
        self.parentRename = parentRename
        self.parentFsync = parentFsync
    }
}

public enum CatalogDiagnosticSeverity: String, Codable, CaseIterable, Sendable {
    case error
    case warning
}

public enum CatalogDiagnosticScope: String, Codable, CaseIterable, Sendable {
    case document
    case policy
    case index
    case entry
    case field
    case unmanaged
}

/// A source-map location produced by the Catalog v3 parser. Coordinates are
/// one-based and refer to the original Markdown source, not a re-rendered
/// approximation.
public struct CatalogSourceSpan: Codable, Equatable, Sendable {
    public let startLine: Int
    public let startColumn: Int
    public let endLine: Int
    public let endColumn: Int

    public init(startLine: Int, startColumn: Int, endLine: Int, endColumn: Int) {
        self.startLine = max(1, startLine)
        self.startColumn = max(1, startColumn)
        self.endLine = max(self.startLine, endLine)
        self.endColumn = max(1, endColumn)
    }
}

/// A source-safe Catalog diagnostic. Line and column are hints for an editor;
/// the message must never echo Markdown values, secret references, paths, or
/// plaintext.
public struct CatalogValidationDiagnostic: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let severity: CatalogDiagnosticSeverity
    public let code: String
    public let line: Int
    public let column: Int?
    public let endLine: Int?
    public let endColumn: Int?
    public let scope: CatalogDiagnosticScope
    public let message: String
    public let hint: String?

    public init(
        id: String? = nil,
        severity: CatalogDiagnosticSeverity = .error,
        code: String,
        line: Int,
        column: Int? = nil,
        endLine: Int? = nil,
        endColumn: Int? = nil,
        scope: CatalogDiagnosticScope,
        message: String,
        hint: String? = nil
    ) {
        self.id = id ?? "\(code):\(line):\(column ?? 1)"
        self.severity = severity
        self.code = code
        self.line = max(1, line)
        self.column = column
        self.endLine = endLine
        self.endColumn = endColumn
        self.scope = scope
        self.message = message
        self.hint = hint
    }
}

/// Read-only validation output shared by the App, MCP bridge, and Obsidian
/// plugin. It contains no document body or secret-bearing field values.
public struct CatalogValidationReport: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64?
    public let rawSHA256: String?
    public let pendingExternalChange: CatalogPendingExternalChange?
    public let diagnostics: [CatalogValidationDiagnostic]

    public init(
        status: SecretCatalogSearchStatus,
        revision: UInt64? = nil,
        rawSHA256: String? = nil,
        pendingExternalChange: CatalogPendingExternalChange? = nil,
        diagnostics: [CatalogValidationDiagnostic] = []
    ) {
        self.status = status
        self.revision = revision
        self.rawSHA256 = rawSHA256
        self.pendingExternalChange = pendingExternalChange
        self.diagnostics = diagnostics
    }
}

/// A source-safe formatting repair proposal. The plan carries only hashes,
/// diagnostics, and their classification; the Markdown candidate stays in
/// the Core/Store process and is never transported to MCP clients.
public struct CatalogFormatRepairPlan: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let currentRawSHA256: String
    public let diagnostics: [CatalogValidationDiagnostic]
    public let repairableDiagnostics: [CatalogValidationDiagnostic]
    public let unrepairableDiagnostics: [CatalogValidationDiagnostic]
    public let proposedRawSHA256: String?
    public let semanticSHA256: String?

    public init(
        id: UUID = UUID(),
        currentRawSHA256: String,
        diagnostics: [CatalogValidationDiagnostic],
        repairableDiagnostics: [CatalogValidationDiagnostic] = [],
        unrepairableDiagnostics: [CatalogValidationDiagnostic] = [],
        proposedRawSHA256: String? = nil,
        semanticSHA256: String? = nil
    ) {
        self.id = id
        self.currentRawSHA256 = currentRawSHA256
        self.diagnostics = diagnostics
        self.repairableDiagnostics = repairableDiagnostics
        self.unrepairableDiagnostics = unrepairableDiagnostics
        self.proposedRawSHA256 = proposedRawSHA256
        self.semanticSHA256 = semanticSHA256
    }

    public var canRepair: Bool {
        !repairableDiagnostics.isEmpty &&
            unrepairableDiagnostics.isEmpty &&
            proposedRawSHA256 != nil
    }
}

public struct CatalogValidationResult: Codable, Equatable, Sendable {
    public let status: SecretCatalogSearchStatus
    public let revision: UInt64?
    public let rawSHA256: String?
    public let pendingExternalChange: CatalogPendingExternalChange?
    public let filePreflight: CatalogFilePreflight?
    public let diagnostics: [CatalogValidationDiagnostic]

    public init(
        status: SecretCatalogSearchStatus,
        revision: UInt64? = nil,
        rawSHA256: String? = nil,
        pendingExternalChange: CatalogPendingExternalChange? = nil,
        filePreflight: CatalogFilePreflight? = nil,
        diagnostics: [CatalogValidationDiagnostic] = []
    ) {
        self.status = status
        self.revision = revision
        self.rawSHA256 = rawSHA256
        self.pendingExternalChange = pendingExternalChange
        self.filePreflight = filePreflight
        self.diagnostics = diagnostics
    }
}

/// Opaque identity for the exact external document that was shown for local
/// approval.  Hashes are concurrency tokens only; no Markdown or secret value
/// is exposed through AppControl.
public struct CatalogPendingExternalChange: Codable, Equatable, Sendable {
    public let acceptedRevision: UInt64
    public let rawSHA256: String
    public let semanticSHA256: String

    public init(acceptedRevision: UInt64, rawSHA256: String, semanticSHA256: String) {
        self.acceptedRevision = acceptedRevision
        self.rawSHA256 = rawSHA256
        self.semanticSHA256 = semanticSHA256
    }
}
