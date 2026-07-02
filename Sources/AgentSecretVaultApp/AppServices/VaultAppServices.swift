import CryptoKit
import Foundation
import VaultCore
import VaultIPC

public protocol RevealSessionPresenting: Sendable {
    func present(sessionID: String, store: RevealSessionStore) async
}

public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}

public enum VaultAppServicesOrphanScanError: Error, Equatable, Sendable {
    case scanUnavailable
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

public actor VaultAppServices: WorkbenchServicing {
    private let textEncryptor: any TextEncrypting
    private let activeRoot: URL?
    private let recordLister: (any RecordListing)?
    private let recordResolver: VaultRecordResolver?
    private let masterKey: SymmetricKey?
    private let masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
    private let isUnlockedProvider: (@Sendable () async -> Bool)
    private let revealSessionStore: RevealSessionStore
    private let revealSessionPresenter: any RevealSessionPresenting
    private let orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)?
    private let statusObserver: (@Sendable (WorkbenchStatus) async -> Void)?
    private let auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)?
    private let auditLog: EncryptedAuditLog?
    private let exportDirectory: URL
    private var pluginConnected = false

    public init(
        textEncryptor: any TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = RevealSessionPresenter(),
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        exportDirectory: URL? = nil
    ) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
        self.recordLister = recordLister
        self.recordResolver = recordResolver
        self.masterKey = masterKey
        self.masterKeyProvider = masterKeyProvider
        self.isUnlockedProvider = isUnlockedProvider
        self.revealSessionStore = revealSessionStore
        self.revealSessionPresenter = revealSessionPresenter
        self.orphanScanObserver = orphanScanObserver
        self.statusObserver = statusObserver
        self.auditObserver = auditObserver
        self.auditLog = auditLog
        self.exportDirectory = (exportDirectory ?? Self.defaultExportDirectory()).standardizedFileURL
    }

    public init(
        encryptSelection: any EncryptSelectionCoordinating & TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = RevealSessionPresenter(),
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        exportDirectory: URL? = nil
    ) {
        self.init(
            textEncryptor: encryptSelection,
            activeRoot: activeRoot,
            recordLister: recordLister,
            recordResolver: recordResolver,
            masterKey: masterKey,
            masterKeyProvider: masterKeyProvider,
            isUnlockedProvider: isUnlockedProvider,
            revealSessionStore: revealSessionStore,
            revealSessionPresenter: revealSessionPresenter,
            orphanScanObserver: orphanScanObserver,
            statusObserver: statusObserver,
            auditObserver: auditObserver,
            auditLog: auditLog,
            exportDirectory: exportDirectory
        )
    }

    public func recordPluginActivity() async {
        guard !pluginConnected else {
            return
        }
        pluginConnected = true
        await statusObserver?(status())
        await emitAudit(
            action: "MCP 连接",
            target: "agent-secret-vault",
            referenceCount: 0,
            result: "已连接"
        )
    }

    public func status() async -> WorkbenchStatus {
        WorkbenchStatus(
            locked: !(await isUnlockedProvider()),
            ipcAvailable: true,
            activeKnowledgeBaseRoot: activeRoot?.path,
            pluginConnected: pluginConnected
        )
    }

    public func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        let reference = try await textEncryptor.encryptText(
            plaintext,
            label: label,
            policy: policy
        )
        return reference.description
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

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        let resolvedParagraph = try await resolveReferences(references: references, context: context)
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

    public func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        let restored = try await resolveReferences(references: references, context: context)
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
        let resolvedText = try await resolveReferences(references: references, context: context)
        let destination = try validatedExportDestination(destinationPath)
        try resolvedText.write(to: destination, atomically: true, encoding: .utf8)
        await emitAudit(
            action: "写入本地文件",
            target: destination.lastPathComponent,
            referenceCount: references.count,
            result: "成功"
        )
        return destination.path
    }

    private func resolveReferences(references: [String], context: RevealContext) async throws -> String {
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
            reason: context.reason
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

        return try resolveTemplate(context.template, ranges: context.ranges, plaintexts: plaintexts)
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

    private func resolvedMasterKey(for policy: SecretPolicy, reason: String) async throws -> SymmetricKey {
        if let masterKey {
            return masterKey
        }
        guard let masterKeyProvider else {
            throw VaultAppServicesRevealError.revealUnavailable
        }
        return try await masterKeyProvider(policy, reason)
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
        do {
            let key = try await resolvedMasterKey(for: .read, reason: "记录 Agent 自动化审计")
            try await auditLog.append(
                AuditEvent(
                    timestamp: entry.occurredAt,
                    integration: "agent-secret-vault-mcp",
                    referenceID: nil,
                    operation: auditOperation(for: action),
                    risk: 0,
                    authorizationOutcome: .notRequired,
                    declaredTarget: entry.target,
                    status: auditStatus(for: result),
                    exitCode: nil
                ),
                masterKey: key
            )
        } catch {
            return
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

    private func sanitizedReason(_ reason: String) -> String {
        let redacted = reason
            .replacing(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/, with: "[SECRET_REFERENCE]")
            .replacing(/(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*["']?[^"',\s}]+/.ignoresCase(), with: "$1=[REDACTED_SECRET]")
        return String(redacted.prefix(160))
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
