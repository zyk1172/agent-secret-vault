import Foundation
import os

/// Obsidian-native, lossless Markdown codec for Catalog v3.
///
/// Headings and field bodies remain ordinary Markdown. SVLT markers delimit
/// managed ranges, allowing a writer to patch one object without reformatting
/// the rest of the file.
public enum SensitiveCatalogDocumentCodec {
    private static let parseFailureLogger = Logger(subsystem: "AgentSecretVault", category: "CatalogParse")
    public static let marker = "<!-- SVLT-CATALOG schema=\"3\" -->"
    public static let v3Marker = marker
    public static let v2Marker = "<!-- SVLT-MANAGED-CATALOG schema=\"2\" -->"
    public static let rootTitle = "敏感信息"

    public enum DocumentFormat: String, Codable, Equatable, Sendable {
        case unmanaged
        case legacy
        case managedV2
        case managedV3
    }

    public struct V2MigrationResult: Equatable, Sendable {
        public let document: SecretCatalogDocument
        public let unmanagedMarkdown: String?

        public init(document: SecretCatalogDocument, unmanagedMarkdown: String? = nil) {
            self.document = document
            self.unmanagedMarkdown = unmanagedMarkdown
        }
    }

    public static func format(_ data: Data) -> DocumentFormat {
        guard let text = String(data: data, encoding: .utf8) else { return .unmanaged }
        return format(text)
    }

    public static func format(_ text: String) -> DocumentFormat {
        let normalized = normalizeNewlines(text)
        if normalized.hasPrefix(v3Marker + "\n") || normalized == v3Marker { return .managedV3 }
        if normalized.hasPrefix(v2Marker + "\n") || normalized == v2Marker { return .managedV2 }
        if text.contains("agent-secret-vault-sensitive-information: 1") { return .legacy }
        return .unmanaged
    }

    public static func decode(_ data: Data) throws -> SecretCatalogDocument {
        guard let text = String(data: data, encoding: .utf8) else {
            throw SecretCatalogValidationError.unmanagedContent
        }
        return try decode(text)
    }

    public static func decode(_ text: String) throws -> SecretCatalogDocument {
        switch format(text) {
        case .managedV3:
            do { return try parseV3(text).document }
            catch let error as SecretCatalogValidationError {
                parseFailureLogger.error("SVLT Catalog parse failure: reason=\(String(describing: error), privacy: .public)")
                throw error
            }
        case .managedV2: return try decodeV2(text)
        case .legacy: throw SecretCatalogValidationError.legacyDocument
        case .unmanaged: throw SecretCatalogValidationError.invalidMarker
        }
    }

    /// Validates a Catalog without touching the filesystem. The returned
    /// diagnostics are intentionally source-safe: only stable codes,
    /// locations, and remediation text leave the Core parser.
    public static func validateDetailed(_ data: Data) -> CatalogValidationReport {
        let rawSHA256 = CatalogSemanticDigest.rawSHA256(data)
        guard let text = String(data: data, encoding: .utf8) else {
            return CatalogValidationReport(
                status: .invalidCatalog,
                rawSHA256: rawSHA256,
                diagnostics: [diagnostic(
                    code: "CATALOG_UTF8_INVALID",
                    line: 1,
                    scope: .document,
                    message: "目录文件不是有效的 UTF-8 文本。",
                    hint: "请使用 UTF-8 保存敏感信息.md。"
                )]
            )
        }

        switch format(text) {
        case .managedV3:
            do {
                _ = try parseV3(text)
                return CatalogValidationReport(status: .found, rawSHA256: rawSHA256)
            } catch let error as SecretCatalogValidationError {
                return CatalogValidationReport(
                    status: .invalidCatalog,
                    rawSHA256: rawSHA256,
                    diagnostics: [diagnostic(for: error, text: text)]
                )
            } catch {
                return CatalogValidationReport(
                    status: .invalidCatalog,
                    rawSHA256: rawSHA256,
                    diagnostics: [diagnostic(
                        code: "CATALOG_VALIDATION_FAILED",
                        line: 1,
                        scope: .document,
                        message: "目录结构无法验证。",
                        hint: "请检查 SVLT v3 marker、策略块和对象块。"
                    )]
                )
            }
        case .managedV2:
            return CatalogValidationReport(
                status: .integrityMissing,
                rawSHA256: rawSHA256,
                diagnostics: [diagnostic(
                    code: "CATALOG_V2_REQUIRES_MIGRATION",
                    line: 1,
                    scope: .document,
                    message: "这是旧版 Catalog v2 文件。",
                    hint: "请在 SVLT App 中完成迁移。"
                )]
            )
        case .legacy:
            return CatalogValidationReport(
                status: .legacyCatalogUnsupported,
                rawSHA256: rawSHA256,
                diagnostics: [diagnostic(
                    code: "CATALOG_LEGACY_UNSUPPORTED",
                    line: 1,
                    scope: .document,
                    message: "这是旧版敏感信息目录格式。",
                    hint: "请在 SVLT App 中迁移到 managed v3。"
                )]
            )
        case .unmanaged:
            let hasReference = !MarkdownReferenceScanner.references(in: text).isEmpty
            return CatalogValidationReport(
                status: .legacyCatalogUnsupported,
                rawSHA256: rawSHA256,
                diagnostics: [diagnostic(
                    code: hasReference ? "UNMANAGED_SECRET_REFERENCE" : "CATALOG_MARKER_MISSING",
                    line: hasReference ? lineContaining("secret://", in: text) : firstContentLine(in: text),
                    scope: hasReference ? .unmanaged : .document,
                    message: hasReference
                        ? "未托管区域不能出现敏感信息引用。"
                        : "缺少 SVLT v3 Catalog marker。",
                    hint: hasReference
                        ? "请将该引用放入受 SVLT 管理的 Field 中。"
                        : "请使用 `<!-- SVLT-CATALOG schema=\"3\" -->` 开头的文件。"
                )]
            )
        }
    }

    private static func diagnostic(
        code: String,
        line: Int,
        scope: CatalogDiagnosticScope,
        message: String,
        hint: String
    ) -> CatalogValidationDiagnostic {
        CatalogValidationDiagnostic(
            code: code,
            line: line,
            column: 1,
            scope: scope,
            message: message,
            hint: hint
        )
    }

    private static func diagnostic(
        for error: SecretCatalogValidationError,
        text: String
    ) -> CatalogValidationDiagnostic {
        let mapping: (String, CatalogDiagnosticScope, String, String, String) = {
            switch error {
            case .invalidMarker:
                ("CATALOG_MARKER_INVALID", .document, "Catalog marker 缺失或无效。", "文件第一行必须是 SVLT v3 marker。", "<!-- SVLT-CATALOG schema=\"3\" -->")
            case .legacyDocument:
                ("CATALOG_LEGACY_UNSUPPORTED", .document, "这是旧版敏感信息目录格式。", "请在 SVLT App 中迁移到 managed v3。", "使用当前 SVLT v3 schema。")
            case .invalidPolicyBlock, .ambiguousLegacyPolicy:
                ("POLICY_BLOCK_INVALID", .policy, "策略块缺失、重复或内容不匹配。", "请从当前版本的 SVLT App 重新生成策略块。", "检查 SVLT-POLICY-BEGIN 与 SVLT-POLICY-END。")
            case .malformedJSON:
                ("MARKER_JSON_INVALID", .document, "SVLT 对象 marker 不是有效 JSON。", "检查对应 marker 内的 JSON 语法和必填字段。", "保持 marker JSON 为单行有效对象。")
            case .unknownSchema, .unsupportedSchemaVersion:
                ("SCHEMA_UNSUPPORTED", .document, "对象使用了不受支持的 schema。", "请使用当前 SVLT v3 schema。", "不要手动升级或改写 schema 名称。")
            case .invalidID:
                ("OBJECT_ID_INVALID", .document, "对象 ID 格式无效。", "检查对象 marker 中的 ID。", "ID 必须是 SVLT 生成的 26 位不透明 ID。")
            case .duplicateIndexID:
                ("INDEX_ID_DUPLICATE", .index, "分组 ID 重复。", "为重复分组重新生成 ID。", "每个分组必须有唯一 ID。")
            case .duplicateEntryID:
                ("ENTRY_ID_DUPLICATE", .entry, "条目 ID 重复。", "为重复条目重新生成 ID。", "每个条目必须有唯一 ID。")
            case .entryReferencesMissingIndex:
                ("ENTRY_INDEX_MISSING", .entry, "条目所属分组不存在或位置不正确。", "把条目放入对应分组，或修正 indexId。", "检查 SVLT-ENTRY marker 与分组边界。")
            case .invalidVisibleText:
                ("VISIBLE_TEXT_INVALID", .document, "可见文本不符合 Catalog 约束。", "移除换行或不受支持的可见值。", "检查标题、标签和别名。")
            case .invalidFieldValue:
                ("FIELD_VALUE_INVALID", .field, "字段值与字段类型不匹配。", "检查 SVLT-FIELD 的 type 和字段正文。", "让正文值符合字段 type。")
            case .duplicateFieldKey:
                ("FIELD_KEY_DUPLICATE", .field, "同一条目中存在重复字段 key。", "合并或删除重复字段。", "每个条目的字段 key 必须唯一。")
            case .valueAndSecretReference:
                ("FIELD_VALUE_AND_REFERENCE", .field, "字段不能同时包含值和敏感信息引用。", "保留引用或普通值其中一种。", "检查 SVLT-FIELD 正文。")
            case .secretFieldContainsValue, .secretFieldKeyMustBeSecret:
                ("SECRET_FIELD_PLAINTEXT", .field, "敏感字段不能包含明文。", "使用 App 填写或替换密码，Markdown 只保存不透明引用。", "不要把密码、Token 或密钥写入 Markdown。")
            case .nonSecretFieldContainsSecretReference, .secretReferenceInMetadata, .invalidSecretReference:
                ("SECRET_REFERENCE_INVALID_LOCATION", .field, "敏感信息引用出现在不允许的位置或格式无效。", "只在合法的 secret Field 中使用有效引用。", "检查字段 type 和 secret:// 引用格式。")
            case .invalidEndpoint:
                ("ENDPOINT_INVALID", .entry, "服务地址字段无效。", "检查 endpoint 的协议、主机和端口。", "保持 endpoint 为合法 Catalog 结构。")
            case .invalidHeading:
                ("HEADING_INVALID", .document, "Markdown heading 与 Catalog 结构不匹配。", "检查分组使用 ##、条目使用 ###，并保持 marker 顺序。", "heading 必须位于对应 marker 内。")
            case .missingIndexBlock:
                ("INDEX_BLOCK_MISSING", .index, "分组 marker 或 heading 不完整。", "补齐分组的 marker 和 ## heading。", "每个 Index 必须有完整对象块。")
            case .missingEntryBlock:
                ("ENTRY_BLOCK_MISSING", .entry, "条目 marker 或 heading 不完整。", "补齐条目的 marker 和 ### heading。", "每个 Entry 必须有完整对象块。")
            case .headingDoesNotMatchBlock:
                ("HEADING_MARKER_MISMATCH", .entry, "heading 与对应 marker 的标题不一致。", "使 heading 与 marker 中的标题保持一致。", "检查对应的 ## 或 ### heading。")
            case .unmanagedContent:
                ("UNMANAGED_CONTENT_INVALID", .unmanaged, "未托管内容包含 Catalog 控制标记。", "移除伪造 marker，或将内容交由 SVLT App 管理。", "未托管区域不能注入 SVLT marker。")
            case .referenceSetChanged:
                ("REFERENCE_SET_CHANGED", .document, "文档引用集合与预期不一致。", "重新从当前 accepted state 生成修改。", "不要在写入窗口外改变引用集合。")
            case .pendingExternalChange:
                ("PENDING_EXTERNAL_CHANGE", .document, "存在尚未批准的外部语义修改。", "在 SVLT App 中查看差异并完成独立审批。", "等待外部变更审批。")
            }
        }()
        return diagnostic(
            code: mapping.0,
            line: lineFor(error: error, in: text),
            scope: mapping.1,
            message: mapping.2,
            hint: mapping.3
        )
    }

    private static func lineFor(error: SecretCatalogValidationError, in text: String) -> Int {
        switch error {
        case .invalidPolicyBlock, .ambiguousLegacyPolicy:
            return lineContaining("SVLT-POLICY", in: text)
        case .secretFieldContainsValue, .secretFieldKeyMustBeSecret,
             .valueAndSecretReference, .duplicateFieldKey, .invalidFieldValue,
             .nonSecretFieldContainsSecretReference, .invalidSecretReference,
             .secretReferenceInMetadata:
            return lineContaining("SVLT-FIELD", in: text)
        case .headingDoesNotMatchBlock:
            return firstHeadingLine(in: text)
        case .missingEntryBlock, .entryReferencesMissingIndex, .duplicateEntryID:
            return lineContaining("SVLT-ENTRY", in: text)
        case .missingIndexBlock, .duplicateIndexID:
            return lineContaining("SVLT-INDEX", in: text)
        case .unmanagedContent:
            return firstContentLine(in: text)
        default:
            return firstContentLine(in: text)
        }
    }

    private static func lineContaining(_ needle: String, in text: String) -> Int {
        let lines = text.components(separatedBy: "\n")
        return max(1, (lines.firstIndex { $0.contains(needle) } ?? 0) + 1)
    }

    private static func firstHeadingLine(in text: String) -> Int {
        let lines = text.components(separatedBy: "\n")
        return max(1, (lines.firstIndex { $0.trimmingCharacters(in: .whitespaces).hasPrefix("#") } ?? 0) + 1)
    }

    private static func firstContentLine(in text: String) -> Int {
        let lines = text.components(separatedBy: "\n")
        return max(1, (lines.firstIndex { !$0.trimmingCharacters(in: .whitespaces).isEmpty } ?? 0) + 1)
    }

    public static func encode(
        _ document: SecretCatalogDocument,
        unmanagedMarkdown: String? = nil
    ) throws -> String {
        try document.validate()
        var lines = [v3Marker, "# \(rootTitle)", ""]
        lines.append(contentsOf: SVLTAgentCatalogPolicy.documentPolicyBlock.components(separatedBy: "\n"))
        lines.append("")
        if let unmanagedMarkdown {
            let normalized = try validatedUnmanagedMarkdown(unmanagedMarkdown)
            if !normalized.isEmpty {
                lines.append(contentsOf: normalized.components(separatedBy: "\n"))
                lines.append("")
            }
        }
        for (offset, index) in document.indexes.enumerated() {
            if offset > 0 { lines.append("") }
            lines.append(contentsOf: renderIndex(index, entries: document.entries.filter { $0.indexId == index.id }))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func canonicalData(
        _ document: SecretCatalogDocument,
        unmanagedMarkdown: String? = nil
    ) throws -> Data {
        Data(try encode(document, unmanagedMarkdown: unmanagedMarkdown).utf8)
    }

    /// Remove the two-entry policy catalog that was emitted by the v2 App.
    /// The matcher is intentionally structural and content-based: an index
    /// with only one coincidental title is not deleted during migration.
    public static func migrateV2DocumentForV3(_ document: SecretCatalogDocument) throws -> SecretCatalogDocument {
        try migrateV2DocumentForV3WithNotes(document).document
    }

    public static func migrateV2DocumentForV3WithNotes(_ document: SecretCatalogDocument) throws -> V2MigrationResult {
        try document.validate()
        let policyIndexes = document.indexes.filter { $0.title == "SVLT 管理规范" }
        guard policyIndexes.isEmpty == false else { return V2MigrationResult(document: document) }
        guard policyIndexes.count == 1, let policyIndex = policyIndexes.first else {
            throw SecretCatalogValidationError.ambiguousLegacyPolicy
        }

        let policyEntries = document.entries.filter { $0.indexId == policyIndex.id }
        let expectedTitles: Set<String> = ["Agent 写入规范", "目录说明"]
        guard policyEntries.count == expectedTitles.count,
              Set(policyEntries.map(\.title)) == expectedTitles,
              policyEntries.allSatisfy({ $0.fields.allSatisfy { $0.secretRef == nil } })
        else {
            throw SecretCatalogValidationError.ambiguousLegacyPolicy
        }

        let supportingText = policyEntries
            .flatMap { entry in
                [entry.notes ?? ""]
                    + entry.aliases
                    + entry.tags
                    + entry.fields.flatMap { field in
                        [field.label] + Self.visibleStrings(field.value)
                    }
            }
            .joined(separator: "\n")
        let hasAgentPolicyMarker = supportingText.localizedCaseInsensitiveContains("agent")
            || supportingText.contains("智能体")
        let hasCatalogPolicyMarker = supportingText.localizedCaseInsensitiveContains("catalog")
            || supportingText.contains("写入")
            || supportingText.contains("secret://")
            || supportingText.contains("SVLT")
        guard hasAgentPolicyMarker && hasCatalogPolicyMarker else {
            throw SecretCatalogValidationError.ambiguousLegacyPolicy
        }

        let remainingIndexes = document.indexes.filter { $0.id != policyIndex.id }
        let remainingEntries = document.entries.filter { $0.indexId != policyIndex.id }
        let migrated = SecretCatalogDocument(indexes: remainingIndexes, entries: remainingEntries)
        try migrated.validate()
        let directoryDescription = policyEntries.first(where: { $0.title == "目录说明" })
            .flatMap(renderLegacyDirectoryDescription)
        return V2MigrationResult(document: migrated, unmanagedMarkdown: directoryDescription)
    }

    /// v2 is input-only and exists for the explicit App migration flow.
    public static func encodeV2(_ document: SecretCatalogDocument) throws -> String {
        try document.validate()
        let indexes = document.indexes.map {
            SecretCatalogIndex(id: $0.id, title: $0.title, aliases: $0.aliases, tags: $0.tags, schema: SecretCatalogIndex.legacySchemaName)
        }
        let entries = document.entries.map {
            SecretCatalogEntry(id: $0.id, indexId: $0.indexId, title: $0.title, type: $0.type, aliases: $0.aliases, endpoints: $0.endpoints, fields: $0.fields, notes: $0.notes, tags: $0.tags, schema: SecretCatalogEntry.legacySchemaName)
        }
        let fence = String(repeating: String(UnicodeScalar(96)!), count: 3)
        var lines = [v2Marker, "# \(rootTitle)", "", "> 本文件由 SVLT 管理。请勿直接修改结构化数据。", "> Agent 必须使用 SVLT MCP Catalog 工具修改。", ""]
        for (offset, index) in indexes.enumerated() {
            if offset > 0 { lines.append(contentsOf: ["", ""]) }
            lines += ["## \(index.title)", "", fence + "json", try canonicalJSON(index), fence]
            for entry in entries where entry.indexId == index.id {
                lines += ["", "", "### \(entry.title)", "", fence + "json", try canonicalJSON(entry), fence]
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func isManagedV2(_ data: Data) -> Bool { format(data) == .managedV2 }
    public static func isManagedV2(_ text: String) -> Bool { format(text) == .managedV2 }
    public static func isManagedV3(_ data: Data) -> Bool { format(data) == .managedV3 }
    public static func isManagedV3(_ text: String) -> Bool { format(text) == .managedV3 }

    /// Apply only the source ranges needed to turn old into new.
    public static func minimalPatch(_ data: Data, from old: SecretCatalogDocument, to new: SecretCatalogDocument) throws -> Data {
        guard format(data) == .managedV3 else { return try canonicalData(new) }
        try old.validate()
        try new.validate()
        let parsed = try parseV3(try utf8(data))
        guard parsed.document == old else { throw SecretCatalogValidationError.referenceSetChanged }

        let oldIndexes = Dictionary(uniqueKeysWithValues: old.indexes.map { ($0.id, $0) })
        let newIndexes = Dictionary(uniqueKeysWithValues: new.indexes.map { ($0.id, $0) })
        let oldEntries = Dictionary(uniqueKeysWithValues: old.entries.map { ($0.id, $0) })
        let newEntries = Dictionary(uniqueKeysWithValues: new.entries.map { ($0.id, $0) })
        var patches: [Patch] = []
        var deletedIndexes = Set<String>()
        var deletedEntries = Set<String>()
        var newIndexesOnDisk = Set<String>()

        for index in old.indexes where newIndexes[index.id] == nil {
            guard let source = parsed.source.indexes[index.id] else { throw SecretCatalogValidationError.missingIndexBlock }
            patch(&patches, source.blockRange, Data())
            deletedIndexes.insert(index.id)
        }
        for index in new.indexes where oldIndexes[index.id] == nil {
            newIndexesOnDisk.insert(index.id)
            let at = indexInsertOffset(index.id, new.indexes, parsed.source, data.count)
            let boundary = at == 0 || data[at - 1] == 0x0A ? "" : "\n"
            let rendered = boundary + renderIndex(index, entries: new.entries.filter { $0.indexId == index.id }).joined(separator: "\n") + "\n"
            patch(&patches, at..<at, Data(rendered.utf8), order: new.indexes.firstIndex { $0.id == index.id } ?? 0)
        }
        for id in Set(oldIndexes.keys).intersection(newIndexes.keys) {
            guard !deletedIndexes.contains(id), let oldIndex = oldIndexes[id], let newIndex = newIndexes[id], let source = parsed.source.indexes[id] else { continue }
            if oldIndex.aliases != newIndex.aliases || oldIndex.tags != newIndex.tags {
                patch(&patches, source.markerRange, Data(renderIndexMarker(newIndex).utf8))
            }
            if oldIndex.title != newIndex.title {
                patch(&patches, source.headingRange, Data("## \(newIndex.title)".utf8))
            }
        }

        for entry in old.entries where newEntries[entry.id] == nil {
            if deletedIndexes.contains(entry.indexId) { continue }
            guard let source = parsed.source.entries[entry.id] else { throw SecretCatalogValidationError.missingEntryBlock }
            patch(&patches, source.blockRange, Data())
            deletedEntries.insert(entry.id)
        }
        for entry in new.entries where oldEntries[entry.id] == nil {
            if newIndexesOnDisk.contains(entry.indexId) { continue }
            guard let indexSource = parsed.source.indexes[entry.indexId] else { throw SecretCatalogValidationError.entryReferencesMissingIndex }
            let at = entryInsertOffset(entry.id, entry.indexId, new.entries, parsed.source, indexSource.closeStart)
            patch(&patches, at..<at, Data((renderEntry(entry).joined(separator: "\n") + "\n").utf8), order: new.entries.firstIndex { $0.id == entry.id } ?? 0)
        }

        for id in Set(oldEntries.keys).intersection(newEntries.keys) {
            guard !deletedEntries.contains(id), let oldEntry = oldEntries[id], let newEntry = newEntries[id] else { continue }
            // Deleting an index removes its complete source block. Avoid an
            // overlapping entry patch when an entry is moved out of that
            // index in the same mutation.
            if deletedIndexes.contains(oldEntry.indexId) { continue }
            guard let source = parsed.source.entries[id] else { continue }
            if oldEntry.indexId != newEntry.indexId {
                patch(&patches, source.blockRange, Data())
                // A newly inserted index already renders all of its final
                // entries in one block, so the moved entry must not also be
                // inserted into a source range that did not exist before.
                if newIndexesOnDisk.contains(newEntry.indexId) { continue }
                guard let destination = parsed.source.indexes[newEntry.indexId] else { throw SecretCatalogValidationError.entryReferencesMissingIndex }
                let at = entryInsertOffset(id, newEntry.indexId, new.entries, parsed.source, destination.closeStart)
                patch(&patches, at..<at, Data((renderEntry(newEntry).joined(separator: "\n") + "\n").utf8), order: new.entries.firstIndex { $0.id == id } ?? 0)
                continue
            }
            if oldEntry.type != newEntry.type || oldEntry.aliases != newEntry.aliases || oldEntry.endpoints != newEntry.endpoints || oldEntry.tags != newEntry.tags {
                patch(&patches, source.markerRange, Data(renderEntryMarker(newEntry).utf8))
            }
            if oldEntry.title != newEntry.title {
                patch(&patches, source.headingRange, Data("### \(newEntry.title)".utf8))
            }
            if oldEntry.notes != newEntry.notes {
                patch(&patches, source.notesRange, Data(renderNotes(newEntry.notes).utf8))
            }

            let oldFields = Dictionary(uniqueKeysWithValues: oldEntry.fields.map { ($0.key, $0) })
            let newFields = Dictionary(uniqueKeysWithValues: newEntry.fields.map { ($0.key, $0) })
            for field in oldEntry.fields where newFields[field.key] == nil {
                guard let source = parsed.source.fields[FieldKey(id: id, key: field.key)] else { throw SecretCatalogValidationError.duplicateFieldKey }
                patch(&patches, source.blockRange, Data())
            }
            for field in newEntry.fields where oldFields[field.key] == nil {
                let at = fieldInsertOffset(field.key, id, newEntry.fields, parsed.source, source.closeStart)
                patch(&patches, at..<at, Data(renderField(field).joined(separator: "\n").utf8), order: newEntry.fields.firstIndex { $0.key == field.key } ?? 0)
            }
            for key in Set(oldFields.keys).intersection(newFields.keys) {
                guard let oldField = oldFields[key], let newField = newFields[key], let source = parsed.source.fields[FieldKey(id: id, key: key)] else { continue }
                if oldField.label != newField.label || oldField.type != newField.type || oldField.agentVisible != newField.agentVisible || oldField.searchable != newField.searchable {
                    patch(&patches, source.markerRange, Data(renderFieldMarker(newField).utf8))
                }
                if oldField.value != newField.value || oldField.secretRef != newField.secretRef || oldField.label != newField.label {
                    patch(&patches, source.bodyRange, Data((renderFieldBody(newField) + "\n").utf8))
                }
            }
        }

        let result = apply(data, patches)
        guard try parseV3(try utf8(result)).document == new else { throw SecretCatalogValidationError.referenceSetChanged }
        return result
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct Line {
        let text: String
        let start: Int
        let contentEnd: Int
        let end: Int
    }
    struct IndexSource { let markerRange: Range<Int>; let headingRange: Range<Int>; let blockRange: Range<Int>; let closeStart: Int }
    struct EntrySource { let markerRange: Range<Int>; let headingRange: Range<Int>; let notesRange: Range<Int>; let blockRange: Range<Int>; let closeStart: Int }
    struct FieldKey: Hashable { let id: String; let key: String }
    struct FieldSource { let markerRange: Range<Int>; let bodyRange: Range<Int>; let blockRange: Range<Int> }
    struct Source { var indexes: [String: IndexSource] = [:]; var entries: [String: EntrySource] = [:]; var fields: [FieldKey: FieldSource] = [:] }
    struct Parsed { let document: SecretCatalogDocument; let source: Source }
    struct Patch { let start: Int; let end: Int; let data: Data; let order: Int }
    struct IndexState {
        let id: String; let aliases: [String]; let tags: [String]; let markerRange: Range<Int>
        var title: String?; var headingRange: Range<Int>?; var entries: [SecretCatalogEntry] = []; var entryIDs = Set<String>()
    }
    struct EntryState {
        let id: String; let type: String; let aliases: [String]; let endpoints: [CatalogEndpoint]; let tags: [String]; let indexID: String; let markerRange: Range<Int>
        var title: String?; var headingRange: Range<Int>?; var bodyStart: Int?; var notesEnd: Int?; var fields: [SecretCatalogFieldValue] = []; var fieldKeys = Set<String>()
    }
    struct FieldState {
        let id: String; let key: String; let label: String; let type: SecretCatalogFieldType; let agentVisible: Bool; let searchable: Bool; let markerRange: Range<Int>; let lineEnd: Int
    }

    static func parseV3(_ text: String) throws -> Parsed {
        try validatePolicyBlock(text)
        let data = Data(text.utf8)
        let lines = splitLines(data)
        guard lines.first?.text == marker else { throw SecretCatalogValidationError.invalidMarker }
        var source = Source()
        var indexes: [SecretCatalogIndex] = []
        var allEntries: [SecretCatalogEntry] = []
        var index: IndexState?
        var entry: EntryState?
        var field: FieldState?
        var policy = false
        var root = false

        for line in lines.dropFirst() {
            let trimmed = line.text.trimmingCharacters(in: .whitespaces)
            if trimmed == SVLTAgentCatalogPolicy.documentPolicyBeginMarker {
                guard !policy, index == nil, entry == nil, field == nil else { throw SecretCatalogValidationError.invalidHeading }
                policy = true
                continue
            }
            if policy {
                if trimmed == "<!-- SVLT-POLICY-END -->" { policy = false }
                continue
            }
            if let current = field {
                if trimmed == "<!-- /SVLT-FIELD -->" {
                    let bodyRange = current.lineEnd..<line.start
                    let parsed = try parseField(body: sliceText(data, range: bodyRange), state: current)
                    guard var currentEntry = entry, currentEntry.fieldKeys.insert(current.key).inserted else { throw SecretCatalogValidationError.duplicateFieldKey }
                    currentEntry.fields.append(parsed)
                    entry = currentEntry
                    source.fields[FieldKey(id: current.id, key: current.key)] = FieldSource(markerRange: current.markerRange, bodyRange: bodyRange, blockRange: current.markerRange.lowerBound..<line.end)
                    field = nil
                } else if trimmed.contains("<!-- SVLT-") || trimmed.contains("<!-- /SVLT-") {
                    // Field bodies are data, not a second marker language.
                    // Reject an injected SVLT token before it can be retained
                    // as ordinary text by a non-secret field.
                    throw SecretCatalogValidationError.unmanagedContent
                }
                continue
            }

            // Every non-policy line outside a secret field is metadata or
            // Markdown, regardless of whether the parser later attaches it to
            // a managed block. Keep the invariant at this source boundary so
            // ignored/unmanaged lines cannot become a second secret-ref
            // storage channel.
            guard MarkdownReferenceScanner.references(in: line.text).isEmpty else {
                throw SecretCatalogValidationError.secretReferenceInMetadata
            }
            let isManagedMarker =
                trimmed == "<!-- /SVLT-INDEX -->" ||
                trimmed == "<!-- /SVLT-ENTRY -->" ||
                trimmed == "<!-- /SVLT-FIELD -->" ||
                (trimmed.hasPrefix("<!-- SVLT-INDEX ") && trimmed.hasSuffix(" -->")) ||
                (trimmed.hasPrefix("<!-- SVLT-ENTRY ") && trimmed.hasSuffix(" -->")) ||
                (trimmed.hasPrefix("<!-- SVLT-FIELD ") && trimmed.hasSuffix(" -->"))
            // Notes delimiters are managed only inside an active entry. The
            // same marker text at document level is not an unmanaged Markdown
            // escape hatch.
            let isEntryNotesMarker = entry != nil && (
                trimmed == "<!-- SVLT-NOTES-BEGIN -->" ||
                trimmed == "<!-- SVLT-NOTES-END -->"
            )
            if (trimmed.contains("<!-- SVLT-") || trimmed.contains("<!-- /SVLT-")),
               !isManagedMarker,
               !isEntryNotesMarker {
                throw SecretCatalogValidationError.unmanagedContent
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-FIELD ", line: line) {
                guard var currentEntry = entry, currentEntry.title != nil else { throw SecretCatalogValidationError.missingEntryBlock }
                if currentEntry.notesEnd == nil { currentEntry.notesEnd = line.start }
                entry = currentEntry
                let value = try fieldMarker(raw.json)
                field = FieldState(id: currentEntry.id, key: value.key, label: value.label, type: value.type, agentVisible: value.agentVisible, searchable: value.searchable, markerRange: raw.range, lineEnd: line.end)
                continue
            }
            if trimmed == "<!-- /SVLT-ENTRY -->" {
                guard let current = entry, let title = current.title, let heading = current.headingRange, var currentIndex = index else { throw SecretCatalogValidationError.missingEntryBlock }
                let noteRange = (current.bodyStart ?? line.start)..<(current.notesEnd ?? line.start)
                let value = SecretCatalogEntry(id: current.id, indexId: current.indexID, title: title, type: current.type, aliases: current.aliases, endpoints: current.endpoints, fields: current.fields, notes: parseNotes(sliceText(data, range: noteRange)), tags: current.tags)
                try value.validateStandalone()
                guard currentIndex.entryIDs.contains(value.id) else { throw SecretCatalogValidationError.duplicateEntryID }
                currentIndex.entries.append(value)
                index = currentIndex
                source.entries[value.id] = EntrySource(markerRange: current.markerRange, headingRange: heading, notesRange: noteRange, blockRange: current.markerRange.lowerBound..<line.end, closeStart: line.start)
                entry = nil
                continue
            }
            if trimmed == "<!-- /SVLT-INDEX -->" {
                guard entry == nil, let current = index, let title = current.title, let heading = current.headingRange else { throw SecretCatalogValidationError.missingIndexBlock }
                let value = SecretCatalogIndex(id: current.id, title: title, aliases: current.aliases, tags: current.tags)
                try value.validateStandalone()
                indexes.append(value)
                allEntries.append(contentsOf: current.entries)
                source.indexes[value.id] = IndexSource(markerRange: current.markerRange, headingRange: heading, blockRange: current.markerRange.lowerBound..<line.end, closeStart: line.start)
                index = nil
                continue
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-INDEX ", line: line) {
                guard index == nil, entry == nil else { throw SecretCatalogValidationError.invalidHeading }
                let value = try indexMarker(raw.json)
                index = IndexState(id: value.id, aliases: value.aliases, tags: value.tags, markerRange: raw.range)
                continue
            }
            if let raw = marker(trimmed, prefix: "<!-- SVLT-ENTRY ", line: line) {
                guard var currentIndex = index, entry == nil, currentIndex.title != nil else { throw SecretCatalogValidationError.missingIndexBlock }
                let value = try entryMarker(raw.json)
                guard currentIndex.entryIDs.insert(value.id).inserted else { throw SecretCatalogValidationError.duplicateEntryID }
                index = currentIndex
                entry = EntryState(id: value.id, type: value.type, aliases: value.aliases, endpoints: value.endpoints, tags: value.tags, indexID: currentIndex.id, markerRange: raw.range)
                continue
            }
            if let heading = heading(trimmed) {
                switch heading.level {
                case 1:
                    guard !root, index == nil, entry == nil, heading.title == rootTitle else { throw SecretCatalogValidationError.invalidHeading }
                    root = true
                case 2:
                    guard root else { throw SecretCatalogValidationError.invalidHeading }
                    guard var currentIndex = index, entry == nil else { continue }
                    // Once a group heading has been consumed, later ##
                    // headings are ordinary user Markdown inside that
                    // marker-bounded group and remain part of its source map.
                    guard currentIndex.title == nil else { continue }
                    currentIndex.title = heading.title
                    currentIndex.headingRange = line.start..<line.contentEnd
                    index = currentIndex
                case 3:
                    guard root else { throw SecretCatalogValidationError.invalidHeading }
                    guard var currentEntry = entry else { continue }
                    // A real entry heading is required immediately after its
                    // SVLT-ENTRY marker. After that point ### is user prose.
                    guard currentEntry.title == nil else { continue }
                    currentEntry.title = heading.title
                    currentEntry.headingRange = line.start..<line.contentEnd
                    currentEntry.bodyStart = line.end
                    entry = currentEntry
                default:
                    continue
                }
                continue
            }
            if entry == nil && index == nil && !root && !trimmed.isEmpty { throw SecretCatalogValidationError.invalidHeading }
        }
        guard root, !policy, field == nil, entry == nil, index == nil else { throw SecretCatalogValidationError.invalidHeading }
        let document = SecretCatalogDocument(indexes: indexes, entries: allEntries)
        try document.validate()
        return Parsed(document: document, source: source)
    }

    static func validatePolicyBlock(_ text: String) throws {
        let lines = normalizeNewlines(text).components(separatedBy: "\n")
        let beginLines = lines.enumerated().compactMap { offset, line in
            line.trimmingCharacters(in: .whitespaces) == SVLTAgentCatalogPolicy.documentPolicyBeginMarker
                ? offset
                : nil
        }
        let endLines = lines.enumerated().compactMap { offset, line in
            line.trimmingCharacters(in: .whitespaces) == SVLTAgentCatalogPolicy.documentPolicyEndMarker
                ? offset
                : nil
        }
        guard beginLines.count == 1, endLines.count == 1,
              let begin = beginLines.first, let end = endLines.first, begin < end
        else {
            throw SecretCatalogValidationError.invalidPolicyBlock
        }

        let block = lines[begin...end].joined(separator: "\n")
        guard block == SVLTAgentCatalogPolicy.documentPolicyBlock else {
            throw SecretCatalogValidationError.invalidPolicyBlock
        }
    }

    static func parseField(body: String, state: FieldState) throws -> SecretCatalogFieldValue {
        let normalized = normalizeNewlines(body).trimmingCharacters(in: CharacterSet.newlines)
        let parts = normalized.components(separatedBy: "\n")
        var label = state.label.isEmpty ? state.key : state.label
        var content = normalized
        if let first = parts.first, let separator = first.range(of: "：") ?? first.range(of: ":") {
            let prefix = first[..<separator.lowerBound]
            if prefix.hasPrefix("- ") {
                label = String(prefix.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                content = ([String(first[separator.upperBound...])] + parts.dropFirst()).joined(separator: "\n")
            }
        }
        content = content.trimmingCharacters(in: CharacterSet.newlines)
        let tick = String(UnicodeScalar(96)!)
        let valueText = content.hasPrefix(tick) && content.hasSuffix(tick) && content.count >= 2 ? String(content.dropFirst().dropLast()) : content
        let value: SecretCatalogValue?
        var secretRef: String?
        if state.type.isSecret {
            guard valueText.isEmpty || (try? SecretReference(valueText)) != nil else { throw SecretCatalogValidationError.secretFieldContainsValue }
            secretRef = valueText.isEmpty ? nil : valueText
            value = nil
        } else {
            secretRef = nil
            if valueText.isEmpty {
                value = nil
            } else {
                switch state.type {
                case .text, .multiline, .url, .host, .date: value = .string(valueText)
                case .number, .port:
                    guard let number = Double(valueText), number.isFinite else { throw SecretCatalogValidationError.invalidFieldValue }
                    value = .number(number)
                case .boolean:
                    guard let boolean = Bool(valueText) else { throw SecretCatalogValidationError.invalidFieldValue }
                    value = .boolean(boolean)
                case .list:
                    if let data = valueText.data(using: .utf8), let list = try? JSONDecoder().decode([String].self, from: data) { value = .list(list) }
                    else { value = .list(valueText.components(separatedBy: "\n")) }
                case .secret: value = nil
                }
            }
        }
        let field = SecretCatalogFieldValue(key: state.key, label: label, type: state.type, agentVisible: state.agentVisible, searchable: state.searchable, value: value, secretRef: secretRef)
        try CatalogValidationProxy.validate(field)
        return field
    }

    static func parseNotes(_ body: String) -> String? {
        let value = normalizeNewlines(body).trimmingCharacters(in: CharacterSet.newlines)
        guard !value.isEmpty else { return nil }
        let lines = value.components(separatedBy: "\n")
        if lines.first?.trimmingCharacters(in: .whitespaces) == "<!-- SVLT-NOTES-BEGIN -->", lines.last?.trimmingCharacters(in: .whitespaces) == "<!-- SVLT-NOTES-END -->" {
            let notes = Array(lines.dropFirst().dropLast()).joined(separator: "\n").trimmingCharacters(in: CharacterSet.newlines)
            return notes.isEmpty ? nil : notes
        }
        return value
    }

    static func marker(_ value: String, prefix: String, line: Line) -> (json: String, range: Range<Int>)? {
        guard value.hasPrefix(prefix), value.hasSuffix(" -->") else { return nil }
        let start = value.index(value.startIndex, offsetBy: prefix.count)
        let end = value.index(value.endIndex, offsetBy: -4)
        return (String(value[start..<end]), line.start..<line.contentEnd)
    }

    static func indexMarker(_ json: String) throws -> (id: String, aliases: [String], tags: [String]) {
        let object = try object(json, allowed: ["id", "aliases", "tags"], required: ["id"])
        guard let id = object["id"] as? String else { throw SecretCatalogValidationError.malformedJSON }
        return (id, (object["aliases"] as? [Any])?.compactMap { $0 as? String } ?? [], (object["tags"] as? [Any])?.compactMap { $0 as? String } ?? [])
    }

    static func entryMarker(_ json: String) throws -> (id: String, type: String, aliases: [String], endpoints: [CatalogEndpoint], tags: [String]) {
        let object = try object(json, allowed: ["id", "type", "aliases", "endpoints", "tags"], required: ["id", "type"])
        guard let id = object["id"] as? String, let type = object["type"] as? String else { throw SecretCatalogValidationError.malformedJSON }
        let endpoints: [CatalogEndpoint]
        if let raw = object["endpoints"] {
            endpoints = try JSONDecoder().decode([CatalogEndpoint].self, from: JSONSerialization.data(withJSONObject: raw))
        } else { endpoints = [] }
        return (id, type, (object["aliases"] as? [Any])?.compactMap { $0 as? String } ?? [], endpoints, (object["tags"] as? [Any])?.compactMap { $0 as? String } ?? [])
    }

    static func fieldMarker(_ json: String) throws -> (key: String, label: String, type: SecretCatalogFieldType, agentVisible: Bool, searchable: Bool) {
        let object = try object(json, allowed: ["key", "label", "type", "agentVisible", "searchable"], required: ["key", "type"])
        guard let key = object["key"] as? String, let rawType = object["type"] as? String, let type = SecretCatalogFieldType(rawValue: rawType) else { throw SecretCatalogValidationError.malformedJSON }
        return (key, object["label"] as? String ?? key, type, object["agentVisible"] as? Bool ?? true, object["searchable"] as? Bool ?? true)
    }

    static func object(_ json: String, allowed: Set<String>, required: Set<String>) throws -> [String: Any] {
        guard let data = json.data(using: .utf8), let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys).isSubset(of: allowed), required.isSubset(of: Set(value.keys)) else { throw SecretCatalogValidationError.malformedJSON }
        return value
    }

    static func splitLines(_ data: Data) -> [Line] {
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { return [] }
        var result: [Line] = []
        var start = 0
        for index in 0...bytes.count where index == bytes.count || bytes[index] == 0x0A {
            let end = index > start && bytes[index - 1] == 0x0D ? index - 1 : index
            result.append(Line(text: String(decoding: bytes[start..<end], as: UTF8.self), start: start, contentEnd: end, end: min(index + 1, bytes.count)))
            start = index + 1
        }
        return result
    }

    static func sliceText(_ data: Data, range: Range<Int>) -> String {
        guard !range.isEmpty else { return "" }
        return String(decoding: [UInt8](data)[range], as: UTF8.self)
    }

    static func heading(_ line: String) -> (level: Int, title: String)? {
        let level = line.prefix(while: { $0 == "#" }).count
        guard (1...3).contains(level) else { return nil }
        let remainder = line.dropFirst(level)
        guard remainder.first == " " || remainder.first == "\t" else { return nil }
        let title = String(remainder).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty, !title.contains("\0") else { return nil }
        return (level, title)
    }

    static func normalizeNewlines(_ value: String) -> String {
        value.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
    }

    static func utf8(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else { throw SecretCatalogValidationError.unmanagedContent }
        return value
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct IndexMarkerValue: Codable { let id: String; let aliases: [String]; let tags: [String] }
    struct EntryMarkerValue: Codable { let id: String; let type: String; let aliases: [String]; let endpoints: [CatalogEndpoint]; let tags: [String] }
    struct FieldMarkerValue: Codable { let key: String; let label: String; let type: String; let agentVisible: Bool; let searchable: Bool }

    static func compact<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? String(data: encoder.encode(value), encoding: .utf8)) ?? "{}"
    }

    static func canonicalJSON<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let text = String(data: try encoder.encode(value), encoding: .utf8), !text.contains("\r") else {
            throw SecretCatalogValidationError.malformedJSON
        }
        return text
    }

    static func renderIndexMarker(_ index: SecretCatalogIndex) -> String {
        "<!-- SVLT-INDEX \(compact(IndexMarkerValue(id: index.id, aliases: index.aliases, tags: index.tags))) -->"
    }
    static func renderEntryMarker(_ entry: SecretCatalogEntry) -> String {
        "<!-- SVLT-ENTRY \(compact(EntryMarkerValue(id: entry.id, type: entry.type, aliases: entry.aliases, endpoints: entry.endpoints, tags: entry.tags))) -->"
    }
    static func renderFieldMarker(_ field: SecretCatalogFieldValue) -> String {
        "<!-- SVLT-FIELD \(compact(FieldMarkerValue(key: field.key, label: field.label, type: field.type.rawValue, agentVisible: field.agentVisible, searchable: field.searchable))) -->"
    }
    static func renderIndex(_ index: SecretCatalogIndex, entries: [SecretCatalogEntry]) -> [String] {
        var result = [renderIndexMarker(index), "## \(index.title)", ""]
        for entry in entries { result.append(contentsOf: renderEntry(entry)) }
        result.append("<!-- /SVLT-INDEX -->")
        return result
    }
    static func renderEntry(_ entry: SecretCatalogEntry) -> [String] {
        var result = [renderEntryMarker(entry), "### \(entry.title)", ""]
        if let notes = entry.notes {
            result += ["<!-- SVLT-NOTES-BEGIN -->"] + notes.components(separatedBy: "\n") + ["<!-- SVLT-NOTES-END -->", ""]
        }
        for field in entry.fields { result.append(contentsOf: renderField(field)) }
        result.append("<!-- /SVLT-ENTRY -->")
        return result
    }
    static func renderField(_ field: SecretCatalogFieldValue) -> [String] {
        [renderFieldMarker(field)] + renderFieldBody(field).components(separatedBy: "\n") + ["<!-- /SVLT-FIELD -->", ""]
    }
    static func renderFieldBody(_ field: SecretCatalogFieldValue) -> String {
        let prefix = "- \(field.label)："
        if let secretRef = field.secretRef {
            let tick = String(UnicodeScalar(96)!)
            return prefix + tick + secretRef + tick
        }
        guard let value = field.value else { return prefix }
        switch value {
        case .string(let value): return prefix + value
        case .number(let value): return prefix + String(value)
        case .boolean(let value): return prefix + String(value)
        case .list(let value):
            let data = try? JSONEncoder().encode(value)
            return prefix + (data.flatMap { String(data: $0, encoding: .utf8) } ?? "[]")
        }
    }
    static func renderNotes(_ notes: String?) -> String {
        guard let notes else { return "" }
        return "\n<!-- SVLT-NOTES-BEGIN -->\n\(notes)\n<!-- SVLT-NOTES-END -->\n"
    }
    static func patch(_ patches: inout [Patch], _ range: Range<Int>, _ data: Data, order: Int = 0) {
        if range.isEmpty, let i = patches.firstIndex(where: { $0.start == range.lowerBound && $0.end == range.upperBound }) {
            let old = patches[i]
            patches[i] = order < old.order
                ? Patch(start: old.start, end: old.end, data: data + old.data, order: order)
                : Patch(start: old.start, end: old.end, data: old.data + data, order: old.order)
        } else {
            patches.append(Patch(start: range.lowerBound, end: range.upperBound, data: data, order: order))
        }
    }
    static func apply(_ source: Data, _ patches: [Patch]) -> Data {
        var bytes = [UInt8](source)
        for item in patches.sorted(by: { $0.start == $1.start ? $0.end > $1.end : $0.start > $1.start }) {
            bytes.replaceSubrange(item.start..<item.end, with: item.data)
        }
        return Data(bytes)
    }
    static func indexInsertOffset(_ id: String, _ indexes: [SecretCatalogIndex], _ source: Source, _ end: Int) -> Int {
        guard let position = indexes.firstIndex(where: { $0.id == id }) else { return end }
        for next in indexes.dropFirst(position + 1) { if let source = source.indexes[next.id] { return source.blockRange.lowerBound } }
        return end
    }
    static func entryInsertOffset(_ id: String, _ indexID: String, _ entries: [SecretCatalogEntry], _ source: Source, _ fallback: Int) -> Int {
        guard let position = entries.firstIndex(where: { $0.id == id }) else { return fallback }
        for next in entries.dropFirst(position + 1) where next.indexId == indexID { if let source = source.entries[next.id] { return source.blockRange.lowerBound } }
        return fallback
    }
    static func fieldInsertOffset(_ key: String, _ entryID: String, _ fields: [SecretCatalogFieldValue], _ source: Source, _ fallback: Int) -> Int {
        guard let position = fields.firstIndex(where: { $0.key == key }) else { return fallback }
        for next in fields.dropFirst(position + 1) { if let source = source.fields[FieldKey(id: entryID, key: next.key)] { return source.blockRange.lowerBound } }
        return fallback
    }
}

private extension SensitiveCatalogDocumentCodec {
    struct Envelope: Decodable { let schema: String }
    static func decodeV2(_ text: String) throws -> SecretCatalogDocument {
        let lines = normalizeNewlines(text).components(separatedBy: "\n")
        guard lines.first == v2Marker else { throw SecretCatalogValidationError.invalidMarker }
        let fence = String(repeating: String(UnicodeScalar(96)!), count: 3)
        var root = false; var indexTitle: String?; var entryTitle: String?; var active: SecretCatalogIndex?
        var indexes: [SecretCatalogIndex] = []; var entries: [SecretCatalogEntry] = []
        var indexCount = 0; var entryCount = 0; var inFence = false; var json: [String] = []; var level = 0
        for line in lines.dropFirst() {
            if inFence {
                if line == fence {
                    inFence = false
                    try decodeV2Block(json.joined(separator: "\n"), level: level, indexTitle: indexTitle, entryTitle: entryTitle, active: active, indexes: &indexes, entries: &entries, indexCount: &indexCount, entryCount: &entryCount, current: &active)
                    json.removeAll(keepingCapacity: true)
                } else { json.append(line) }
                continue
            }
            if let value = heading(line) {
                switch value.level {
                case 1: guard !root, value.title == rootTitle else { throw SecretCatalogValidationError.invalidHeading }; root = true
                case 2: guard root else { throw SecretCatalogValidationError.invalidHeading }; try finish(entryTitle, entryCount); try finish(indexTitle, indexCount); indexTitle = value.title; entryTitle = nil; active = nil; indexCount = 0; entryCount = 0
                case 3: guard root, indexTitle != nil, active != nil else { throw SecretCatalogValidationError.invalidHeading }; try finish(entryTitle, entryCount); entryTitle = value.title; entryCount = 0
                default: throw SecretCatalogValidationError.invalidHeading
                }
                continue
            }
            if line == fence + "json" {
                guard root, indexTitle != nil else { throw SecretCatalogValidationError.invalidHeading }
                inFence = true; level = entryTitle == nil ? 2 : 3; json.removeAll(keepingCapacity: true); continue
            }
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty || trimmed == "> 本文件由 SVLT 管理。请勿直接修改结构化数据。" || trimmed == "> Agent 必须使用 SVLT MCP Catalog 工具修改。" else {
                throw SecretCatalogValidationError.unmanagedContent
            }
        }
        guard root, !inFence else { throw SecretCatalogValidationError.malformedJSON }
        try finish(entryTitle, entryCount); try finish(indexTitle, indexCount)
        let document = SecretCatalogDocument(indexes: indexes, entries: entries); try document.validate(); return document
    }

    static func visibleStrings(_ value: SecretCatalogValue?) -> [String] {
        guard let value else { return [] }
        switch value {
        case .string(let value): return [value]
        case .list(let values): return values
        case .number, .boolean: return []
        }
    }

    static func renderLegacyDirectoryDescription(_ entry: SecretCatalogEntry) -> String? {
        var content: [String] = []
        if let notes = entry.notes, !notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            content.append(notes.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        for field in entry.fields {
            let value = visibleStrings(field.value).joined(separator: ", ")
            content.append("\(field.label)：\(value)")
        }
        if !entry.aliases.isEmpty {
            content.append("别名：\(entry.aliases.joined(separator: "、"))")
        }
        if !entry.tags.isEmpty {
            content.append("标签：\(entry.tags.joined(separator: "、"))")
        }
        guard !content.isEmpty else { return nil }
        let body = content.joined(separator: "\n")
        let lines = body.components(separatedBy: "\n").map { line in
            line.isEmpty ? ">" : "> \(line)"
        }
        return (["> [!note]- 目录说明"] + lines).joined(separator: "\n")
    }

    static func validatedUnmanagedMarkdown(_ value: String) throws -> String {
        let normalized = normalizeNewlines(value).trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count <= 20_000,
              !normalized.contains("\0"),
              !normalized.contains("\r"),
              MarkdownReferenceScanner.referenceIDs(in: normalized).isEmpty
        else {
            throw SecretCatalogValidationError.secretReferenceInMetadata
        }
        return normalized
    }
    static func decodeV2Block(_ json: String, level: Int, indexTitle: String?, entryTitle: String?, active: SecretCatalogIndex?, indexes: inout [SecretCatalogIndex], entries: inout [SecretCatalogEntry], indexCount: inout Int, entryCount: inout Int, current: inout SecretCatalogIndex?) throws {
        guard let data = json.data(using: .utf8), let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else { throw SecretCatalogValidationError.malformedJSON }
        switch (level, envelope.schema) {
        case (2, SecretCatalogIndex.legacySchemaName):
            guard indexCount == 0, let title = indexTitle else { throw SecretCatalogValidationError.missingIndexBlock }
            let old = try JSONDecoder().decode(SecretCatalogIndex.self, from: data); guard old.title == title else { throw SecretCatalogValidationError.headingDoesNotMatchBlock }
            let value = SecretCatalogIndex(id: old.id, title: old.title, aliases: old.aliases, tags: old.tags); try value.validateStandalone(); indexes.append(value); current = value; indexCount += 1
        case (3, SecretCatalogEntry.legacySchemaName):
            guard entryCount == 0, let title = entryTitle, let active else { throw SecretCatalogValidationError.missingEntryBlock }
            let old = try JSONDecoder().decode(SecretCatalogEntry.self, from: data); guard old.title == title, old.indexId == active.id else { throw SecretCatalogValidationError.headingDoesNotMatchBlock }
            entries.append(SecretCatalogEntry(id: old.id, indexId: old.indexId, title: old.title, type: old.type, aliases: old.aliases, endpoints: old.endpoints, fields: old.fields, notes: old.notes, tags: old.tags)); entryCount += 1
        default: throw SecretCatalogValidationError.unknownSchema
        }
    }
    static func finish(_ title: String?, _ count: Int) throws { guard title == nil || count == 1 else { throw SecretCatalogValidationError.missingEntryBlock } }
}

private extension SecretCatalogIndex {
    func validateStandalone() throws { try SecretCatalogOpaqueID.validate(id); guard !title.isEmpty, !title.contains("\n"), !title.contains("\r") else { throw SecretCatalogValidationError.invalidVisibleText } }
}

private extension SecretCatalogEntry {
    func validateStandalone() throws { try SecretCatalogOpaqueID.validate(id); guard !title.isEmpty, !title.contains("\n"), !title.contains("\r") else { throw SecretCatalogValidationError.invalidVisibleText } }
}

private enum CatalogValidationProxy {
    static func validate(_ field: SecretCatalogFieldValue) throws {
        let indexID = "0123456789ABCDEFGHJKMNPQRS"; let entryID = "0123456789ABCDEFGHJKMNPQRT"
        try SecretCatalogDocument(indexes: [SecretCatalogIndex(id: indexID, title: "校验")], entries: [SecretCatalogEntry(id: entryID, indexId: indexID, title: "校验", fields: [field])]).validate()
    }
}
