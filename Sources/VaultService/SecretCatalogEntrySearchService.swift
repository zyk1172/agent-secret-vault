import Foundation
import VaultCore

/// Searches a validated v3 document and projects complete Entries without
/// exposing hidden metadata or secret plaintext.
public struct SecretCatalogEntrySearchService: Sendable {
    public static let maximumLimit = 20

    public init() {}

    public func search(
        query: String,
        field: SecretCatalogField? = nil,
        limit: Int = 10,
        document: SecretCatalogDocument
    ) -> SecretCatalogSearchResult {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return SecretCatalogSearchResult(status: .invalidQuery)
        }

        let boundedLimit = min(max(limit, 1), Self.maximumLimit)
        let normalizedQuery = normalize(trimmed)
        let indexes = Dictionary(uniqueKeysWithValues: document.indexes.map { ($0.id, $0) })
        let ranked = document.entries.compactMap { entry -> RankedMatch? in
            guard let index = indexes[entry.indexId] else { return nil }
            if let field,
               !entry.fields.contains(where: { matches($0, legacyField: field) }) {
                return nil
            }
            guard let score = score(entry: entry, index: index, query: normalizedQuery) else {
                return nil
            }
            return RankedMatch(score: score, match: project(index: index, entry: entry))
        }
        .sorted(by: isEarlier)
        .prefix(boundedLimit)
        .map(\.match)

        guard !ranked.isEmpty else {
            return SecretCatalogSearchResult(status: .notFound)
        }
        return SecretCatalogSearchResult(status: .found, matches: Array(ranked))
    }

    public func get(
        entryID: String,
        document: SecretCatalogDocument
    ) -> SecretCatalogSearchResult {
        guard let entry = document.entries.first(where: { $0.id == entryID }),
              let index = document.indexes.first(where: { $0.id == entry.indexId })
        else {
            return SecretCatalogSearchResult(status: .notFound)
        }
        return SecretCatalogSearchResult(status: .found, matches: [project(index: index, entry: entry)])
    }

    /// Lists every Index, including Indexes with no Entries.  This is a
    /// separate projection from search because an Entry-centric match cannot
    /// represent an empty Index.
    public func listIndexes(document: SecretCatalogDocument) -> [SecretCatalogIndexSummary] {
        document.indexes.map { index in
            SecretCatalogIndexSummary(
                id: index.id,
                title: index.title,
                aliases: index.aliases,
                tags: index.tags,
                entryCount: document.entries.count(where: { $0.indexId == index.id })
            )
        }
    }

    /// Lists the projected Entries belonging to one Index.  A valid empty
    /// Index returns FOUND with an empty array; an unknown opaque ID returns
    /// NOT_FOUND without exposing document details.
    public func listEntries(
        indexID: String,
        document: SecretCatalogDocument,
        revision: UInt64
    ) -> SecretCatalogEntryListResult {
        guard document.indexes.contains(where: { $0.id == indexID }) else {
            return SecretCatalogEntryListResult(
                status: .notFound,
                revision: revision,
                indexID: indexID
            )
        }

        let index = document.indexes.first { $0.id == indexID }!
        let entries = document.entries
            .filter { $0.indexId == indexID }
            .map { project(index: index, entry: $0).entry }
        return SecretCatalogEntryListResult(
            status: .found,
            revision: revision,
            indexID: indexID,
            entries: entries
        )
    }

    private func project(
        index: SecretCatalogIndex,
        entry: SecretCatalogEntry
    ) -> SecretCatalogMatch {
        let fields = entry.fields.compactMap { field -> SecretCatalogFieldMatch? in
            if field.type.isSecret {
                return SecretCatalogFieldMatch(
                    key: field.key,
                    label: field.label,
                    type: field.type,
                    secretRef: field.secretRef
                )
            }
            guard field.agentVisible else { return nil }
            return SecretCatalogFieldMatch(
                key: field.key,
                label: field.label,
                type: field.type,
                value: field.value
            )
        }
        return SecretCatalogMatch(
            index: SecretCatalogIndexMatch(
                id: index.id,
                title: index.title,
                aliases: index.aliases,
                tags: index.tags
            ),
            entry: SecretCatalogEntryMatch(
                id: entry.id,
                indexId: entry.indexId,
                title: entry.title,
                type: entry.type,
                aliases: entry.aliases,
                endpoints: entry.endpoints,
                fields: fields,
                notes: entry.notes,
                tags: entry.tags
            )
        )
    }

    private func score(
        entry: SecretCatalogEntry,
        index: SecretCatalogIndex,
        query: String
    ) -> Int? {
        let indexTitle = normalize(index.title)
        let entryTitle = normalize(entry.title)
        let aliases = (index.aliases + entry.aliases).map(normalize)
        if indexTitle == query || entryTitle == query { return 0 }
        if aliases.contains(query) { return 1 }
        if indexTitle.hasPrefix(query) || entryTitle.hasPrefix(query) { return 2 }
        if aliases.contains(where: { $0.hasPrefix(query) }) { return 3 }

        let structuralTerms = [indexTitle, entryTitle]
            + aliases
            + index.tags.map(normalize)
            + entry.tags.map(normalize)
            + entry.endpoints.flatMap { endpoint in
                [normalize(endpoint.type), normalize(endpoint.host), endpoint.port.map(String.init) ?? ""]
            }
            + [normalize(entry.notes)]
        if structuralTerms.contains(where: { !$0.isEmpty && $0.contains(query) }) { return 4 }

        let metadataTerms = entry.fields.flatMap { field -> [String] in
            guard field.searchable else { return [] }
            // `label` is the user-facing searchable name. Keep the stable
            // machine key as a compatibility term for existing Agent/MCP
            // queries without making it a second user-editable name.
            var terms = [normalize(field.key), normalize(field.label)]
            if let value = field.value {
                terms.append(contentsOf: valueTerms(value))
            }
            return terms
        }
        guard metadataTerms.contains(where: { !$0.isEmpty && $0.contains(query) }) else {
            return nil
        }
        return 5
    }

    private func matches(_ field: SecretCatalogFieldValue, legacyField: SecretCatalogField) -> Bool {
        let key = normalize(field.key)
        switch legacyField {
        case .username: return ["username", "user", "account", "账号", "用户名"].contains(key)
        case .password: return ["password", "pass", "pwd", "密码"].contains(key)
        case .token: return key.contains("token") || key.contains("令牌")
        case .apiKey: return key.contains("apikey") || key.contains("api密钥")
        case .cookie: return key.contains("cookie")
        case .privateKey: return key.contains("privatekey") || key.contains("私钥")
        case .other: return true
        }
    }

    private func valueTerms(_ value: SecretCatalogValue) -> [String] {
        switch value {
        case .string(let string): return [normalize(string)]
        case .number(let number): return [String(number), String(Int(number))]
        case .boolean(let boolean): return [boolean ? "true" : "false"]
        case .list(let list): return list.map(normalize)
        }
    }

    private func normalize(_ value: String?) -> String {
        guard let value else { return "" }
        return value
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: Locale(identifier: "en_US_POSIX"))
            .lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private struct RankedMatch {
        let score: Int
        let match: SecretCatalogMatch
    }

    private func isEarlier(_ lhs: RankedMatch, _ rhs: RankedMatch) -> Bool {
        if lhs.score != rhs.score { return lhs.score < rhs.score }
        let lhsTitle = normalize(lhs.match.entry.title)
        let rhsTitle = normalize(rhs.match.entry.title)
        if lhsTitle != rhsTitle { return lhsTitle < rhsTitle }
        return lhs.match.entry.id < rhs.match.entry.id
    }
}
