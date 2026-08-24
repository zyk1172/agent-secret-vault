import Foundation
import VaultCore

public enum SecretCatalogServiceError: Error, Equatable, Sendable {
    case malformedDocument
    case symlinkRejected
    case invalidEncoding
}

/// Performs local, deterministic discovery over the selected Markdown catalog
/// and encrypted-record metadata.  It never asks for or loads a master key.
public struct SecretCatalogService: Sendable {
    public static let defaultLimit = 10
    public static let maximumLimit = 20

    private let selectionStore: SecretCatalogSelectionStore

    public init(selectionManifestURL: URL) {
        self.selectionStore = SecretCatalogSelectionStore(manifestURL: selectionManifestURL)
    }

    public func selectedEntries() throws -> [LegacySecretCatalogEntry] {
        guard let documentURL = try selectionStore.selectedDocumentURL() else {
            return []
        }
        guard FileManager.default.fileExists(atPath: documentURL.path) else {
            return []
        }

        let values = try documentURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isSymbolicLink != true else {
            throw SecretCatalogServiceError.symlinkRejected
        }
        guard values.isRegularFile == true else {
            throw SecretCatalogServiceError.malformedDocument
        }

        guard let text = try? String(contentsOf: documentURL, encoding: .utf8) else {
            throw SecretCatalogServiceError.invalidEncoding
        }
        return SecretCatalogMarkdownParser.parse(text)
    }

    public func search(
        query: String,
        field: SecretCatalogField?,
        limit: Int,
        entries: [LegacySecretCatalogEntry],
        metadata: [SecretCatalogRecordMetadata]
    ) -> SecretCatalogSearchResult {
        let trimmedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedQuery.isEmpty else {
            return SecretCatalogSearchResult(status: .invalidQuery)
        }

        let boundedLimit = min(max(limit, 1), Self.maximumLimit)
        let candidates = mergedCandidates(entries: entries, metadata: metadata)
        let normalizedQuery = LegacySecretCatalogEntry.normalizeForSearch(trimmedQuery)
        let ranked = candidates.compactMap { candidate -> RankedCandidate? in
            guard field == nil || candidate.field == field else {
                return nil
            }
            guard let score = score(candidate, query: normalizedQuery) else {
                return nil
            }
            return RankedCandidate(candidate: candidate, score: score)
        }
        .sorted(by: Self.isEarlier)
        .prefix(boundedLimit)
        .map { $0.candidate.match }

        guard !ranked.isEmpty else {
            return SecretCatalogSearchResult(status: .notFound)
        }
        return SecretCatalogSearchResult(status: .found, matches: Array(ranked))
    }

    private func mergedCandidates(
        entries: [LegacySecretCatalogEntry],
        metadata: [SecretCatalogRecordMetadata]
    ) -> [Candidate] {
        var metadataByReference: [String: SecretCatalogRecordMetadata] = [:]
        for record in metadata {
            guard let reference = canonicalReference(record.reference) else {
                continue
            }
            metadataByReference[reference] = SecretCatalogRecordMetadata(
                reference: reference,
                policy: record.policy,
                label: safeMetadata(record.label),
                allowedDestinations: record.allowedDestinations.map(Self.safeDestination)
            )
        }

        var entriesByReference: [String: LegacySecretCatalogEntry] = [:]
        for entry in entries {
            guard let reference = canonicalReference(entry.reference) else {
                continue
            }
            entriesByReference[reference] = mergeEntries(
                entriesByReference[reference],
                with: LegacySecretCatalogEntry(
                    reference: reference,
                    service: safeMetadata(entry.service),
                    field: entry.field,
                    label: safeMetadata(entry.label),
                    destinations: entry.destinations.map(Self.safeDestination),
                    purpose: safeMetadata(entry.purpose),
                    groupID: entry.groupID,
                    contextTerms: entry.contextTerms.map { self.safeMetadata($0) }.compactMap { $0 }
                )
            )
        }

        let references = Set(metadataByReference.keys).union(entriesByReference.keys).sorted()
        return references.compactMap { reference in
            let entry = entriesByReference[reference]
            let record = metadataByReference[reference]
            guard entry != nil || record != nil else {
                return nil
            }

            let service = entry?.service
            let field = entry?.field == .other
                ? (inferField(from: entry?.label ?? record?.label) ?? .other)
                : (entry?.field ?? inferField(from: record?.label) ?? .other)
            let destinations = Array(Set((entry?.destinations ?? []) + (record?.allowedDestinations ?? [])))
                .filter { !$0.isEmpty }
                .sorted()
            let label = entry?.label
                ?? record?.label
                ?? synthesizedLabel(service: service, field: field)
            let purpose = entry?.purpose
            let contextTerms = Array(Set(
                (entry?.contextTerms ?? [])
                    + [service, label, purpose].compactMap { $0 }
                    + destinations
                    + [field.rawValue, field.displayName]
            ))
            .filter { !$0.isEmpty }
            .sorted()
            let groupID = entry?.groupID
                ?? LegacySecretCatalogEntry.stableGroupID(service: service, destinations: destinations, headingPath: [])

            return Candidate(
                reference: reference,
                service: service,
                field: field,
                label: label,
                policy: record?.policy ?? .read,
                destinations: destinations,
                purpose: purpose,
                groupID: groupID,
                contextTerms: contextTerms
            )
        }
    }

    private func mergeEntries(
        _ existing: LegacySecretCatalogEntry?,
        with incoming: LegacySecretCatalogEntry
    ) -> LegacySecretCatalogEntry {
        guard let existing else {
            return incoming
        }
        let field = existing.field == .other ? incoming.field : existing.field
        return LegacySecretCatalogEntry(
            reference: existing.reference,
            service: existing.service ?? incoming.service,
            field: field,
            label: existing.label ?? incoming.label,
            destinations: Array(Set(existing.destinations + incoming.destinations)).sorted(),
            purpose: existing.purpose ?? incoming.purpose,
            groupID: existing.groupID ?? incoming.groupID,
            contextTerms: Array(Set(existing.contextTerms + incoming.contextTerms)).sorted()
        )
    }

    private func score(_ candidate: Candidate, query: String) -> Int? {
        let service = normalized(candidate.service)
        let label = normalized(candidate.label)
        let destinations = candidate.destinations.map(normalized)

        if !service.isEmpty, service == query {
            return 0
        }
        if destinations.contains(query) {
            return 1
        }
        if !label.isEmpty, label == query {
            return 2
        }
        if !service.isEmpty, service.hasPrefix(query) {
            return 3
        }
        if !label.isEmpty, label.hasPrefix(query) {
            return 4
        }

        let tokenFields = [service, label] + destinations + [normalized(candidate.field.rawValue), normalized(candidate.field.displayName)]
        if tokenFields.contains(where: { !$0.isEmpty && $0.contains(query) }) {
            return 5
        }

        let contextFields = candidate.contextTerms.map(normalized) + [normalized(candidate.purpose)]
        if contextFields.contains(where: { !$0.isEmpty && $0.contains(query) }) {
            return 6
        }
        return nil
    }

    private func inferField(from label: String?) -> SecretCatalogField? {
        guard let label else {
            return nil
        }
        let normalized = LegacySecretCatalogEntry.normalizeForSearch(label)
        if normalized.contains("password") || normalized.contains("密码") {
            return .password
        }
        if normalized.contains("username") || normalized.contains("user") || normalized.contains("用户名") || normalized.contains("账号") {
            return .username
        }
        if normalized.contains("apikey") || normalized.contains("api key") || normalized.contains("api密钥") {
            return .apiKey
        }
        if normalized.contains("token") || normalized.contains("令牌") {
            return .token
        }
        if normalized.contains("cookie") {
            return .cookie
        }
        if normalized.contains("privatekey") || normalized.contains("私钥") {
            return .privateKey
        }
        return nil
    }

    private func synthesizedLabel(service: String?, field: SecretCatalogField) -> String? {
        if let service, field != .other {
            return "\(service) \(field.displayName)"
        }
        return service ?? (field == .other ? nil : field.displayName)
    }

    private func canonicalReference(_ value: String) -> String? {
        try? SecretReference(value).description
    }

    private func normalized(_ value: String?) -> String {
        guard let value else {
            return ""
        }
        return LegacySecretCatalogEntry.normalizeForSearch(value)
    }

    private func safeMetadata(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let sanitized = value
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sanitized.isEmpty else {
            return nil
        }
        return String(sanitized.prefix(160))
    }

    private static func safeDestination(_ value: String) -> String {
        String(value
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .prefix(160))
    }

    private struct Candidate {
        let reference: String
        let service: String?
        let field: SecretCatalogField
        let label: String?
        let policy: SecretPolicy
        let destinations: [String]
        let purpose: String?
        let groupID: String?
        let contextTerms: [String]

        var match: SecretCatalogMatch {
            SecretCatalogMatch(
                reference: reference,
                service: service,
                field: field,
                label: label,
                policy: policy,
                destinations: destinations,
                purpose: purpose,
                groupID: groupID
            )
        }
    }

    private struct RankedCandidate {
        let candidate: Candidate
        let score: Int
    }

    private static func isEarlier(_ lhs: RankedCandidate, _ rhs: RankedCandidate) -> Bool {
        if lhs.score != rhs.score {
            return lhs.score < rhs.score
        }
        let lhsService = LegacySecretCatalogEntry.normalizeForSearch(lhs.candidate.service ?? "")
        let rhsService = LegacySecretCatalogEntry.normalizeForSearch(rhs.candidate.service ?? "")
        if lhsService != rhsService {
            return lhsService < rhsService
        }
        let lhsLabel = LegacySecretCatalogEntry.normalizeForSearch(lhs.candidate.label ?? "")
        let rhsLabel = LegacySecretCatalogEntry.normalizeForSearch(rhs.candidate.label ?? "")
        if lhsLabel != rhsLabel {
            return lhsLabel < rhsLabel
        }
        if lhs.candidate.field.rawValue != rhs.candidate.field.rawValue {
            return lhs.candidate.field.rawValue < rhs.candidate.field.rawValue
        }
        return lhs.candidate.reference < rhs.candidate.reference
    }
}
