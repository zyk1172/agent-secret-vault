import CryptoKit
import Foundation
import VaultCore
import VaultIPC

public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}

public actor VaultAppServices: WorkbenchServicing {
    private let textEncryptor: any TextEncrypting
    private let activeRoot: URL?
    private let recordResolver: VaultRecordResolver?
    private let masterKey: SymmetricKey?
    private let revealSessionStore: RevealSessionStore

    public init(
        textEncryptor: any TextEncrypting,
        activeRoot: URL?,
        recordResolver: VaultRecordResolver? = nil,
        masterKey: SymmetricKey? = nil,
        revealSessionStore: RevealSessionStore = RevealSessionStore()
    ) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
        self.recordResolver = recordResolver
        self.masterKey = masterKey
        self.revealSessionStore = revealSessionStore
    }

    public init(
        encryptSelection: any EncryptSelectionCoordinating & TextEncrypting,
        activeRoot: URL?,
        recordResolver: VaultRecordResolver? = nil,
        masterKey: SymmetricKey? = nil,
        revealSessionStore: RevealSessionStore = RevealSessionStore()
    ) {
        self.init(
            textEncryptor: encryptSelection,
            activeRoot: activeRoot,
            recordResolver: recordResolver,
            masterKey: masterKey,
            revealSessionStore: revealSessionStore
        )
    }

    public func status() async -> WorkbenchStatus {
        WorkbenchStatus(
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: activeRoot?.path,
            pluginConnected: false
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

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }
        guard let recordResolver, let masterKey else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        let validatedReferences: [String]
        do {
            validatedReferences = try references.map { try SecretReference($0).description }
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }

        guard context.ranges.count == validatedReferences.count else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let plaintexts = try await validatedReferences.asyncMap { reference in
            let data = try await recordResolver.resolve(reference: reference, masterKey: masterKey)
            guard let plaintext = String(data: data, encoding: .utf8) else {
                throw VaultAppServicesRevealError.invalidResolvedPlaintext
            }
            return plaintext
        }

        let resolvedParagraph = try resolveTemplate(context.template, ranges: context.ranges, plaintexts: plaintexts)
        return await revealSessionStore.create(resolvedParagraph: resolvedParagraph)
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
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
