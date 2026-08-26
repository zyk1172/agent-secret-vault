import CryptoKit
import Foundation

/// Stable digest for binding an authorization ticket to a normalized Catalog
/// candidate. Secret fields contribute only opaque secret references.
public enum CatalogSemanticDigest {
    public static func rawSHA256(_ data: Data) -> String {
        SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    public static func sha256(_ document: SecretCatalogDocument) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(document)) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Hashes the sorted opaque reference set without exposing the references
    /// in recovery-plan or diagnostic summaries.
    public static func referenceSetSHA256(_ document: SecretCatalogDocument) -> String {
        let references = document.entries
            .flatMap { $0.fields.compactMap(\.secretRef) }
            .sorted()
            .joined(separator: "\n")
        return SHA256.hash(data: Data(references.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
