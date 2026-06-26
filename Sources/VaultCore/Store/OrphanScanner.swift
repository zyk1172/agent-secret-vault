import Foundation

public struct OrphanCandidate: Equatable, Identifiable, Sendable {
    public let id: String
    public let versions: [Int]
    public let referencedBy: [URL]

    public init(
        id: String,
        versions: [Int],
        referencedBy: [URL]
    ) {
        self.id = id
        self.versions = versions
        self.referencedBy = referencedBy
    }
}

public struct OrphanScanner: Sendable {
    private static let scheme = "secret://"
    private static let idLength = 26
    private static let allowedIDCharacters = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let tokenBoundaryCharacters = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/.-")

    private let baseDirectory: URL
    private let markdownDirectories: [URL]

    public init(
        baseDirectory: URL,
        markdownDirectories: [URL]
    ) {
        self.baseDirectory = baseDirectory
        self.markdownDirectories = markdownDirectories
    }

    public func scan(includeReferenced: Bool = false) async throws -> [OrphanCandidate] {
        let references = try scanMarkdownReferences()
        let store = FileRecordStore(baseDirectory: baseDirectory)
        var candidates: [OrphanCandidate] = []

        for id in try recordIDs() {
            let versions = try await store.versions(id: id)
            if versions.isEmpty {
                continue
            }

            let referencedBy = Array(references[id] ?? []).sorted { $0.path < $1.path }
            if !includeReferenced && !referencedBy.isEmpty {
                continue
            }

            candidates.append(OrphanCandidate(
                id: id,
                versions: versions,
                referencedBy: referencedBy
            ))
        }

        return candidates.sorted { $0.id < $1.id }
    }

    private func recordIDs() throws -> [String] {
        let recordsDirectory = baseDirectory
            .appendingPathComponent(".agent-secret-vault", isDirectory: true)
            .appendingPathComponent("records", isDirectory: true)
        guard FileManager.default.fileExists(atPath: recordsDirectory.path) else {
            return []
        }

        let urls = try FileManager.default.contentsOfDirectory(
            at: recordsDirectory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: [.skipsSubdirectoryDescendants]
        )

        return try urls.compactMap { url in
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true,
                  values.isSymbolicLink != true
            else {
                return nil
            }

            let id = url.lastPathComponent
            return (try? SecretReference("secret://\(id)")).map(\.id)
        }
        .sorted()
    }

    private func scanMarkdownReferences() throws -> [String: Set<URL>] {
        var references: [String: Set<URL>] = [:]

        for directory in markdownDirectories {
            for url in try markdownFiles(under: directory) {
                let text = try String(contentsOf: url, encoding: .utf8)
                for id in Self.extractSecretReferenceIDs(from: text) {
                    references[id, default: []].insert(url)
                }
            }
        }

        return references
    }

    private func markdownFiles(under directory: URL) throws -> [URL] {
        guard FileManager.default.fileExists(atPath: directory.path) else {
            return []
        }

        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        var urls: [URL] = []

        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  url.pathExtension.lowercased() == "md"
            else {
                continue
            }
            urls.append(url.standardizedFileURL)
        }

        return urls.sorted { $0.path < $1.path }
    }

    private static func extractSecretReferenceIDs(from text: String) -> Set<String> {
        var ids: Set<String> = []
        var searchStart = text.startIndex

        while let schemeRange = text.range(of: scheme, range: searchStart..<text.endIndex) {
            defer {
                searchStart = schemeRange.upperBound
            }

            guard isBoundary(previousIndex(before: schemeRange.lowerBound, in: text), in: text) else {
                continue
            }

            var idEnd = schemeRange.upperBound
            var id = ""
            for _ in 0..<idLength {
                guard idEnd < text.endIndex else {
                    id = ""
                    break
                }
                let character = text[idEnd]
                guard allowedIDCharacters.contains(character) else {
                    id = ""
                    break
                }
                id.append(character)
                idEnd = text.index(after: idEnd)
            }

            guard id.count == idLength,
                  isBoundary(idEnd, in: text),
                  (try? SecretReference("\(scheme)\(id)")) != nil
            else {
                continue
            }
            ids.insert(id)
        }

        return ids
    }

    private static func isBoundary(_ index: String.Index?, in text: String) -> Bool {
        guard let index,
              index >= text.startIndex,
              index < text.endIndex
        else {
            return true
        }
        return !tokenBoundaryCharacters.contains(text[index])
    }

    private static func previousIndex(before index: String.Index, in text: String) -> String.Index? {
        guard index > text.startIndex else {
            return nil
        }
        return text.index(before: index)
    }
}
