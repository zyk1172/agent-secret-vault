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

        for id in try await recordIDs() {
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

    private func recordIDs() async throws -> [String] {
        let store = FileRecordStore(baseDirectory: baseDirectory)
        return try await store.recordIDs()
    }

    private func scanMarkdownReferences() throws -> [String: Set<URL>] {
        var references: [String: Set<URL>] = [:]

        for directory in markdownDirectories {
            for url in try markdownFiles(under: directory) {
                let text = try String(contentsOf: url, encoding: .utf8)
                for id in MarkdownReferenceScanner.referenceIDs(in: text) {
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
}
