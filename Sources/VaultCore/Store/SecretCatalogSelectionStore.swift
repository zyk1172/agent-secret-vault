import Foundation

public enum SecretCatalogSelectionStoreError: Error, Equatable, Sendable {
    case invalidManifest
    case symlinkRejected
    case malformedDocumentPath
    case writeFailed
}

/// Shares only the user-selected catalog path between the UI App and the
/// independent Agent.  The manifest never contains catalog text or secrets.
public struct SecretCatalogSelectionStore: Sendable {
    public struct Manifest: Codable, Equatable, Sendable {
        public let documentPath: String

        public init(documentPath: String) {
            self.documentPath = documentPath
        }
    }

    public let manifestURL: URL

    public init(manifestURL: URL) {
        self.manifestURL = manifestURL.standardizedFileURL
    }

    public static func defaultManifestURL(fileManager: FileManager = .default) throws -> URL {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return appSupport
            .appendingPathComponent("AgentSecretVault", isDirectory: true)
            .appendingPathComponent("sensitive-index-selection.json")
    }

    public func selectedDocumentURL() throws -> URL? {
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            return nil
        }
        try assertSafeFile(manifestURL)
        let data = try Data(contentsOf: manifestURL)
        let manifest: Manifest
        do {
            manifest = try JSONDecoder().decode(Manifest.self, from: data)
        } catch {
            throw SecretCatalogSelectionStoreError.invalidManifest
        }
        guard manifest.documentPath.hasPrefix("/"), !manifest.documentPath.contains("\0") else {
            throw SecretCatalogSelectionStoreError.malformedDocumentPath
        }
        return URL(fileURLWithPath: manifest.documentPath).standardizedFileURL
    }

    public func save(documentURL: URL) throws {
        let normalized = documentURL.standardizedFileURL
        guard normalized.path.hasPrefix("/"), normalized.pathExtension.lowercased() == "md" else {
            throw SecretCatalogSelectionStoreError.malformedDocumentPath
        }

        let parent = manifestURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try assertSafeDirectory(parent)

        let data = try JSONEncoder().encode(Manifest(documentPath: normalized.path))
        let temporaryURL = parent.appendingPathComponent(".sensitive-index-selection-\(UUID().uuidString).tmp")
        do {
            try data.write(to: temporaryURL, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporaryURL.path)
            try assertSafeFile(temporaryURL)
            guard try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: temporaryURL))
                    == Manifest(documentPath: normalized.path)
            else {
                throw SecretCatalogSelectionStoreError.writeFailed
            }
            if FileManager.default.fileExists(atPath: manifestURL.path) {
                try assertSafeFile(manifestURL)
                _ = try FileManager.default.replaceItemAt(manifestURL, withItemAt: temporaryURL)
            } else {
                try FileManager.default.moveItem(at: temporaryURL, to: manifestURL)
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        } catch {
            try? FileManager.default.removeItem(at: temporaryURL)
            if let error = error as? SecretCatalogSelectionStoreError {
                throw error
            }
            throw SecretCatalogSelectionStoreError.writeFailed
        }
    }

    private func assertSafeFile(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else {
            throw SecretCatalogSelectionStoreError.invalidManifest
        }
        guard values.isSymbolicLink != true else {
            throw SecretCatalogSelectionStoreError.symlinkRejected
        }
    }

    private func assertSafeDirectory(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else {
            throw SecretCatalogSelectionStoreError.invalidManifest
        }
        guard values.isSymbolicLink != true else {
            throw SecretCatalogSelectionStoreError.symlinkRejected
        }
    }
}
