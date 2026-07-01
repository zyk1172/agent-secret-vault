import Foundation

public enum FileWrappedMasterKeyStoreError: Error, Equatable, Sendable {
    case parentDirectoryIsNotDirectory
    case symlinkRejected
}

public struct FileWrappedMasterKeyStore: WrappedMasterKeyStoring {
    private let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL.standardizedFileURL
    }

    public func loadWrappedMasterKeySet() async throws -> WrappedMasterKeySet? {
        try rejectSymlink(at: fileURL)
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(WrappedMasterKeySet.self, from: data)
    }

    public func saveWrappedMasterKeySet(_ wrapped: WrappedMasterKeySet) async throws {
        let parent = fileURL.deletingLastPathComponent()
        try createDirectoryRejectingSymlink(parent)
        try rejectSymlink(at: fileURL)
        let data = try JSONEncoder().encode(wrapped)
        try data.write(to: fileURL, options: [.atomic])
        try rejectSymlink(at: fileURL)
    }

    private func createDirectoryRejectingSymlink(_ directory: URL) throws {
        if FileManager.default.fileExists(atPath: directory.path) {
            try rejectSymlink(at: directory)
            let values = try directory.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else {
                throw FileWrappedMasterKeyStoreError.parentDirectoryIsNotDirectory
            }
            return
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try rejectSymlink(at: directory)
    }

    private func rejectSymlink(at url: URL) throws {
        if (try? FileManager.default.destinationOfSymbolicLink(atPath: url.path)) != nil {
            throw FileWrappedMasterKeyStoreError.symlinkRejected
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw FileWrappedMasterKeyStoreError.symlinkRejected
        }
    }
}
