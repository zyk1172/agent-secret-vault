import AppKit
import Foundation
import VaultCore

public enum SensitiveCatalogTemplateStoreError: Error, Equatable, Sendable {
    case packagedTemplateMissing
    case packagedTemplateMismatch
    case supportDirectoryUnsafe
    case supportTemplateUnsafe
}

/// Installs the read-only packaged Catalog template into the App Support
/// directory. This store never receives a user-vault URL and never writes to
/// the selected Catalog.
public final class SensitiveCatalogTemplateStore: @unchecked Sendable {
    private static let resourceName = "敏感信息"
    private static let resourceExtension = "md"
    private static let applicationDirectory = "AgentSecretVault"
    private static let templateDirectory = "Templates"

    private let bundle: Bundle
    private let fileManager: FileManager

    public init(
        bundle: Bundle = Bundle(for: SensitiveCatalogTemplateStore.self),
        fileManager: FileManager = .default
    ) {
        self.bundle = bundle
        self.fileManager = fileManager
    }

    public var supportTemplateURL: URL {
        applicationSupportDirectory
            .appendingPathComponent(Self.applicationDirectory, isDirectory: true)
            .appendingPathComponent(Self.templateDirectory, isDirectory: true)
            .appendingPathComponent("\(Self.resourceName).\(Self.resourceExtension)", isDirectory: false)
    }

    public func packagedTemplateURL() throws -> URL {
        if let url = bundle.url(
            forResource: Self.resourceName,
            withExtension: Self.resourceExtension,
            subdirectory: Self.templateDirectory
        ) {
            return url
        }
        if let url = Bundle.main.url(
            forResource: Self.resourceName,
            withExtension: Self.resourceExtension,
            subdirectory: Self.templateDirectory
        ) {
            return url
        }
        throw SensitiveCatalogTemplateStoreError.packagedTemplateMissing
    }

    @discardableResult
    public func ensureInstalled() throws -> URL {
        let packagedURL = try packagedTemplateURL()
        let packagedData = try Data(contentsOf: packagedURL, options: [.mappedIfSafe])
        let canonicalData = try SensitiveCatalogDocumentCodec.canonicalData(SecretCatalogDocument())
        guard packagedData == canonicalData else {
            throw SensitiveCatalogTemplateStoreError.packagedTemplateMismatch
        }

        let directory = supportTemplateURL.deletingLastPathComponent()
        try makeSafeDirectory(directory)
        if fileManager.fileExists(atPath: supportTemplateURL.path) {
            try assertSafeFile(supportTemplateURL)
        }
        let installedData: Data? = fileManager.fileExists(atPath: supportTemplateURL.path)
            ? try Data(contentsOf: supportTemplateURL, options: [.mappedIfSafe])
            : nil
        if installedData != packagedData {
            try packagedData.write(to: supportTemplateURL, options: [.atomic])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: supportTemplateURL.path)
        }
        return supportTemplateURL
    }

    public func revealInFinder() throws -> URL {
        let url = try ensureInstalled()
        NSWorkspace.shared.activateFileViewerSelecting([url])
        return url
    }

    private var applicationSupportDirectory: URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support", isDirectory: true)
    }

    private func makeSafeDirectory(_ url: URL) throws {
        if fileManager.fileExists(atPath: url.path) {
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true, values.isSymbolicLink != true else {
                throw SensitiveCatalogTemplateStoreError.supportDirectoryUnsafe
            }
        } else {
            try fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private func assertSafeFile(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory != true, values.isSymbolicLink != true else {
            throw SensitiveCatalogTemplateStoreError.supportTemplateUnsafe
        }
    }
}
