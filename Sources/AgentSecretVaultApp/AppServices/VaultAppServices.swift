import Foundation
import VaultCore
import VaultIPC

public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}

public actor VaultAppServices: WorkbenchServicing {
    private let textEncryptor: any TextEncrypting
    private let activeRoot: URL?

    public init(textEncryptor: any TextEncrypting, activeRoot: URL?) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
    }

    public init(encryptSelection: any EncryptSelectionCoordinating & TextEncrypting, activeRoot: URL?) {
        self.init(textEncryptor: encryptSelection, activeRoot: activeRoot)
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
        "session-\(UUID().uuidString)"
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}
