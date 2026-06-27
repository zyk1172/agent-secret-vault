import Foundation
import VaultCore
import VaultIPC

public actor VaultAppServices: WorkbenchServicing {
    private let encryptSelection: any EncryptSelectionCoordinating
    private let activeRoot: URL?

    public init(encryptSelection: any EncryptSelectionCoordinating, activeRoot: URL?) {
        self.encryptSelection = encryptSelection
        self.activeRoot = activeRoot
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
        let result = try await encryptSelection.encryptAndReplace(
            plaintext: plaintext,
            label: label,
            policy: policy
        )
        switch result {
        case let .replaced(reference), let .unlinkedRecord(reference):
            return reference.description
        }
    }

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-\(UUID().uuidString)"
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}
