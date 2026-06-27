import Foundation
import Testing
import VaultCore
import VaultIPC

private actor SpyWorkbenchService: WorkbenchServicing {
    var encryptCalls: [String] = []

    func status() async -> WorkbenchStatus {
        WorkbenchStatus(locked: false, ipcAvailable: true, activeKnowledgeBaseRoot: "/tmp/kb", pluginConnected: true)
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        encryptCalls.append(plaintext)
        return "secret://0123456789ABCDEFGHJKMNPQRS"
    }

    func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-1"
    }

    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}

@Test func handlerReturnsStatusAndNeverPlaintextInEncryptResponse() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)

    let status = try await handler.handle(.workbenchStatus)
    #expect(status == .workbenchStatus(WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: "/tmp/kb",
        pluginConnected: true
    )))

    let encrypted = try await handler.handle(.encryptText(
        plaintext: "ASV_CANARY_HANDLER",
        label: nil,
        policy: .credential
    ))
    #expect(encrypted == .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"))
    let encoded = try JSONEncoder().encode(encrypted)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("ASV_CANARY_HANDLER"))
}
