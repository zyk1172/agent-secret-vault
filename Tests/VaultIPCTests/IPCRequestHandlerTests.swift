import Foundation
import Testing
import VaultCore
import VaultIPC

private actor SpyWorkbenchService: WorkbenchServicing {
    var encryptCalls: [String] = []
    var revealCalls: [[String]] = []
    var restoreCalls: [[String]] = []
    var exportCalls: [(references: [String], destinationPath: String)] = []

    func status() async -> WorkbenchStatus {
        WorkbenchStatus(locked: false, ipcAvailable: true, activeKnowledgeBaseRoot: "/tmp/kb", pluginConnected: true)
    }

    func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata {
        SecretReferenceMetadata(
            reference: reference,
            policy: .read,
            label: "NAS password",
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        encryptCalls.append(plaintext)
        return "secret://0123456789ABCDEFGHJKMNPQRS"
    }

    func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        revealCalls.append(references)
        return "session-1"
    }

    func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        restoreCalls.append(references)
        return "restored plaintext"
    }

    func exportResolvedText(
        references: [String],
        context: RevealContext,
        destinationPath: String
    ) async throws -> String {
        exportCalls.append((references: references, destinationPath: destinationPath))
        return destinationPath
    }

    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}

@Test func handlerReturnsRestoredTextOnlyForExplicitRestoreRequests() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)

    let response = try await handler.handle(.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Restore current paragraph",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    ))

    #expect(response == .restoredText("restored plaintext"))
}

@Test func handlerReturnsOnlyExportPathForLocalFileExports() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)
    let destinationPath = "/Users/example/Desktop/NAS.md"

    let response = try await handler.handle(.exportResolvedText(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "Export local file",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        ),
        destinationPath: destinationPath
    ))

    #expect(response == .exported(path: destinationPath))
    let encoded = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    #expect(!encoded.contains("restored plaintext"))
}

@Test func handlerSupportsLegacyMCPRequestsWithoutPlaintextResponses() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)

    #expect(try await handler.handle(.status) == .status(locked: false))
    #expect(try await handler.handle(.inspectReference(reference: "secret://0123456789ABCDEFGHJKMNPQRS")) == .referenceMetadata(SecretReferenceMetadata(
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        policy: .read,
        label: "NAS password",
        createdAt: Date(timeIntervalSinceReferenceDate: 1),
        updatedAt: Date(timeIntervalSinceReferenceDate: 2)
    )))
    #expect(try await handler.handle(.reveal(
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        reason: "show to user"
    )) == .displayedToUser)
    #expect(try await handler.handle(.encrypt(label: nil, policy: .credential)) == .failure(code: "SELECTION_ENCRYPT_UNAVAILABLE"))
    #expect(try await handler.handle(.execute(.init(
        templateID: "noop",
        executable: "/usr/bin/true",
        values: [:],
        secrets: [:],
        destinationHost: nil,
        destinationPath: nil,
        requestedRisk: .read
    ))) == .failure(code: "EXECUTE_UNAVAILABLE"))
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
