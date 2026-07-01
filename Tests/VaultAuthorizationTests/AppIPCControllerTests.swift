import Foundation
import Testing
import VaultCore
import VaultIPC
@testable import AgentSecretVaultApp

@Test func appIPCControllerPublishesEndpointMetadataWithoutSecrets() throws {
    let metadata = AppIPCController.EndpointMetadata(socketPath: "/tmp/asv.sock")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let encoded = try encoder.encode(metadata)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(json.contains("/tmp/asv.sock"))
    #expect(!json.contains("capability"))
    #expect(!json.contains("token"))
}

@Test func appIPCControllerHandlesAuthenticatedFrames() async throws {
    let service = ControllerSpyWorkbenchService()
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-\(UUID().uuidString.prefix(8))")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(
        directoryURL: directoryURL
    ))
    let controller = AppIPCController(server: server, handler: IPCRequestHandler(service: service))
    try controller.start()
    defer {
        controller.stop()
        try? FileManager.default.removeItem(at: directoryURL)
    }

    let token = try CapabilityToken(base64Encoded: String(
        contentsOf: server.configuration.tokenURL,
        encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines))
    let request = AuthenticatedIPCRequest(capabilityToken: token, request: .workbenchStatus)
    let responseFrame = try await controller.handleAuthenticatedFrame(try IPCFrameCodec.encode(request))
    let response = try IPCFrameCodec.decode(IPCResponse.self, from: responseFrame)

    #expect(response == .workbenchStatus(WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: false
    )))
}

private actor ControllerSpyWorkbenchService: WorkbenchServicing {
    func status() async -> WorkbenchStatus {
        WorkbenchStatus(locked: false, ipcAvailable: true, activeKnowledgeBaseRoot: nil, pluginConnected: false)
    }

    func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata {
        SecretReferenceMetadata(
            reference: reference,
            policy: .read,
            label: nil,
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        "secret://0123456789ABCDEFGHJKMNPQRS"
    }

    func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-1"
    }

    func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        "restored plaintext"
    }

    func exportResolvedText(
        references: [String],
        context: RevealContext,
        destinationPath: String
    ) async throws -> String {
        destinationPath
    }

    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}
