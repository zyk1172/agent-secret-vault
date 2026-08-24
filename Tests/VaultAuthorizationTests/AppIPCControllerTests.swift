import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultIPC
import VaultService
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

@Test func controllerRotatesCapabilityTokenAcrossRestart() async throws {
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-rotate-\(UUID().uuidString)")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(directoryURL: directoryURL))
    let controller = AppIPCController(
        server: server,
        handler: IPCRequestHandler(service: ControllerSpyWorkbenchService())
    )
    defer {
        controller.stop()
        try? FileManager.default.removeItem(at: directoryURL)
    }

    try controller.start()
    let oldToken = try CapabilityToken(base64Encoded: String(contentsOf: server.configuration.tokenURL).trimmingCharacters(in: .whitespacesAndNewlines))
    let oldFrame = try IPCFrameCodec.encode(AuthenticatedIPCRequest(capabilityToken: oldToken, request: .status))

    controller.stop()
    try controller.start()
    let newToken = try CapabilityToken(base64Encoded: String(contentsOf: server.configuration.tokenURL).trimmingCharacters(in: .whitespacesAndNewlines))
    #expect(oldToken != newToken)

    let rejectedFrame = try await controller.handleAuthenticatedFrame(oldFrame)
    #expect(try IPCFrameCodec.decode(IPCResponse.self, from: rejectedFrame) == .failure(code: "INVALID_CAPABILITY_TOKEN"))
}

@Test func controllerRejectsAnUnboundedClientConfiguration() throws {
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-limit-\(UUID().uuidString)")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(directoryURL: directoryURL))
    let controller = AppIPCController(
        server: server,
        handler: IPCRequestHandler(service: ControllerSpyWorkbenchService()),
        maxActiveClients: 0
    )

    #expect(throws: AppIPCControllerError.invalidMaxActiveClients) {
        try controller.start()
    }
    try? FileManager.default.removeItem(at: directoryURL)
}

@Test func appControlIPCUsesRealCatalogStoreAndHMACPathForEntryCreation() async throws {
    let root = URL(fileURLWithPath: "/tmp/svlt-app-control-\(UUID().uuidString.prefix(8))")
    let ipcRoot = root.appendingPathComponent("ipc", isDirectory: true)
    let documentURL = root.appendingPathComponent("敏感信息.md")
    let selectionURL = root.appendingPathComponent("selection.json")
    let integrityURL = root.appendingPathComponent("catalog-integrity.json")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let store = SensitiveCatalogDocumentStore(
        documentURL: documentURL,
        integrityURL: integrityURL,
        keyStore: try FixedCatalogIntegrityKeyStore(key: Data(repeating: 11, count: 32))
    )
    try await store.selectDocument(at: documentURL)
    _ = try await store.canonicalWrite(SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: "0123456789ABCDEFGHJKMNPQRS", title: "QNAP")]
    ))
    try SecretCatalogSelectionStore(manifestURL: selectionURL).save(documentURL: documentURL)

    let service = VaultAppServices(
        textEncryptor: IntegrationTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: store,
        catalogSelectionManifestURL: selectionURL,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization()
    )
    let configuration = try UnixSocketServerConfiguration.appControlConfiguration(directoryURL: ipcRoot)
    let controller = AppControlIPCController(
        server: UnixSocketServer(configuration: configuration),
        handler: AppControlRequestHandler(service: service),
        peerAuthenticator: AppControlPeerAuthenticator(validator: { _ in true })
    )
    try controller.start()
    defer { controller.stop() }

    let client = AppControlIPCClient(configuration: configuration)
    let result = try await client.catalogCreateEntry(
        CatalogDraftRequest(
            indexID: "0123456789ABCDEFGHJKMNPQRS",
            title: "音乐服务器",
            endpoints: [CatalogEndpoint(type: "http", host: "192.168.2.240", port: 4533)],
            fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("zyk")),
                SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
            ]
        ),
        expectedRevision: 1
    )

    #expect(result.revision == 2)
    #expect(result.entry?.title == "音乐服务器")
    let verified = try await store.snapshot()
    #expect(verified.revision == 2)
    #expect(verified.integrity == .verified)
    #expect(verified.document.entries.first?.fields.first(where: { $0.key == "username" })?.value == .string("zyk"))
    #expect(verified.document.entries.first?.fields.first(where: { $0.key == "password" })?.secretRef == nil)
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

private struct IntegrationTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    }
}
