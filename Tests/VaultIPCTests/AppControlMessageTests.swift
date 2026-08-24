import Foundation
import Testing
import VaultCore
import VaultIPC

private struct ControlService: AppControlServicing {
    func catalogStatus() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 3)
    }

    func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 1)
    }

    func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        CatalogAgentWriteAuthorizationStatus(mode: mode, expiresAt: Date().addingTimeInterval(duration ?? 600))
    }

    func revokeCatalogAgentWrite() async {}

    func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus {
        CatalogAgentWriteAuthorizationStatus(mode: .disabled, expiresAt: nil)
    }

    func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64) {
        ("secret://0123456789ABCDEFGHJKMNPQRS", 4)
    }
}

@Test func appControlMessagesRoundTripWithoutPuttingPlaintextInResponse() async throws {
    let request = AppControlRequest.catalogSecureInput(
        entryID: "0123456789ABCDEFGHJKMNPQRS",
        key: "password",
        label: "QNAP password",
        plaintext: "ASV_APP_CONTROL_CANARY",
        policy: .credential
    )
    let decodedRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(request)
    )
    #expect(decodedRequest == request)

    let bindRequest = AppControlRequest.catalogBindExistingSecret(
        entryID: "0123456789ABCDEFGHJKMNPQRS",
        key: "password",
        secretRef: "secret://0123456789ABCDEFGHJKMNPQRT",
        expectedRevision: 3
    )
    let decodedBindRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(bindRequest)
    )
    #expect(decodedBindRequest == bindRequest)

    let response = await AppControlRequestHandler(service: ControlService()).handle(request)
    let encoded = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    #expect(!encoded.contains("ASV_APP_CONTROL_CANARY"))
    #expect(response == .secretBound(reference: "secret://0123456789ABCDEFGHJKMNPQRS", revision: 4))
}

@Test func appControlPeerIdentityIsInjectedForTests() {
    let authenticator = AppControlPeerAuthenticator(validator: { $0 == 123 })
    #expect(authenticator.isAuthorized(fileDescriptor: 123))
    #expect(!authenticator.isAuthorized(fileDescriptor: 124))
}
