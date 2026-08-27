import Foundation
import Testing
import VaultCore
import VaultIPC

private struct ControlService: AppControlServicing {
    func catalogStatus() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 3)
    }

    func repairCatalogFormat(expectedRawSHA256: String) async throws -> CatalogValidationResult {
        _ = expectedRawSHA256
        return CatalogValidationResult(status: .found, revision: 4)
    }

    func catalogFormatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        nil
    }

    func catalogRecentAuditEntries(limit: Int) async throws -> [CatalogSecurityAuditEntry] {
        _ = limit
        return []
    }

    func catalogAuditHealth() async -> String? { nil }

    func catalogSecureInputRequest(id _: UUID) async throws -> CatalogAgentSecureInputRequest {
        throw AppControlRequestHandlerError.unsupportedRequest
    }

    func submitCatalogSecureInput(
        id: UUID,
        submission: CatalogSecureInputSubmission
    ) async throws -> CatalogSecureInputStatus {
        _ = submission
        return CatalogSecureInputStatus(requestID: id, status: .completed, revision: 4)
    }

    func beginCatalogSecureInputCommit(id _: UUID) async throws -> CatalogAgentSecureInputRequest {
        throw AppControlRequestHandlerError.unsupportedRequest
    }

    func completeCatalogSecureInput(id _: UUID, completion _: CatalogSecureInputCompletion) async {}

    func cancelCatalogSecureInput(id _: UUID) async {}

    func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 1)
    }

    func adoptCatalogExternalV3() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 1)
    }

    func approveCatalogExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> CatalogValidationResult {
        _ = (expectedRevision, expectedRawSHA256, expectedSemanticSHA256)
        return CatalogValidationResult(status: .found, revision: 2)
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

    func pendingCatalogWriteAccessRequest(id _: UUID) async throws -> CatalogAgentWriteAccessRequest {
        CatalogAgentWriteAccessRequest(
            source: .codex,
            reasonCategory: .knowledgeMaintenance,
            duration: .singleUse
        )
    }

    func respondToCatalogWriteAccessRequest(id _: UUID, approved _: Bool) async throws {}

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

    func catalogCommitEntryEdit(
        _ entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        _ = (entry, secretInputs)
        return CatalogWriteResult(revision: expectedRevision + 1)
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

    func catalogRevealField(entryID: String, key: String) async throws -> String {
        _ = (entryID, key)
        return "ASV_REVEAL_TEST_VALUE"
    }

    func catalogApplyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        _ = mutation
        return CatalogWriteResult(revision: expectedRevision + 1)
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

    let secureInputRequestID = UUID()
    let secureInputRequest = AppControlRequest.catalogSubmitSecureInput(
        id: secureInputRequestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: ["0123456789ABCDEFGHJKMNPQRT:password"],
            plaintextByFieldKey: ["password": "ASV_SECURE_INPUT_CANARY"]
        )
    )
    let decodedSecureInputRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(secureInputRequest)
    )
    #expect(decodedSecureInputRequest == secureInputRequest)

    let secureInputResponse = await AppControlRequestHandler(service: ControlService()).handle(secureInputRequest)
    #expect(secureInputResponse == .catalogSecureInputStatus(
        CatalogSecureInputStatus(requestID: secureInputRequestID, status: .completed, revision: 4)
    ))
    let encodedSecureInputResponse = String(decoding: try JSONEncoder().encode(secureInputResponse), as: UTF8.self)
    #expect(!encodedSecureInputResponse.contains("ASV_SECURE_INPUT_CANARY"))

    let commitRequest = AppControlRequest.catalogCommitEntryEdit(
        entry: SecretCatalogEntry(
            id: "0123456789ABCDEFGHJKMNPQRT",
            indexId: "0123456789ABCDEFGHJKMNPQRS",
            title: "QNAP",
            fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
        ),
        secretInputs: [CatalogSecretInput(key: "password", label: "密码", plaintext: "ASV_ENTRY_EDIT_CANARY")],
        expectedRevision: 3
    )
    let decodedCommitRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(commitRequest)
    )
    #expect(decodedCommitRequest == commitRequest)

    let approvalRequest = AppControlRequest.catalogApproveExternalChange(
        expectedRevision: 7,
        expectedRawSHA256: String(repeating: "a", count: 64),
        expectedSemanticSHA256: String(repeating: "b", count: 64)
    )
    let decodedApprovalRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(approvalRequest)
    )
    #expect(decodedApprovalRequest == approvalRequest)

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
