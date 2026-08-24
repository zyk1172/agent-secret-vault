import Foundation
import Darwin
import Testing
import VaultAuthorization
import VaultCore
import VaultExecution
@testable import VaultIPC

private let testIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let testEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let testSecretReference = "secret://0123456789ABCDEFGHJKMNPQRS"

private func sampleCatalogMatch() -> SecretCatalogMatch {
    SecretCatalogMatch(
        index: SecretCatalogIndexMatch(
            id: testIndexID,
            title: "QNAP",
            aliases: ["NAS"],
            tags: ["设备"]
        ),
        entry: SecretCatalogEntryMatch(
            id: testEntryID,
            indexId: testIndexID,
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: ["QNAP 登录"],
            endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
            fields: [
                SecretCatalogFieldMatch(
                    key: "username",
                    label: "用户名",
                    type: .text,
                    value: .string("admin")
                ),
                SecretCatalogFieldMatch(
                    key: "password",
                    label: "密码",
                    type: .secret,
                    secretRef: testSecretReference
                )
            ],
            notes: "管理后台",
            tags: ["QNAP"]
        )
    )
}

@Test func requestJSONRoundTripsEveryCase() throws {
    let requests: [IPCRequest] = [
        .status,
        .workbenchStatus,
        .savedReferences,
        .searchCatalog(query: "QNAP", field: .password, limit: 10),
        .catalogSearch(query: "Komga", field: nil, limit: 20),
        .catalogGet(entryID: testEntryID),
        .catalogCreateDraft(
            request: CatalogDraftRequest(indexID: testIndexID, title: "SSH", fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("zyk"))
            ])
        ),
        .catalogPatchMetadata(
            entryID: testEntryID,
            patch: CatalogMetadataPatch(title: "新标题"),
            expectedRevision: 1
        ),
        .catalogCommit(
            draft: CatalogDraft(draftID: testEntryID, baseRevision: 1, entry: sampleCatalogMatch().entry),
            expectedRevision: 1
        ),
        .catalogAddSecretPlaceholder(
            entryID: testEntryID,
            key: "token",
            label: "Token",
            agentVisible: true,
            searchable: false,
            expectedRevision: 1
        ),
        .catalogBindExistingSecret(
            entryID: testEntryID,
            key: "password",
            secretRef: testSecretReference,
            expectedRevision: 1
        ),
        .catalogValidate,
        .pendingRevealSessions,
        .inspectReference(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .deleteRecord(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .authorizeHighRisk(reason: "delete record"),
        .lock,
        .clearRevealSessions,
        .revealSessionData(sessionID: "session-1"),
        .reveal(reference: "secret://0123456789ABCDEFGHJKMNPQRS", reason: "show to user"),
        .encrypt(label: "api token", policy: .externalSend),
        .encryptBound(
            label: "QNAP credential",
            policy: .credential,
            allowedDestinations: ["qnap.local", "192.168.2.240"],
            allowedProtocols: ["ssh", "https"]
        ),
        .restoreReferences(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "restore",
                template: "{{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            )
        ),
        .exportResolvedText(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "export",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            ),
            destinationPath: "/Users/example/Desktop/token.md"
        ),
        .execute(ExecutionRequest(
            templateID: "send-message",
            executable: "/usr/bin/printf",
            values: ["message": "hello"],
            secrets: ["apiToken": try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
            destinationHost: "api.example.com",
            destinationPath: "/v1/send",
            requestedRisk: .writeOrExternalSend
        )),
        .executeSecretOperation(SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
            destination: "qnap.local",
            port: 22,
            protocolType: .ssh,
            command: "hostname",
            requestedEffects: ["read-only"],
            parameters: ["passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS"],
            agentAssessment: AgentRiskAssessment(
                declaredRisk: .silent,
                reason: "read-only diagnostic",
                intendedEffect: "read status"
            )
        ))
    ]

    for request in requests {
        let encoded = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(IPCRequest.self, from: encoded)

        #expect(decoded == request)
    }
}

@Test func responseJSONRoundTripsEveryCase() throws {
    let responses: [IPCResponse] = [
        .status(locked: false),
        .workbenchStatus(WorkbenchStatus(locked: true, ipcAvailable: true, activeKnowledgeBaseRoot: nil, pluginConnected: false)),
        .savedReferences([]),
        .catalogSearchResult(SecretCatalogSearchResult(
            status: .found,
            matches: [sampleCatalogMatch()]
        )),
        .catalogDraft(CatalogDraft(draftID: testEntryID, baseRevision: 1, entry: sampleCatalogMatch().entry)),
        .catalogWriteResult(CatalogWriteResult(revision: 2, entry: sampleCatalogMatch().entry)),
        .catalogValidation(status: .found, revision: 2),
        .referenceMetadata(SecretReferenceMetadata(
            reference: "secret://0123456789ABCDEFGHJKMNPQRS",
            policy: .read,
            label: "NAS password",
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )),
        .displayedToUser,
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .restoredText("restored value"),
        .exported(path: "/Users/example/Desktop/token.md"),
        .execution(.completed(exitCode: 0, stdout: "ok [REDACTED_SECRET]", stderr: "")),
        .execution(.quarantined(reason: .binaryOutput)),
        .secretOperation(SecretOperationOutput(status: "COMPLETED", httpStatus: 200, contentType: "application/json", bodyPreview: "{\"ok\":true}")),
        .failure(code: "APP_UNAVAILABLE")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: encoded)

        #expect(decoded == response)
    }
}

@Test func encodedResponsesNeverContainPlaintextShapedKeys() throws {
    let responses: [IPCResponse] = [
        .status(locked: true),
        .referenceMetadata(SecretReferenceMetadata(
            reference: "secret://0123456789ABCDEFGHJKMNPQRS",
            policy: .read,
            label: "NAS password",
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )),
        .displayedToUser,
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .exported(path: "/Users/example/Desktop/token.md"),
        .execution(.completed(exitCode: 0, stdout: "sanitized", stderr: "")),
        .execution(.quarantined(reason: .encodedSecretVariantDetected)),
        .failure(code: "DENIED")
    ]

    for response in responses {
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(response))
        let forbiddenKeys = collectForbiddenKeys(in: object)

        #expect(forbiddenKeys.isEmpty)
    }
}

@Test func frameCodecUsesBigEndianLengthPrefixAndRoundTripsJSON() throws {
    let frame = try IPCFrameCodec.encode(IPCResponse.status(locked: false))

    #expect(frame.count > 4)
    #expect(frame.prefix(4).elementsEqual([0, 0, 0, UInt8(frame.count - 4)]))

    let decoded = try IPCFrameCodec.decode(IPCResponse.self, from: frame)
    #expect(decoded == .status(locked: false))
}

@Test func frameCodecRejectsFramesOverOneMiB() throws {
    let oversizedPayload = Data(repeating: 0x41, count: 1_048_577)
    var frame = Data([0, 16, 0, 1])
    frame.append(oversizedPayload)

    #expect(throws: IPCFrameError.frameTooLarge) {
        _ = try IPCFrameCodec.decode(IPCResponse.self, from: frame)
    }
}

@Test func capabilityTokenRequiresExactlyThirtyTwoDecodedBytes() throws {
    let valid = try CapabilityToken(base64Encoded: Data(repeating: 0xA5, count: 32).base64EncodedString())

    #expect(valid.rawValue == Data(repeating: 0xA5, count: 32).base64EncodedString())
    #expect(throws: CapabilityTokenError.invalidEncoding) {
        _ = try CapabilityToken(base64Encoded: "not base64")
    }
    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 31)) {
        _ = try CapabilityToken(base64Encoded: Data(repeating: 0x00, count: 31).base64EncodedString())
    }
    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 33)) {
        _ = try CapabilityToken(base64Encoded: Data(repeating: 0x00, count: 33).base64EncodedString())
    }
}

@Test func authenticatedRequestRejectsNon256BitTokenDuringDecoding() throws {
    let json = """
    {
      "capabilityToken": "\(Data(repeating: 0x00, count: 16).base64EncodedString())",
      "request": { "type": "status" }
    }
    """.data(using: .utf8)!

    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 16)) {
        _ = try JSONDecoder().decode(AuthenticatedIPCRequest.self, from: json)
    }
}

@Test func authenticatedRequestRoundTripsWithValidatedCapabilityToken() throws {
    let token = try CapabilityToken(base64Encoded: Data(repeating: 0x7F, count: 32).base64EncodedString())
    let request = AuthenticatedIPCRequest(capabilityToken: token, request: .status)

    let encoded = try JSONEncoder().encode(request)
    let decoded = try JSONDecoder().decode(AuthenticatedIPCRequest.self, from: encoded)

    #expect(decoded == request)
}

@Test func authenticatorReturnsRequestOnlyForMatchingCapabilityToken() throws {
    let expected = try CapabilityToken(base64Encoded: Data(repeating: 0x11, count: 32).base64EncodedString())
    let different = try CapabilityToken(base64Encoded: Data(repeating: 0x22, count: 32).base64EncodedString())
    let authenticator = IPCAuthenticator(expectedToken: expected)

    let authenticated = AuthenticatedIPCRequest(capabilityToken: expected, request: .status)
    #expect(try authenticator.authenticate(authenticated) == .status)

    let rejected = AuthenticatedIPCRequest(capabilityToken: different, request: .status)
    #expect(throws: IPCAuthenticationError.invalidCapabilityToken) {
        _ = try authenticator.authenticate(rejected)
    }
}

@Test func serverWritesCapabilityTokenFileWithOwnerOnlyPermissions() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appending(path: "vault-ipc-\(UUID().uuidString)")
    let configuration = UnixSocketServerConfiguration(directoryURL: temporaryDirectory)
    let server = UnixSocketServer(configuration: configuration)
    let token = try CapabilityToken(base64Encoded: Data(repeating: 0x4D, count: 32).base64EncodedString())

    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    try server.writeCapabilityToken(token)

    let tokenData = try Data(contentsOf: configuration.tokenURL)
    #expect(tokenData == Data(token.rawValue.utf8))

    var fileStat = stat()
    #expect(stat(configuration.tokenURL.path, &fileStat) == 0)
    #expect((fileStat.st_mode & 0o777) == 0o600)
}

@Test func serverBindsSocketUnderConfiguredDirectoryWithOwnerOnlyPermissions() throws {
    let temporaryDirectory = URL(filePath: "/tmp")
        .appending(path: "vipc-\(UUID().uuidString)")
    let configuration = UnixSocketServerConfiguration(directoryURL: temporaryDirectory)
    let server = UnixSocketServer(configuration: configuration)

    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let boundSocket = try server.bindListeningSocket()
    defer {
        boundSocket.close()
    }

    #expect(boundSocket.fileDescriptor >= 0)

    var socketStat = stat()
    #expect(stat(configuration.socketURL.path, &socketStat) == 0)
    #expect((socketStat.st_mode & 0o777) == 0o600)
}

@Test func controlPlaneResponsesRoundTripWithoutPlaintext() throws {
    let responses: [IPCResponse] = [
        .operationCompleted,
        .authorizationApproved,
        .savedReferences([]),
        .revealSessionIDs(["session-1"]),
        .revealSessionData(RestoredParagraph(text: "redacted", values: []))
    ]
    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: encoded)
        #expect(decoded == response)
    }
}

private func collectForbiddenKeys(in value: Any) -> [String] {
    let forbidden = /plaintext|secretValue|resolvedArguments|masterKey/.ignoresCase()

    if let dictionary = value as? [String: Any] {
        return dictionary.flatMap { key, nestedValue in
            var matches: [String] = []
            if key.contains(forbidden) {
                matches.append(key)
            }
            matches.append(contentsOf: collectForbiddenKeys(in: nestedValue))
            return matches
        }
    }

    if let array = value as? [Any] {
        return array.flatMap(collectForbiddenKeys)
    }

    return []
}
