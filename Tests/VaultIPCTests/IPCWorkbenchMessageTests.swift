import Foundation
import Testing
import VaultIPC

@Test func workbenchRequestsRoundTripWithoutPlaintextResponseFields() throws {
    let requests: [IPCRequest] = [
        .workbenchStatus,
        .revealReferences(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "Paragraph reveal",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            )
        ),
        .exportResolvedText(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "Local file export",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            ),
            destinationPath: "/Users/example/Desktop/token.md"
        ),
        .scanOrphans(markdownReferences: ["secret://0123456789ABCDEFGHJKMNPQRS"])
    ]

    for request in requests {
        let encoded = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(IPCRequest.self, from: encoded)
        #expect(decoded == request)
    }

    let responses: [IPCResponse] = [
        .workbenchStatus(WorkbenchStatus(
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: "/tmp/kb",
            pluginConnected: true
        )),
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .revealSessionOpened(sessionID: "session-1"),
        .exported(path: "/Users/example/Desktop/token.md"),
        .orphanScan(OrphanScanResult(missingRecords: [], unreferencedRecords: [])),
        .failure(code: "APP_LOCKED")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let json = String(decoding: encoded, as: UTF8.self)
        #expect(!json.contains("plaintext"))
        #expect(!json.contains("resolvedValue"))
        #expect(!json.contains("secretValue"))
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: encoded)
        #expect(decoded == response)
    }
}

@Test func agentIPCRejectsPlaintextEncryptRequestsAtTheWireBoundary() throws {
    let data = Data(#"{"type":"encryptText","plaintext":"AGENT_IPC_CANARY","policy":"credential"}"#.utf8)

    #expect(throws: DecodingError.self) {
        _ = try JSONDecoder().decode(IPCRequest.self, from: data)
    }
}

@Test func workbenchStatusEncodesNilKnowledgeBaseRootAsExplicitNull() throws {
    let status = WorkbenchStatus(
        locked: true,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: false
    )

    let encoded = try JSONEncoder().encode(status)
    let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])

    #expect(object.keys.contains("activeKnowledgeBaseRoot"))
    #expect(object["activeKnowledgeBaseRoot"] is NSNull)

    let decoded = try JSONDecoder().decode(WorkbenchStatus.self, from: encoded)
    #expect(decoded == status)
}
