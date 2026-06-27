import Foundation
import Testing
import VaultIPC

@Test func workbenchRequestsRoundTripWithoutPlaintextResponseFields() throws {
    let requests: [IPCRequest] = [
        .workbenchStatus,
        .encryptText(plaintext: "local-only plaintext", label: nil, policy: .credential),
        .revealReferences(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "Paragraph reveal",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            )
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
        .orphanScan(OrphanScanResult(missingRecords: [], unreferencedRecords: [])),
        .failure(code: "APP_LOCKED")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let json = String(decoding: encoded, as: UTF8.self)
        #expect(!json.contains("plaintext"))
        #expect(!json.contains("resolvedValue"))
        #expect(!json.contains("secretValue"))
        _ = try JSONDecoder().decode(IPCResponse.self, from: encoded)
    }
}
