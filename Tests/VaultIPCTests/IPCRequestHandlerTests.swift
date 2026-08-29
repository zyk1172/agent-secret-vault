import Foundation
import Testing
import VaultCore
import VaultIPC

private let handlerIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let handlerEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let handlerSecretReference = "secret://0123456789ABCDEFGHJKMNPQRS"

private func handlerCatalogMatch() -> SecretCatalogMatch {
    SecretCatalogMatch(
        index: SecretCatalogIndexMatch(id: handlerIndexID, title: "QNAP"),
        entry: SecretCatalogEntryMatch(
            id: handlerEntryID,
            indexId: handlerIndexID,
            title: "QNAP 管理后台登录",
            type: "credential",
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
                    secretRef: handlerSecretReference
                )
            ],
            notes: "媒体管理"
        )
    )
}

private actor SpyWorkbenchService: WorkbenchServicing {
    var encryptCalls: [String] = []
    var revealCalls: [[String]] = []
    var exportCalls: [(references: [String], destinationPath: String)] = []
    var searchCalls: [(query: String, field: SecretCatalogField?, limit: Int)] = []

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

    func searchSecrets(
        query: String,
        field: SecretCatalogField?,
        limit: Int
    ) async throws -> SecretCatalogSearchResult {
        searchCalls.append((query: query, field: field, limit: limit))
        return SecretCatalogSearchResult(
            status: .found,
            matches: [handlerCatalogMatch()]
        )
    }
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

@Test func handlerRoutesCatalogSearchAsOpaqueMetadataOnly() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)

    let response = try await handler.handle(.searchCatalog(query: "QNAP", field: .password, limit: 10))
    let expected = IPCResponse.catalogSearchResult(SecretCatalogSearchResult(
        status: .found,
        matches: [handlerCatalogMatch()]
    ))

    #expect(response == expected)
    let encoded = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    #expect(!encoded.contains("ASV_CANARY_CATALOG_PLAINTEXT"))
    #expect(!encoded.contains("/敏感信息.md"))
    #expect(!encoded.contains("line"))
}

@Test func handlerRoutesOpaqueSecretOperationAndNeverReturnsSecretMaterial() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)
    let reference = "secret://0123456789ABCDEFGHJKMNPQRS"
    let response = try await handler.handle(.executeSecretOperation(SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [try SecretReference(reference)],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        requestedEffects: ["read-only"],
        parameters: ["passwordRef": reference],
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "diagnostic",
            intendedEffect: "read status"
        )
    )))

    #expect(response == .failure(code: "ACTION_EXECUTION_FAILED"))
}
