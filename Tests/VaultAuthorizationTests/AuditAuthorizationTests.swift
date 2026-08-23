import CryptoKit
import Foundation
import Testing
import VaultCore
import VaultIPC
@testable import VaultService

@Test func statusAuditUsesIndependentKeyAndNeverRequestsVaultMasterKey() async throws {
    let auditDirectory = FileManager.default.temporaryDirectory
        .appending(path: "svlt-audit-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: auditDirectory)
    }

    let masterCalls = AuditCallCounter()
    let auditCalls = AuditCallCounter()
    let auditKey = SymmetricKey(data: Data(repeating: 0xA7, count: 32))
    let auditLog = EncryptedAuditLog(
        directoryURL: auditDirectory,
        auditKeyProvider: {
            await auditCalls.increment()
            return auditKey
        }
    )
    let service = VaultAppServices(
        textEncryptor: AuditTestTextEncryptor(),
        activeRoot: nil,
        masterKeyProvider: { _, _ in
            await masterCalls.increment()
            return SymmetricKey(data: Data(repeating: 0xB8, count: 32))
        },
        auditLog: auditLog
    )

    await service.recordPluginActivity()
    _ = await service.status()

    #expect(await masterCalls.count == 0)
    #expect(await auditCalls.count == 0)

    try await auditLog.append(AuditEvent(
        timestamp: Date(),
        integration: "test",
        referenceID: nil,
        operation: .status,
        risk: 0,
        authorizationOutcome: .notRequired,
        declaredTarget: "status",
        status: .completed,
        exitCode: nil
    ))
    #expect(await masterCalls.count == 0)
    #expect(await auditCalls.count == 1)
    #expect((try await auditLog.export()).count == 1)
}

private struct AuditTestTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private actor AuditCallCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}
