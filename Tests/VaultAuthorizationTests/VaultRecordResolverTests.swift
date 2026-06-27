import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import AgentSecretVaultApp

@Test func resolverDecryptsInternallyByReference() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_RESOLVER".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await store.save(record)

    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let plaintext = try await resolver.resolve(
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        masterKey: key
    )
    #expect(String(decoding: plaintext, as: UTF8.self) == "ASV_CANARY_RESOLVER")
}
