import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import AgentSecretVaultApp

@Test func lowProtectionKeyIsUnlockedOnceAndReused() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x41, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    let first = try await protectionKeyStore.deviceKey(for: .read, reason: "Restore low protection")
    let second = try await protectionKeyStore.deviceKey(for: .read, reason: "Encrypt low protection")

    #expect(first == Data(repeating: 0x41, count: 32))
    #expect(second == Data(repeating: 0x41, count: 32))
    #expect(await deviceKeyStore.reasons == ["打开知识库密文保险箱"])
    #expect(await protectionKeyStore.isLowProtectionUnlocked)
}

@Test func clearingLowProtectionUnlockRelocksReadAccess() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x43, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    #expect(await protectionKeyStore.isLowProtectionUnlocked)
    await protectionKeyStore.clearLowProtectionUnlock()
    #expect(!(await protectionKeyStore.isLowProtectionUnlocked))

    _ = try await protectionKeyStore.deviceKey(for: .read, reason: "Unlock read after clearing")
    #expect(await deviceKeyStore.reasons == [
        "打开知识库密文保险箱",
        "打开知识库密文保险箱"
    ])
}

@Test func highProtectionStillRequestsFreshDeviceAuthorization() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x42, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    _ = try await protectionKeyStore.deviceKey(for: .credential, reason: "Reveal credential")
    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "Send externally")

    #expect(await deviceKeyStore.reasons == [
        "打开知识库密文保险箱",
        "Reveal credential",
        "Send externally"
    ])
}

private actor CountingDeviceKeyStore: DeviceKeyStoring {
    private let keyData: Data
    private(set) var reasons: [String] = []

    init(keyData: Data) {
        self.keyData = keyData
    }

    func deviceKey(reason: String) async throws -> Data {
        reasons.append(reason)
        return keyData
    }
}
