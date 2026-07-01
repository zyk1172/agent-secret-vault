import Foundation
import VaultAuthorization
import VaultCore

public actor AppProtectionKeyStore {
    private let deviceKeyStore: any DeviceKeyStoring
    private var lowProtectionKey: Data?

    public init(deviceKeyStore: any DeviceKeyStoring) {
        self.deviceKeyStore = deviceKeyStore
    }

    public var isLowProtectionUnlocked: Bool {
        lowProtectionKey != nil
    }

    public func unlockLowProtection(reason: String = "打开知识库密文保险箱") async throws {
        lowProtectionKey = try await deviceKeyStore.deviceKey(reason: reason)
    }

    public func deviceKey(for policy: SecretPolicy, reason: String) async throws -> Data {
        switch policy {
        case .read:
            if let lowProtectionKey {
                return lowProtectionKey
            }
            let key = try await deviceKeyStore.deviceKey(reason: "打开知识库密文保险箱")
            lowProtectionKey = key
            return key
        case .externalSend, .credential:
            return try await deviceKeyStore.deviceKey(reason: reason)
        }
    }

    public func clearLowProtectionUnlock() {
        lowProtectionKey = nil
    }
}
