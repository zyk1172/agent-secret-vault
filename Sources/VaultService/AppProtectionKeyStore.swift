import Foundation
import VaultAuthorization
import VaultCore

/// Keeps only in-memory wrapping keys. Read authorization is session-scoped;
/// credential and destination-bound external-send keys use configurable
/// windows. No key is written to disk or UserDefaults.
public actor AppProtectionKeyStore {
    private struct CachedKey: Sendable {
        var data: Data
        let expiresAt: Date
    }

    private let deviceKeyStore: any DeviceKeyStoring
    private let credentialTTL: TimeInterval
    private let externalSendTTL: TimeInterval
    private let now: @Sendable () -> Date
    private var lowProtectionKey: Data?
    private var credentialKey: CachedKey?
    private var externalSendKeys: [String: CachedKey] = [:]

    public init(
        deviceKeyStore: any DeviceKeyStoring,
        credentialTTL: TimeInterval = 600,
        externalSendTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.deviceKeyStore = deviceKeyStore
        self.credentialTTL = credentialTTL
        self.externalSendTTL = externalSendTTL
        self.now = now
    }

    public var isLowProtectionUnlocked: Bool {
        lowProtectionKey != nil
    }

    public var isUnlocked: Bool {
        let credentialActive = credentialKey.map { now() < $0.expiresAt } ?? false
        let externalActive = externalSendKeys.values.contains { now() < $0.expiresAt }
        return lowProtectionKey != nil || credentialActive || externalActive
    }

    /// Retained for explicit UI unlock actions. The daemon never calls this at
    /// startup; normal operation enters through `deviceKey(for:)` lazily.
    public func unlockLowProtection(reason: String = "打开知识库密文保险箱") async throws {
        let key = try await deviceKeyStore.deviceKey(reason: reason)
        lowProtectionKey = key
    }

    public func deviceKey(
        for policy: SecretPolicy,
        reason: String,
        destination: String? = nil
    ) async throws -> Data {
        switch policy {
        case .read:
            if let lowProtectionKey {
                return lowProtectionKey
            }
            let key = try await deviceKeyStore.deviceKey(reason: "打开知识库密文保险箱")
            lowProtectionKey = key
            return key
        case .credential:
            if let credentialKey, now() < credentialKey.expiresAt {
                return credentialKey.data
            }
            self.credentialKey = nil
            let key = try await deviceKeyStore.deviceKey(reason: reason)
            if credentialTTL > 0 {
                credentialKey = CachedKey(
                    data: key,
                    expiresAt: now().addingTimeInterval(credentialTTL)
                )
            }
            return key
        case .externalSend:
            guard let destination, !destination.isEmpty else {
                return try await deviceKeyStore.deviceKey(reason: reason)
            }
            if let cached = externalSendKeys[destination], now() < cached.expiresAt {
                return cached.data
            }
            externalSendKeys[destination] = nil
            let key = try await deviceKeyStore.deviceKey(reason: reason)
            if externalSendTTL > 0 {
                externalSendKeys[destination] = CachedKey(
                    data: key,
                    expiresAt: now().addingTimeInterval(externalSendTTL)
                )
            }
            return key
        }
    }

    /// High-risk operations bypass every cached window and do not repopulate
    /// it. This is used for deletion, export, and security-setting changes.
    public func freshDeviceKey(for policy: SecretPolicy, reason: String) async throws -> Data {
        clearCachedKey(for: policy)
        return try await deviceKeyStore.deviceKey(reason: reason)
    }

    public func clearLowProtectionUnlock() {
        clear(&lowProtectionKey)
    }

    public func clearAll() {
        clear(&lowProtectionKey)
        clearCachedKey(for: .credential)
        for key in externalSendKeys.values {
            var data = key.data
            data.resetBytes(in: 0..<data.count)
        }
        externalSendKeys.removeAll()
    }

    private func clearCachedKey(for policy: SecretPolicy) {
        switch policy {
        case .read:
            clear(&lowProtectionKey)
        case .credential:
            if var cached = credentialKey {
                cached.data.resetBytes(in: 0..<cached.data.count)
            }
            credentialKey = nil
        case .externalSend:
            for key in externalSendKeys.values {
                var data = key.data
                data.resetBytes(in: 0..<data.count)
            }
            externalSendKeys.removeAll()
        }
    }

    private func clear(_ data: inout Data?) {
        guard data != nil else {
            return
        }
        let count = data?.count ?? 0
        data?.resetBytes(in: 0..<count)
        data = nil
    }
}
