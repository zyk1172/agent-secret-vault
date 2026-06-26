import Foundation
import Security

public protocol RecoveryKeyStoring: Sendable {
    func supportsRequiredKeychainControls() async throws -> Bool
    func loadRecoveryKeyData() async throws -> Data?
    func loadOrCreateRecoveryKeyData() async throws -> Data
}

public enum RecoveryKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case accessControlCreationFailed
    case keychain(OSStatus)
}

public struct KeychainRecoveryKeyStore: RecoveryKeyStoring {
    public let service: String
    public let account: String

    public init(
        service: String = "com.agent-secret-vault.recovery-key",
        account: String = "icloud-recovery-wrapping-key"
    ) {
        self.service = service
        self.account = account
    }

    public func supportsRequiredKeychainControls() async throws -> Bool {
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlocked,
            [],
            &error
        )
        if accessControl == nil {
            error?.release()
            return false
        }
        return true
    }

    public func loadRecoveryKeyData() async throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw RecoveryKeyStoreError.keychain(status)
            }
            guard data.count == 32 else {
                throw RecoveryKeyStoreError.invalidKeySize(data.count)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw RecoveryKeyStoreError.keychain(status)
        }
    }

    public func loadOrCreateRecoveryKeyData() async throws -> Data {
        if let existing = try await loadRecoveryKeyData() {
            return existing
        }

        let keyData = try Self.randomKeyData()
        do {
            try saveKeyData(keyData)
            return keyData
        } catch RecoveryKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try await loadRecoveryKeyData() else {
                throw RecoveryKeyStoreError.keychain(errSecItemNotFound)
            }
            return existing
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanTrue as Any
        ]
    }

    private func saveKeyData(_ keyData: Data) throws {
        guard keyData.count == 32 else {
            throw RecoveryKeyStoreError.invalidKeySize(keyData.count)
        }

        var attributes = baseQuery
        attributes[kSecValueData as String] = keyData
        attributes[kSecAttrAccessControl as String] = try makeAccessControl()

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw RecoveryKeyStoreError.keychain(status)
        }
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlocked,
            [],
            &error
        ) else {
            error?.release()
            throw RecoveryKeyStoreError.accessControlCreationFailed
        }

        return accessControl
    }

    private static func randomKeyData() throws -> Data {
        var data = Data(count: 32)
        let status = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }

            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw RecoveryKeyStoreError.randomGenerationFailed(status)
        }
        return data
    }
}
