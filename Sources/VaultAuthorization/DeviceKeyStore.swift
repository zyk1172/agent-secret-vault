import Foundation
import Security

public protocol DeviceKeyStoring: Sendable {
    func deviceKey(reason: String) async throws -> Data
}

public protocol DeviceKeyMaterialStoring: Sendable {
    func loadOrCreateDeviceKeyData() async throws -> Data
}

public enum DeviceKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case accessControlCreationFailed
    case keychain(OSStatus)
}

public struct DeviceKeyStore: DeviceKeyStoring {
    private let authenticator: any BiometricAuthorizing
    private let materialStore: any DeviceKeyMaterialStoring

    public init(
        authenticator: any BiometricAuthorizing = LocalAuthenticator(),
        materialStore: any DeviceKeyMaterialStoring = KeychainDeviceKeyMaterialStore()
    ) {
        self.authenticator = authenticator
        self.materialStore = materialStore
    }

    public func deviceKey(reason: String) async throws -> Data {
        try await authenticator.evaluate(reason: reason)

        let key = try await materialStore.loadOrCreateDeviceKeyData()
        guard key.count == 32 else {
            throw DeviceKeyStoreError.invalidKeySize(key.count)
        }

        return key
    }
}

public struct KeychainDeviceKeyMaterialStore: DeviceKeyMaterialStoring {
    public let service: String
    public let account: String

    public init(
        service: String = "com.agent-secret-vault.device-key",
        account: String = "device-wrapping-key"
    ) {
        self.service = service
        self.account = account
    }

    public func loadOrCreateDeviceKeyData() async throws -> Data {
        if let existing = try readKeyData() {
            return existing
        }

        let keyData = try Self.randomKeyData()
        do {
            try saveKeyData(keyData)
            return keyData
        } catch DeviceKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try readKeyData() else {
                throw DeviceKeyStoreError.keychain(errSecItemNotFound)
            }
            return existing
        }
    }

    private func readKeyData() throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw DeviceKeyStoreError.keychain(status)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw DeviceKeyStoreError.keychain(status)
        }
    }

    private func saveKeyData(_ keyData: Data) throws {
        var attributes = baseQuery
        attributes[kSecValueData as String] = keyData
        attributes[kSecAttrAccessControl as String] = try makeAccessControl()

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceKeyStoreError.keychain(status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.userPresence],
            &error
        ) else {
            error?.release()
            throw DeviceKeyStoreError.accessControlCreationFailed
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
            throw DeviceKeyStoreError.randomGenerationFailed(status)
        }

        return data
    }
}
