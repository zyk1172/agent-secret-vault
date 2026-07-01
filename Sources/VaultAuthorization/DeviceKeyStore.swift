import Foundation
import Security

public protocol DeviceKeyStoring: Sendable {
    func deviceKey(reason: String) async throws -> Data
}

public protocol DeviceKeyMaterialStoring: Sendable {
    func loadOrCreateDeviceKeyData() async throws -> Data
}

protocol KeychainClient: Sendable {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?)
    func add(_ attributes: [String: Any]) -> OSStatus
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
    private let keychain: any KeychainClient
    private let randomKeyDataProvider: @Sendable () throws -> Data

    public init(
        service: String = "com.agent-secret-vault.device-key",
        account: String = "device-wrapping-key"
    ) {
        self.init(
            service: service,
            account: account,
            keychain: SystemKeychainClient(),
            randomKeyData: Self.randomKeyData
        )
    }

    init(
        service: String,
        account: String,
        keychain: any KeychainClient,
        randomKeyData: @escaping @Sendable () throws -> Data
    ) {
        self.service = service
        self.account = account
        self.keychain = keychain
        self.randomKeyDataProvider = randomKeyData
    }

    public func loadOrCreateDeviceKeyData() async throws -> Data {
        if let existing = try readKeyData() {
            return existing
        }

        let keyData = try randomKeyDataProvider()
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

        let result = keychain.copyMatching(query)

        switch result.status {
        case errSecSuccess:
            guard let data = result.data else {
                throw DeviceKeyStoreError.keychain(result.status)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw DeviceKeyStoreError.keychain(result.status)
        }
    }

    private func saveKeyData(_ keyData: Data) throws {
        var attributes = baseQuery
        attributes[kSecValueData as String] = keyData
        attributes[kSecAttrAccessControl as String] = try makeAccessControl()

        let status = keychain.add(attributes)
        if status == errSecSuccess {
            return
        }

        guard status == errSecMissingEntitlement else {
            throw DeviceKeyStoreError.keychain(status)
        }

        var fallbackAttributes = baseQuery
        fallbackAttributes[kSecValueData as String] = keyData
        fallbackAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let fallbackStatus = keychain.add(fallbackAttributes)
        guard fallbackStatus == errSecSuccess else {
            throw DeviceKeyStoreError.keychain(fallbackStatus)
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

private struct SystemKeychainClient: KeychainClient {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
