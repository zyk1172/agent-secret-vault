import Foundation
import LocalAuthentication
import Security

public protocol DeviceKeyStoring: Sendable {
    func deviceKey(reason: String) async throws -> Data
}

public protocol DeviceKeyMaterialStoring: Sendable {
    func loadOrCreateDeviceKeyData() async throws -> Data

    /// The default keeps lightweight test stores source-compatible. The
    /// production Keychain store overrides it to use the already evaluated
    /// LAContext for every Security query in this operation.
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data
}

public extension DeviceKeyMaterialStoring {
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data {
        try await loadOrCreateDeviceKeyData()
    }
}

protocol KeychainClient: Sendable {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?)
    func copyAttributes(_ query: [String: Any]) -> (status: OSStatus, attributes: [String: Any]?)
    func add(_ attributes: [String: Any]) -> OSStatus
}

public enum DeviceKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case accessControlCreationFailed
    case unsupportedRequiredKeychainControls
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
        let key: Data
        if let contextAuthorizer = authenticator as? any KeychainContextAuthorizing {
            let context = try await contextAuthorizer.makeAuthenticationContext(reason: reason)
            key = try await materialStore.loadOrCreateDeviceKeyData(
                authenticationContext: context
            )
        } else {
            // Non-Keychain test/dedicated stores retain the old protocol path.
            // The production LocalAuthenticator always takes the shared-context
            // branch above.
            try await authenticator.evaluate(reason: reason)
            key = try await materialStore.loadOrCreateDeviceKeyData()
        }

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
        try await loadOrCreateDeviceKeyData(authenticationContext: nil)
    }

    public func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data {
        if let existing = try readKeyData(authenticationContext: authenticationContext) {
            return existing
        }

        let keyData = try randomKeyDataProvider()
        do {
            try saveKeyData(keyData, authenticationContext: authenticationContext)
            return keyData
        } catch DeviceKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try readKeyData(authenticationContext: authenticationContext) else {
                throw DeviceKeyStoreError.keychain(errSecItemNotFound)
            }
            return existing
        }
    }

    private func readKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext.rawContext
        }

        let result = keychain.copyMatching(query)

        switch result.status {
        case errSecSuccess:
            guard let data = result.data else {
                throw DeviceKeyStoreError.keychain(result.status)
            }
            var attributesQuery = baseQuery
            attributesQuery[kSecReturnAttributes as String] = kCFBooleanTrue
            attributesQuery[kSecMatchLimit as String] = kSecMatchLimitOne
            if let authenticationContext {
                attributesQuery[kSecUseAuthenticationContext as String] = authenticationContext.rawContext
            }
            let attributesResult = keychain.copyAttributes(attributesQuery)
            guard attributesResult.status == errSecSuccess,
                  attributesResult.attributes?[kSecAttrAccessControl as String] != nil,
                  requiresUserPresenceProtection()
            else {
                // Existing development builds could have created a weaker
                // accessible-only item. Never silently accept that item in a
                // release path; require migration/recovery instead.
                throw DeviceKeyStoreError.unsupportedRequiredKeychainControls
            }
            return data
        case errSecItemNotFound:
            return nil
        case errSecMissingEntitlement, errSecParam, errSecNotAvailable:
            throw DeviceKeyStoreError.unsupportedRequiredKeychainControls
        default:
            throw DeviceKeyStoreError.keychain(result.status)
        }
    }

    private func requiresUserPresenceProtection() -> Bool {
        let probeContext = LAContext()
        probeContext.interactionNotAllowed = true
        var probe = baseQuery
        probe[kSecMatchLimit as String] = kSecMatchLimitOne
        probe[kSecUseAuthenticationContext as String] = probeContext
        let result = keychain.copyMatching(probe)
        return result.status == errSecInteractionNotAllowed
    }

    private func saveKeyData(
        _ keyData: Data,
        authenticationContext _: LocalAuthenticationContext?
    ) throws {
        var attributes = baseQuery
        attributes[kSecValueData as String] = keyData
        attributes[kSecAttrAccessControl as String] = try makeAccessControl()
        // SecItemAdd creates the protected item; the evaluated context is
        // intentionally supplied to the subsequent/read query path where
        // Security may otherwise create a second authentication context.
        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            if status == errSecMissingEntitlement || status == errSecParam || status == errSecNotAvailable {
                throw DeviceKeyStoreError.unsupportedRequiredKeychainControls
            }
            throw DeviceKeyStoreError.keychain(status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain as String: true
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

struct SystemKeychainClient: KeychainClient {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }

    func copyAttributes(_ query: [String: Any]) -> (status: OSStatus, attributes: [String: Any]?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? [String: Any])
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
