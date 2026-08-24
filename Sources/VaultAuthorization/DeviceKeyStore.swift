import Foundation
import LocalAuthentication
import Security

public protocol DeviceKeyStoring: Sendable {
    func deviceKey(reason: String) async throws -> Data

    /// Returns compatible key material candidates after one authentication.
    /// The first candidate is canonical; additional candidates are only for
    /// migration from an older Keychain namespace.
    func deviceKeyCandidates(reason: String) async throws -> [Data]
}

public extension DeviceKeyStoring {
    func deviceKeyCandidates(reason: String) async throws -> [Data] {
        [try await deviceKey(reason: reason)]
    }
}

public protocol DeviceKeyMaterialStoring: Sendable {
    func loadOrCreateDeviceKeyData() async throws -> Data

    /// The default keeps lightweight test stores source-compatible. The
    /// production Keychain store overrides it to use the already evaluated
    /// LAContext for every Security query in this operation.
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data

    func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data]
}

public extension DeviceKeyMaterialStoring {
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data {
        try await loadOrCreateDeviceKeyData()
    }

    func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        [try await loadOrCreateDeviceKeyData(authenticationContext: authenticationContext)]
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
    case authenticationRequired
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
        guard let key = try await deviceKeyCandidates(reason: reason).first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        return key
    }

    public func deviceKeyCandidates(reason: String) async throws -> [Data] {
        let keys: [Data]
        do {
            keys = try await materialStore.loadDeviceKeyDataCandidates(
                authenticationContext: nil
            )
        } catch DeviceKeyStoreError.authenticationRequired {
            // The normal wrapping key is WhenUnlockedThisDeviceOnly and does
            // not need a prompt.  A one-time prompt is retained only for a
            // legacy userPresence item that still protects an existing vault;
            // it is never part of the normal low-risk path.
            if let contextAuthorizer = authenticator as? any KeychainContextAuthorizing {
                let context = try await contextAuthorizer.makeAuthenticationContext(reason: reason)
                keys = try await materialStore.loadDeviceKeyDataCandidates(
                    authenticationContext: context
                )
            } else {
                try await authenticator.evaluate(reason: reason)
                keys = try await materialStore.loadDeviceKeyDataCandidates(
                    authenticationContext: nil
                )
            }
        }

        guard !keys.isEmpty else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        for key in keys where key.count != 32 {
            throw DeviceKeyStoreError.invalidKeySize(key.count)
        }
        return keys
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
        guard let key = try await loadDeviceKeyDataCandidates(
            authenticationContext: authenticationContext
        ).first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        return key
    }

    public func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        var candidates: [Data] = []

        if let legacy = try readKeyData(
            from: legacyBaseQuery,
            authenticationContext: authenticationContext,
            tolerateUnsupportedControls: false
        ) {
            candidates.append(legacy)
        }

        // A development build used the Data Protection Keychain without a
        // shared access group. Read it only as a migration candidate; all new
        // items are written to the normal user Keychain namespace shared by
        // the App and the launchd Agent.
        if let dataProtection = try readKeyData(
            from: dataProtectionBaseQuery,
            authenticationContext: authenticationContext,
            tolerateUnsupportedControls: true
        ), !candidates.contains(dataProtection) {
            candidates.append(dataProtection)
        }

        guard candidates.isEmpty else {
            return candidates
        }

        let keyData = try randomKeyDataProvider()
        do {
            try saveKeyData(keyData, authenticationContext: authenticationContext)
            return [keyData]
        } catch DeviceKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try readKeyData(
                from: legacyBaseQuery,
                authenticationContext: authenticationContext,
                tolerateUnsupportedControls: false
            ) else {
                throw DeviceKeyStoreError.keychain(errSecItemNotFound)
            }
            return [existing]
        }
    }

    private func readKeyData(
        from baseQuery: [String: Any],
        authenticationContext: LocalAuthenticationContext?,
        tolerateUnsupportedControls: Bool
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
            // Existing releases could have created a legacy
            // kSecAttrAccessible-only item. It remains the key that protects
            // existing records, so accept it after LocalAuthentication has
            // already succeeded instead of silently generating a new key.
            _ = keychain.copyAttributes(attributesQuery)
            return data
        case errSecItemNotFound:
            return nil
        case errSecMissingEntitlement, errSecParam, errSecNotAvailable, errSecInteractionNotAllowed:
            if result.status == errSecInteractionNotAllowed, !tolerateUnsupportedControls {
                throw DeviceKeyStoreError.authenticationRequired
            }
            if tolerateUnsupportedControls {
                return nil
            }
            throw DeviceKeyStoreError.unsupportedRequiredKeychainControls
        default:
            throw DeviceKeyStoreError.keychain(result.status)
        }
    }

    private func saveKeyData(
        _ keyData: Data,
        authenticationContext _: LocalAuthenticationContext?
    ) throws {
        var attributes = legacyBaseQuery
        attributes[kSecValueData as String] = keyData
        // Silent operations rely on the logged-in user's unlocked Keychain,
        // not on userPresence for every master-key lookup.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            throw DeviceKeyStoreError.keychain(status)
        }
    }

    private var legacyBaseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }

    private var dataProtectionBaseQuery: [String: Any] {
        var query = legacyBaseQuery
        query[kSecUseDataProtectionKeychain as String] = true
        return query
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
