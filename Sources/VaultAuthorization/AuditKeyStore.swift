import Foundation
import Security

public protocol AuditKeyStoring: Sendable {
    func loadOrCreateAuditKeyData() async throws -> Data
}

public enum AuditKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case keychain(OSStatus)
}

/// Audit encryption is intentionally separate from the vault wrapping key and
/// does not carry `.userPresence`. Writing a status/audit event must never
/// unlock the vault or create a new authentication prompt.
public struct KeychainAuditKeyStore: AuditKeyStoring {
    public let service: String
    public let account: String
    private let keychain: any KeychainClient
    private let randomKeyDataProvider: @Sendable () throws -> Data

    public init(
        service: String = "com.agent-secret-vault.audit-key",
        account: String = "audit-encryption-key"
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

    public func loadOrCreateAuditKeyData() async throws -> Data {
        for queryBase in [legacyBaseQuery, dataProtectionBaseQuery] {
            var query = queryBase
            query[kSecReturnData as String] = kCFBooleanTrue
            query[kSecMatchLimit as String] = kSecMatchLimitOne

            let result = keychain.copyMatching(query)
            switch result.status {
            case errSecSuccess:
                guard let data = result.data else {
                    throw AuditKeyStoreError.keychain(result.status)
                }
                try validate(data)
                return data
            case errSecItemNotFound, errSecMissingEntitlement, errSecParam, errSecNotAvailable:
                continue
            default:
                throw AuditKeyStoreError.keychain(result.status)
            }
        }

        let data = try randomKeyDataProvider()
        var attributes = legacyBaseQuery
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let addStatus = keychain.add(attributes)
        switch addStatus {
        case errSecSuccess:
            return data
        case errSecDuplicateItem:
            var retryQuery = legacyBaseQuery
            retryQuery[kSecReturnData as String] = kCFBooleanTrue
            retryQuery[kSecMatchLimit as String] = kSecMatchLimitOne
            let retry = keychain.copyMatching(retryQuery)
            guard retry.status == errSecSuccess, let existing = retry.data else {
                throw AuditKeyStoreError.keychain(retry.status)
            }
            try validate(existing)
            return existing
        default:
            throw AuditKeyStoreError.keychain(addStatus)
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

    private var legacyBaseQuery: [String: Any] {
        baseQuery
    }

    private var dataProtectionBaseQuery: [String: Any] {
        var query = baseQuery
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    private func validate(_ data: Data) throws {
        guard data.count == 32 else {
            throw AuditKeyStoreError.invalidKeySize(data.count)
        }
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
            throw AuditKeyStoreError.randomGenerationFailed(status)
        }
        return data
    }
}
