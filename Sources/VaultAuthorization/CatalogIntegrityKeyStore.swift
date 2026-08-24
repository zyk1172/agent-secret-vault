import Foundation
import Security
import VaultCore

public enum CatalogIntegrityKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case keychain(OSStatus)
}

public protocol CatalogIntegrityKeyStoring: Sendable {
    func loadOrCreateKey() throws -> Data
}

/// The catalog HMAC key is independent from the vault wrapping key.  It is
/// stored as a normal per-user Keychain item so the App and its launchd Agent
/// can verify the same managed document without exposing the key to MCP.
public struct KeychainCatalogIntegrityKeyStore: CatalogIntegrityKeyStoring {
    public let service: String
    public let account: String

    public init(
        service: String = "com.agent-secret-vault.catalog-integrity",
        account: String = "catalog-hmac-key"
    ) {
        self.service = service
        self.account = account
    }

    public func loadOrCreateKey() throws -> Data {
        var query = baseQuery
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let readStatus = SecItemCopyMatching(query as CFDictionary, &item)
        if readStatus == errSecSuccess {
            guard let data = item as? Data else {
                throw CatalogIntegrityKeyStoreError.keychain(readStatus)
            }
            guard data.count == 32 else {
                throw CatalogIntegrityKeyStoreError.invalidKeySize(data.count)
            }
            return data
        }
        guard readStatus == errSecItemNotFound else {
            throw CatalogIntegrityKeyStoreError.keychain(readStatus)
        }

        let key = try RandomBytes.generate(count: 32)
        var attributes = baseQuery
        attributes[kSecValueData as String] = key
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            return try loadOrCreateKey()
        }
        guard addStatus == errSecSuccess else {
            throw CatalogIntegrityKeyStoreError.keychain(addStatus)
        }
        return key
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }
}

public struct FixedCatalogIntegrityKeyStore: CatalogIntegrityKeyStoring {
    public let key: Data

    public init(key: Data) throws {
        guard key.count == 32 else {
            throw CatalogIntegrityKeyStoreError.invalidKeySize(key.count)
        }
        self.key = key
    }

    public func loadOrCreateKey() throws -> Data { key }
}
