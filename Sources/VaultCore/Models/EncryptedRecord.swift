import Foundation

public struct EncryptedRecord: Codable, Sendable, Equatable {
    public let formatVersion: Int
    public let id: String
    public let recordVersion: Int
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let wrappedDataKey: Data
    public let wrappedDataKeyNonce: Data
    public let wrappedDataKeyTag: Data
    public let label: String?
    public let policy: SecretPolicy
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        formatVersion: Int,
        id: String,
        recordVersion: Int,
        ciphertext: Data,
        nonce: Data,
        tag: Data,
        wrappedDataKey: Data,
        wrappedDataKeyNonce: Data,
        wrappedDataKeyTag: Data,
        label: String?,
        policy: SecretPolicy,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.formatVersion = formatVersion
        self.id = id
        self.recordVersion = recordVersion
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
        self.wrappedDataKey = wrappedDataKey
        self.wrappedDataKeyNonce = wrappedDataKeyNonce
        self.wrappedDataKeyTag = wrappedDataKeyTag
        self.label = label
        self.policy = policy
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public enum SecretPolicy: String, Codable, Sendable {
    case read
    case externalSend
    case credential
}
