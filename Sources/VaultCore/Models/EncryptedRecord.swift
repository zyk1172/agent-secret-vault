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
    public let keyDerivationSalt: Data?
    public let label: String?
    public let policy: SecretPolicy
    public let allowedDestinations: [String]
    public let allowedProtocols: [String]
    public let allowedBindings: [SecretDestinationBinding]
    /// Zero means the record predates authenticated destination metadata.  A
    /// new record uses version 1 so changing a binding cannot silently broaden
    /// where a credential may be sent.
    public let policyBindingVersion: Int
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
        keyDerivationSalt: Data? = nil,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = [],
        allowedBindings: [SecretDestinationBinding] = [],
        policyBindingVersion: Int = 0,
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
        self.keyDerivationSalt = keyDerivationSalt
        self.label = label
        self.policy = policy
        self.allowedDestinations = allowedDestinations
        self.allowedProtocols = allowedProtocols
        self.allowedBindings = allowedBindings
        self.policyBindingVersion = policyBindingVersion
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case formatVersion
        case id
        case recordVersion
        case ciphertext
        case nonce
        case tag
        case wrappedDataKey
        case wrappedDataKeyNonce
        case wrappedDataKeyTag
        case keyDerivationSalt
        case label
        case policy
        case allowedDestinations
        case allowedProtocols
        case allowedBindings
        case policyBindingVersion
        case createdAt
        case updatedAt
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            formatVersion: try container.decode(Int.self, forKey: .formatVersion),
            id: try container.decode(String.self, forKey: .id),
            recordVersion: try container.decode(Int.self, forKey: .recordVersion),
            ciphertext: try container.decode(Data.self, forKey: .ciphertext),
            nonce: try container.decode(Data.self, forKey: .nonce),
            tag: try container.decode(Data.self, forKey: .tag),
            wrappedDataKey: try container.decode(Data.self, forKey: .wrappedDataKey),
            wrappedDataKeyNonce: try container.decode(Data.self, forKey: .wrappedDataKeyNonce),
            wrappedDataKeyTag: try container.decode(Data.self, forKey: .wrappedDataKeyTag),
            keyDerivationSalt: try container.decodeIfPresent(Data.self, forKey: .keyDerivationSalt),
            label: try container.decodeIfPresent(String.self, forKey: .label),
            policy: try container.decode(SecretPolicy.self, forKey: .policy),
            allowedDestinations: try container.decodeIfPresent([String].self, forKey: .allowedDestinations) ?? [],
            allowedProtocols: try container.decodeIfPresent([String].self, forKey: .allowedProtocols) ?? [],
            allowedBindings: try container.decodeIfPresent([SecretDestinationBinding].self, forKey: .allowedBindings) ?? [],
            policyBindingVersion: try container.decodeIfPresent(Int.self, forKey: .policyBindingVersion) ?? 0,
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(formatVersion, forKey: .formatVersion)
        try container.encode(id, forKey: .id)
        try container.encode(recordVersion, forKey: .recordVersion)
        try container.encode(ciphertext, forKey: .ciphertext)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(tag, forKey: .tag)
        try container.encode(wrappedDataKey, forKey: .wrappedDataKey)
        try container.encode(wrappedDataKeyNonce, forKey: .wrappedDataKeyNonce)
        try container.encode(wrappedDataKeyTag, forKey: .wrappedDataKeyTag)
        try container.encodeIfPresent(keyDerivationSalt, forKey: .keyDerivationSalt)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encode(policy, forKey: .policy)
        try container.encode(allowedDestinations, forKey: .allowedDestinations)
        try container.encode(allowedProtocols, forKey: .allowedProtocols)
        try container.encode(allowedBindings, forKey: .allowedBindings)
        try container.encode(policyBindingVersion, forKey: .policyBindingVersion)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
    }
}

public enum SecretPolicy: String, Codable, Sendable {
    case read
    case externalSend
    case credential
}
