import Foundation

/// The versioned field types supported by the managed catalog.  A field's
/// type is a schema property; it is never inferred from the field label.
public enum SecretCatalogFieldType: String, Codable, CaseIterable, Sendable {
    case text
    case multiline
    case url
    case host
    case port
    case number
    case boolean
    case date
    case list
    case secret

    public var isSecret: Bool { self == .secret }
}

/// JSON-safe, non-secret field values.  There is deliberately no arbitrary
/// `Any` value here so a catalog block can be validated before it is written.
public enum SecretCatalogValue: Codable, Equatable, Sendable {
    case string(String)
    case number(Double)
    case boolean(Bool)
    case list([String])

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode(Bool.self) {
            self = .boolean(value)
        } else if let value = try? container.decode([String].self) {
            self = .list(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else {
            throw SecretCatalogValidationError.invalidFieldValue
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            guard value.isFinite else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
            try container.encode(value)
        case .boolean(let value):
            try container.encode(value)
        case .list(let value):
            try container.encode(value)
        }
    }
}

public struct CatalogEndpoint: Codable, Equatable, Sendable {
    public let type: String
    public let host: String
    public let port: Int?

    public init(type: String = "https", host: String, port: Int? = nil) {
        self.type = type
        self.host = host
        self.port = port
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case host
        case port
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try StrictCatalogCoding.rejectUnknownKeys(decoder, allowed: CodingKeys.allCases)
        type = try container.decode(String.self, forKey: .type)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decodeIfPresent(Int.self, forKey: .port)
    }
}

/// A field in a v3 entry. Ordinary metadata lives in `value`; a secret is
/// represented only by an opaque `secret://` reference.  A secret field with
/// neither value nor reference is a valid placeholder for a later App entry.
public struct SecretCatalogFieldValue: Codable, Equatable, Sendable {
    public let key: String
    public let label: String
    public let type: SecretCatalogFieldType
    public let agentVisible: Bool
    public let searchable: Bool
    public let value: SecretCatalogValue?
    public let secretRef: String?

    public init(
        key: String,
        label: String,
        type: SecretCatalogFieldType,
        agentVisible: Bool = true,
        searchable: Bool = true,
        value: SecretCatalogValue? = nil,
        secretRef: String? = nil
    ) {
        self.key = key
        self.label = label
        self.type = type
        self.agentVisible = agentVisible
        self.searchable = searchable
        self.value = value
        self.secretRef = secretRef
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case key
        case label
        case type
        case agentVisible
        case searchable
        case value
        case secretRef
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try StrictCatalogCoding.rejectUnknownKeys(decoder, allowed: CodingKeys.allCases)
        key = try container.decode(String.self, forKey: .key)
        label = try container.decode(String.self, forKey: .label)
        type = try container.decode(SecretCatalogFieldType.self, forKey: .type)
        agentVisible = try container.decode(Bool.self, forKey: .agentVisible)
        searchable = try container.decode(Bool.self, forKey: .searchable)
        value = try container.decodeIfPresent(SecretCatalogValue.self, forKey: .value)
        secretRef = try container.decodeIfPresent(String.self, forKey: .secretRef)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(key, forKey: .key)
        try container.encode(label, forKey: .label)
        try container.encode(type, forKey: .type)
        try container.encode(agentVisible, forKey: .agentVisible)
        try container.encode(searchable, forKey: .searchable)
        try container.encodeIfPresent(value, forKey: .value)
        try container.encodeIfPresent(secretRef, forKey: .secretRef)
    }
}

public struct SecretCatalogIndex: Codable, Equatable, Sendable {
    public static let schemaName = "svlt.catalog.index/v3"
    public static let legacySchemaName = "svlt.catalog.index/v2"

    public let schema: String
    public let id: String
    public let title: String
    public let aliases: [String]
    public let tags: [String]

    public init(
        id: String,
        title: String,
        aliases: [String] = [],
        tags: [String] = [],
        schema: String = SecretCatalogIndex.schemaName
    ) {
        self.schema = schema
        self.id = id
        self.title = title
        self.aliases = aliases
        self.tags = tags
    }

    public static func generated(
        title: String,
        aliases: [String] = [],
        tags: [String] = []
    ) throws -> Self {
        Self(
            id: try SecretCatalogOpaqueID.generate(),
            title: title,
            aliases: aliases,
            tags: tags
        )
    }

    /// A title edit intentionally constructs a new value with the same ID.
    public func renaming(to title: String) -> Self {
        Self(id: id, title: title, aliases: aliases, tags: tags, schema: schema)
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case id
        case title
        case aliases
        case tags
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try StrictCatalogCoding.rejectUnknownKeys(decoder, allowed: CodingKeys.allCases)
        schema = try container.decode(String.self, forKey: .schema)
        id = try container.decode(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        aliases = try container.decode([String].self, forKey: .aliases)
        tags = try container.decode([String].self, forKey: .tags)
    }
}

public struct SecretCatalogEntry: Codable, Equatable, Sendable {
    public static let schemaName = "svlt.catalog.entry/v3"
    public static let legacySchemaName = "svlt.catalog.entry/v2"

    public let schema: String
    public let id: String
    public let indexId: String
    public let title: String
    public let type: String
    public let aliases: [String]
    public let endpoints: [CatalogEndpoint]
    public let fields: [SecretCatalogFieldValue]
    public let notes: String?
    public let tags: [String]

    public init(
        id: String,
        indexId: String,
        title: String,
        type: String = "credential",
        aliases: [String] = [],
        endpoints: [CatalogEndpoint] = [],
        fields: [SecretCatalogFieldValue] = [],
        notes: String? = nil,
        tags: [String] = [],
        schema: String = SecretCatalogEntry.schemaName
    ) {
        self.schema = schema
        self.id = id
        self.indexId = indexId
        self.title = title
        self.type = type
        self.aliases = aliases
        self.endpoints = endpoints
        self.fields = fields
        self.notes = notes
        self.tags = tags
    }

    public static func generated(
        indexId: String,
        title: String,
        type: String = "credential",
        aliases: [String] = [],
        endpoints: [CatalogEndpoint] = [],
        fields: [SecretCatalogFieldValue] = [],
        notes: String? = nil,
        tags: [String] = []
    ) throws -> Self {
        Self(
            id: try SecretCatalogOpaqueID.generate(),
            indexId: indexId,
            title: title,
            type: type,
            aliases: aliases,
            endpoints: endpoints,
            fields: fields,
            notes: notes,
            tags: tags
        )
    }

    public func renaming(to title: String) -> Self {
        Self(
            id: id,
            indexId: indexId,
            title: title,
            type: type,
            aliases: aliases,
            endpoints: endpoints,
            fields: fields,
            notes: notes,
            tags: tags,
            schema: schema
        )
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case id
        case indexId
        case title
        case type
        case aliases
        case endpoints
        case fields
        case notes
        case tags
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try StrictCatalogCoding.rejectUnknownKeys(decoder, allowed: CodingKeys.allCases)
        schema = try container.decode(String.self, forKey: .schema)
        id = try container.decode(String.self, forKey: .id)
        indexId = try container.decode(String.self, forKey: .indexId)
        title = try container.decode(String.self, forKey: .title)
        type = try container.decode(String.self, forKey: .type)
        aliases = try container.decode([String].self, forKey: .aliases)
        endpoints = try container.decode([CatalogEndpoint].self, forKey: .endpoints)
        fields = try container.decode([SecretCatalogFieldValue].self, forKey: .fields)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        tags = try container.decode([String].self, forKey: .tags)
    }
}

public struct SecretCatalogDocument: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 3
    public static let legacyV2SchemaVersion = 2

    public let schemaVersion: Int
    public let indexes: [SecretCatalogIndex]
    public let entries: [SecretCatalogEntry]

    public init(
        schemaVersion: Int = SecretCatalogDocument.currentSchemaVersion,
        indexes: [SecretCatalogIndex] = [],
        entries: [SecretCatalogEntry] = []
    ) {
        self.schemaVersion = schemaVersion
        self.indexes = indexes
        self.entries = entries
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion
        case indexes
        case entries
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try StrictCatalogCoding.rejectUnknownKeys(decoder, allowed: CodingKeys.allCases)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        indexes = try container.decode([SecretCatalogIndex].self, forKey: .indexes)
        entries = try container.decode([SecretCatalogEntry].self, forKey: .entries)
    }

    public func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw SecretCatalogValidationError.unsupportedSchemaVersion
        }

        guard indexes.allSatisfy({ $0.schema == SecretCatalogIndex.schemaName }) else {
            throw SecretCatalogValidationError.unknownSchema
        }
        guard entries.allSatisfy({ $0.schema == SecretCatalogEntry.schemaName }) else {
            throw SecretCatalogValidationError.unknownSchema
        }

        var indexIDs = Set<String>()
        for index in indexes {
            try SecretCatalogOpaqueID.validate(index.id)
            guard indexIDs.insert(index.id).inserted else {
                throw SecretCatalogValidationError.duplicateIndexID
            }
            try CatalogValidation.validateVisibleText(index.title)
            try index.aliases.forEach(CatalogValidation.validateVisibleText)
            try index.tags.forEach(CatalogValidation.validateVisibleText)
        }

        var entryIDs = Set<String>()
        for entry in entries {
            try SecretCatalogOpaqueID.validate(entry.id)
            guard entryIDs.insert(entry.id).inserted else {
                throw SecretCatalogValidationError.duplicateEntryID
            }
            guard indexIDs.contains(entry.indexId) else {
                throw SecretCatalogValidationError.entryReferencesMissingIndex
            }
            try CatalogValidation.validateVisibleText(entry.title)
            try CatalogValidation.validateVisibleText(entry.type)
            try entry.aliases.forEach(CatalogValidation.validateVisibleText)
            try entry.tags.forEach(CatalogValidation.validateVisibleText)
            if let notes = entry.notes {
                try CatalogValidation.validateMarkdownText(notes)
            }

            var fieldKeys = Set<String>()
            for field in entry.fields {
                guard fieldKeys.insert(field.key).inserted else {
                    throw SecretCatalogValidationError.duplicateFieldKey
                }
                try CatalogValidation.validateField(field)
            }
            for endpoint in entry.endpoints {
                try CatalogValidation.validateEndpoint(endpoint)
            }
        }
    }
}

public enum SecretCatalogValidationError: Error, Equatable, Sendable {
    case invalidMarker
    case legacyDocument
    case malformedJSON
    case unknownSchema
    case unsupportedSchemaVersion
    case invalidID
    case duplicateIndexID
    case duplicateEntryID
    case entryReferencesMissingIndex
    case invalidVisibleText
    case invalidFieldValue
    case duplicateFieldKey
    case valueAndSecretReference
    case secretFieldContainsValue
    case nonSecretFieldContainsSecretReference
    case invalidSecretReference
    case secretFieldKeyMustBeSecret
    case invalidEndpoint
    case invalidHeading
    case missingIndexBlock
    case missingEntryBlock
    case headingDoesNotMatchBlock
    case unmanagedContent
    case referenceSetChanged
    case pendingExternalChange
}

public enum SecretCatalogOpaqueID {
    public static let length = 26
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let allowedCharacters = Set(alphabet)

    public static func generate() throws -> String {
        let bytes = try RandomBytes.generate(count: length)
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }

    public static func validate(_ id: String) throws {
        guard id.count == length,
              id.allSatisfy({ allowedCharacters.contains($0) })
        else {
            throw SecretCatalogValidationError.invalidID
        }
    }
}

private enum CatalogValidation {
    static func validateVisibleText(_ value: String) throws {
        guard !value.isEmpty,
              value.count <= 2_000,
              !value.contains("\0"),
              !value.contains("\n"),
              !value.contains("\r")
        else {
            throw SecretCatalogValidationError.invalidVisibleText
        }
    }

    static func validateMarkdownText(_ value: String) throws {
        guard !value.isEmpty,
              value.count <= 20_000,
              !value.contains("\0"),
              !value.contains("\r")
        else {
            throw SecretCatalogValidationError.invalidVisibleText
        }
    }

    static func validateField(_ field: SecretCatalogFieldValue) throws {
        try validateVisibleText(field.key)
        try validateVisibleText(field.label)

        if field.value != nil, field.secretRef != nil {
            throw SecretCatalogValidationError.valueAndSecretReference
        }

        if let secretRef = field.secretRef {
            guard (try? SecretReference(secretRef)) != nil else {
                throw SecretCatalogValidationError.invalidSecretReference
            }
            guard field.type.isSecret else {
                throw SecretCatalogValidationError.nonSecretFieldContainsSecretReference
            }
        }

        if field.type.isSecret {
            guard field.value == nil else {
                throw SecretCatalogValidationError.secretFieldContainsValue
            }
            return
        }

        let normalizedKey = normalize(field.key)
        if ["password", "pass", "pwd", "token", "apikey", "secret", "cookie", "privatekey", "私钥", "密码", "令牌", "密钥"].contains(normalizedKey) {
            throw SecretCatalogValidationError.secretFieldKeyMustBeSecret
        }

        guard let value = field.value else { return }
        switch field.type {
        case .text, .multiline, .url, .host, .date:
            guard case .string(let string) = value,
                  string.count <= 20_000,
                  !string.contains("\0"),
                  !string.contains("\r")
            else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
        case .port:
            guard case .number(let number) = value,
                  number.isFinite,
                  number.rounded() == number,
                  (0...65_535).contains(number)
            else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
        case .number:
            guard case .number(let number) = value, number.isFinite else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
        case .boolean:
            guard case .boolean = value else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
        case .list:
            guard case .list = value else {
                throw SecretCatalogValidationError.invalidFieldValue
            }
        case .secret:
            break
        }
    }

    static func validateEndpoint(_ endpoint: CatalogEndpoint) throws {
        try validateVisibleText(endpoint.type)
        try validateVisibleText(endpoint.host)
        if let port = endpoint.port, !(0...65_535).contains(port) {
            throw SecretCatalogValidationError.invalidEndpoint
        }
    }

    private static func normalize(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "-", with: "")
    }
}

private enum StrictCatalogCoding {
    private struct AnyCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int?

        init?(stringValue: String) {
            self.stringValue = stringValue
            self.intValue = nil
        }

        init?(intValue: Int) {
            self.stringValue = String(intValue)
            self.intValue = intValue
        }
    }

    static func rejectUnknownKeys<Key: CodingKey>(
        _ decoder: any Decoder,
        allowed: [Key]
    ) throws {
        let allowedNames = Set(allowed.map(\.stringValue))
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard container.allKeys.allSatisfy({ allowedNames.contains($0.stringValue) }) else {
            throw SecretCatalogValidationError.unknownSchema
        }
    }
}
