import Foundation

/// Strongly typed payloads for purpose-built secret operations. The legacy
/// descriptor fields remain available for compatibility decoding, but new
/// callers should put protocol-specific data here instead of extending the
/// unbounded parameters dictionary.
public enum SecretOperationPayload: Codable, Equatable, Sendable {
    case http(HTTPOperation)
    case database(DatabaseOperation)
    case fileTransfer(FileTransferOperation)
    case browser(BrowserLoginOperation)
    case localApp(LocalAppFillOperation)
    case export(ExportOperation)
    case trustedProcess(TrustedProcessOperation)

    private enum CodingKeys: String, CodingKey {
        case type
        case operation
    }

    private enum PayloadType: String, Codable {
        case http
        case database
        case fileTransfer
        case browser
        case localApp
        case export
        case trustedProcess
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(PayloadType.self, forKey: .type) {
        case .http:
            self = .http(try container.decode(HTTPOperation.self, forKey: .operation))
        case .database:
            self = .database(try container.decode(DatabaseOperation.self, forKey: .operation))
        case .fileTransfer:
            self = .fileTransfer(try container.decode(FileTransferOperation.self, forKey: .operation))
        case .browser:
            self = .browser(try container.decode(BrowserLoginOperation.self, forKey: .operation))
        case .localApp:
            self = .localApp(try container.decode(LocalAppFillOperation.self, forKey: .operation))
        case .export:
            self = .export(try container.decode(ExportOperation.self, forKey: .operation))
        case .trustedProcess:
            self = .trustedProcess(try container.decode(TrustedProcessOperation.self, forKey: .operation))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .http(operation):
            try container.encode(PayloadType.http, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .database(operation):
            try container.encode(PayloadType.database, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .fileTransfer(operation):
            try container.encode(PayloadType.fileTransfer, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .browser(operation):
            try container.encode(PayloadType.browser, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .localApp(operation):
            try container.encode(PayloadType.localApp, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .export(operation):
            try container.encode(PayloadType.export, forKey: .type)
            try container.encode(operation, forKey: .operation)
        case let .trustedProcess(operation):
            try container.encode(PayloadType.trustedProcess, forKey: .type)
            try container.encode(operation, forKey: .operation)
        }
    }

    public var referencedSecretReferences: [SecretReference] {
        switch self {
        case let .http(operation):
            return operation.auth.referencedSecretReferences
        case let .database(operation):
            return [operation.usernameReference, operation.passwordReference]
                .compactMap { $0 } + operation.parameters.compactMap(\.secretReference)
        case let .fileTransfer(operation):
            return [operation.usernameReference, operation.passwordReference].compactMap { $0 }
        case let .browser(operation):
            return [operation.usernameReference, operation.passwordReference].compactMap { $0 }
        case let .localApp(operation):
            return operation.fields.compactMap(\.valueReference)
        case let .export(operation):
            return operation.secretReferences
        case let .trustedProcess(operation):
            return operation.secretReferences
        }
    }
}

public enum HTTPMethod: String, Codable, CaseIterable, Sendable {
    case get = "GET"
    case head = "HEAD"
    case post = "POST"
    case put = "PUT"
    case patch = "PATCH"
    case delete = "DELETE"
}

/// Header authentication is typed so adapters can validate each mechanism
/// separately. Secret values are represented only by SecretReference.
public struct HTTPAuthStrategy: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case none
        case basic
        case bearer
        case apiKeyHeader
        case cookie
        case customHeader
        case oauth2ClientCredentials
        case oauth2RefreshToken
        case clientCertificate
        case hmacSigning
    }

    public let kind: Kind
    public let username: String?
    public let usernameReference: SecretReference?
    public let passwordReference: SecretReference?
    public let valueReference: SecretReference?
    public let headerName: String?
    public let scheme: String?
    public let cookieName: String?

    public init(
        kind: Kind,
        username: String? = nil,
        usernameReference: SecretReference? = nil,
        passwordReference: SecretReference? = nil,
        valueReference: SecretReference? = nil,
        headerName: String? = nil,
        scheme: String? = nil,
        cookieName: String? = nil
    ) {
        self.kind = kind
        self.username = username
        self.usernameReference = usernameReference
        self.passwordReference = passwordReference
        self.valueReference = valueReference
        self.headerName = headerName
        self.scheme = scheme
        self.cookieName = cookieName
    }

    public static let none = HTTPAuthStrategy(kind: .none)

    public var referencedSecretReferences: [SecretReference] {
        [usernameReference, passwordReference, valueReference].compactMap { $0 }
    }

    public var auditProfile: String {
        switch kind {
        case .none: return "none"
        case .basic: return "basic"
        case .bearer: return "bearer"
        case .apiKeyHeader: return "api-key-header"
        case .cookie: return "cookie"
        case .customHeader: return "custom-header"
        case .oauth2ClientCredentials: return "oauth2-client-credentials"
        case .oauth2RefreshToken: return "oauth2-refresh-token"
        case .clientCertificate: return "client-certificate"
        case .hmacSigning: return "hmac-signing"
        }
    }
}

public struct HTTPBody: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case none
        case raw
        case json
        case form
    }

    public let kind: Kind
    public let content: String?
    public let fields: [String: String]

    public init(
        kind: Kind,
        content: String? = nil,
        fields: [String: String] = [:]
    ) {
        self.kind = kind
        self.content = content
        self.fields = fields
    }

    public static let none = HTTPBody(kind: .none)
    public static func raw(_ content: String) -> HTTPBody {
        HTTPBody(kind: .raw, content: content)
    }
    public static func json(_ content: String) -> HTTPBody {
        HTTPBody(kind: .json, content: content)
    }
    public static func form(_ fields: [String: String]) -> HTTPBody {
        HTTPBody(kind: .form, fields: fields)
    }
}

public struct HTTPResponsePolicy: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case metadataOnly
        case sanitizedPreview
        case structuredFields
        case captureCredential
    }

    public enum CredentialSource: String, Codable, CaseIterable, Sendable {
        case json
        case header
    }

    public let kind: Kind
    public let maxBytes: Int
    public let fields: [String]
    public let source: CredentialSource?
    public let selector: String?

    public init(
        kind: Kind,
        maxBytes: Int = 16_384,
        fields: [String] = [],
        source: CredentialSource? = nil,
        selector: String? = nil
    ) {
        self.kind = kind
        self.maxBytes = maxBytes
        self.fields = fields
        self.source = source
        self.selector = selector
    }

    public static let metadataOnly = HTTPResponsePolicy(kind: .metadataOnly)
}

public struct HTTPOperation: Codable, Equatable, Sendable {
    public let method: HTTPMethod
    public let auth: HTTPAuthStrategy
    public let body: HTTPBody
    public let responsePolicy: HTTPResponsePolicy
    public let timeoutMs: Int?

    public init(
        method: HTTPMethod = .get,
        auth: HTTPAuthStrategy = .none,
        body: HTTPBody = .none,
        responsePolicy: HTTPResponsePolicy = .metadataOnly,
        timeoutMs: Int? = nil
    ) {
        self.method = method
        self.auth = auth
        self.body = body
        self.responsePolicy = responsePolicy
        self.timeoutMs = timeoutMs
    }
}

public enum DatabaseParameterValue: Codable, Equatable, Sendable {
    case string(String)
    case integer(Int64)
    case double(Double)
    case boolean(Bool)
    case secretReference(SecretReference)
    case null

    private enum CodingKeys: String, CodingKey { case type, value }
    private enum ValueType: String, Codable { case string, integer, double, boolean, secretReference, null }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ValueType.self, forKey: .type) {
        case .string: self = .string(try container.decode(String.self, forKey: .value))
        case .integer: self = .integer(try container.decode(Int64.self, forKey: .value))
        case .double: self = .double(try container.decode(Double.self, forKey: .value))
        case .boolean: self = .boolean(try container.decode(Bool.self, forKey: .value))
        case .secretReference: self = .secretReference(try container.decode(SecretReference.self, forKey: .value))
        case .null: self = .null
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .string(value):
            try container.encode(ValueType.string, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .integer(value):
            try container.encode(ValueType.integer, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .double(value):
            try container.encode(ValueType.double, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .boolean(value):
            try container.encode(ValueType.boolean, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .secretReference(value):
            try container.encode(ValueType.secretReference, forKey: .type)
            try container.encode(value, forKey: .value)
        case .null:
            try container.encode(ValueType.null, forKey: .type)
        }
    }
}

public struct DatabaseParameter: Codable, Equatable, Sendable {
    public let name: String
    public let value: DatabaseParameterValue

    public init(name: String, value: DatabaseParameterValue) {
        self.name = name
        self.value = value
    }

    public var secretReference: SecretReference? {
        if case let .secretReference(reference) = value { return reference }
        return nil
    }
}

public struct DatabaseOperation: Codable, Equatable, Sendable {
    public let engine: SecretOperationProtocol
    public let database: String
    public let username: String?
    public let usernameReference: SecretReference?
    public let passwordReference: SecretReference?
    public let statement: String
    public let parameters: [DatabaseParameter]
    public let maxRows: Int
    public let timeoutMs: Int?

    public init(
        engine: SecretOperationProtocol,
        database: String,
        username: String? = nil,
        usernameReference: SecretReference? = nil,
        passwordReference: SecretReference? = nil,
        statement: String,
        parameters: [DatabaseParameter] = [],
        maxRows: Int = 100,
        timeoutMs: Int? = nil
    ) {
        self.engine = engine
        self.database = database
        self.username = username
        self.usernameReference = usernameReference
        self.passwordReference = passwordReference
        self.statement = statement
        self.parameters = parameters
        self.maxRows = maxRows
        self.timeoutMs = timeoutMs
    }
}

public struct FileTransferOperation: Codable, Equatable, Sendable {
    public let protocolType: SecretOperationProtocol
    public let operation: SecretFileOperation
    public let remotePath: String
    public let localPath: String?
    public let localFileGrantID: String?
    public let username: String?
    public let usernameReference: SecretReference?
    public let passwordReference: SecretReference?

    public init(
        protocolType: SecretOperationProtocol,
        operation: SecretFileOperation,
        remotePath: String,
        localPath: String? = nil,
        localFileGrantID: String? = nil,
        username: String? = nil,
        usernameReference: SecretReference? = nil,
        passwordReference: SecretReference? = nil
    ) {
        self.protocolType = protocolType
        self.operation = operation
        self.remotePath = remotePath
        self.localPath = localPath
        self.localFileGrantID = localFileGrantID
        self.username = username
        self.usernameReference = usernameReference
        self.passwordReference = passwordReference
    }
}

public struct BrowserLoginOperation: Codable, Equatable, Sendable {
    public let profileID: String?
    public let browser: String?
    public let url: String?
    public let username: String?
    public let usernameReference: SecretReference?
    public let passwordReference: SecretReference?
    public let usernameSelector: String?
    public let passwordSelector: String?
    public let submitSelector: String?
    public let submit: Bool

    public init(
        profileID: String? = nil,
        browser: String? = nil,
        url: String? = nil,
        username: String? = nil,
        usernameReference: SecretReference? = nil,
        passwordReference: SecretReference? = nil,
        usernameSelector: String? = nil,
        passwordSelector: String? = nil,
        submitSelector: String? = nil,
        submit: Bool = false
    ) {
        self.profileID = profileID
        self.browser = browser
        self.url = url
        self.username = username
        self.usernameReference = usernameReference
        self.passwordReference = passwordReference
        self.usernameSelector = usernameSelector
        self.passwordSelector = passwordSelector
        self.submitSelector = submitSelector
        self.submit = submit
    }
}

public struct LocalAppFillField: Codable, Equatable, Sendable {
    public let name: String
    public let value: String?
    public let valueReference: SecretReference?

    public init(name: String, value: String? = nil, valueReference: SecretReference? = nil) {
        self.name = name
        self.value = value
        self.valueReference = valueReference
    }
}

public struct LocalAppFillOperation: Codable, Equatable, Sendable {
    public let bundleID: String
    public let fields: [LocalAppFillField]
    public let submitButton: String?

    public init(bundleID: String, fields: [LocalAppFillField], submitButton: String? = nil) {
        self.bundleID = bundleID
        self.fields = fields
        self.submitButton = submitButton
    }
}

public struct ExportOperation: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case persistent
        case ephemeral
        case directDelivery
    }

    public let kind: Kind
    public let destinationRoot: String?
    public let overwrite: Bool
    public let secretReferences: [SecretReference]

    public init(
        kind: Kind = .persistent,
        destinationRoot: String? = nil,
        overwrite: Bool = false,
        secretReferences: [SecretReference] = []
    ) {
        self.kind = kind
        self.destinationRoot = destinationRoot
        self.overwrite = overwrite
        self.secretReferences = secretReferences
    }
}

public struct TrustedProcessOperation: Codable, Equatable, Sendable {
    public let profileID: String
    public let arguments: [String]
    public let secretReferences: [SecretReference]

    public init(
        profileID: String,
        arguments: [String] = [],
        secretReferences: [SecretReference] = []
    ) {
        self.profileID = profileID
        self.arguments = arguments
        self.secretReferences = secretReferences
    }
}
