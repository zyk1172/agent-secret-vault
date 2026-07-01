import Foundation
import VaultCore
import VaultExecution

public enum CapabilityTokenError: Error, Equatable, Sendable {
    case invalidEncoding
    case invalidLength(actualBytes: Int)
}

public struct CapabilityToken: Codable, Equatable, Sendable {
    public static let byteCount = 32

    public let rawValue: String

    public init(base64Encoded rawValue: String) throws {
        guard let decoded = Data(base64Encoded: rawValue) else {
            throw CapabilityTokenError.invalidEncoding
        }
        guard decoded.count == Self.byteCount else {
            throw CapabilityTokenError.invalidLength(actualBytes: decoded.count)
        }

        self.rawValue = rawValue
    }

    public static func random() -> CapabilityToken {
        let bytes = (0..<byteCount).map { _ in
            UInt8.random(in: UInt8.min ... UInt8.max)
        }
        return try! CapabilityToken(base64Encoded: Data(bytes).base64EncodedString())
    }

    public func constantTimeEquals(_ other: CapabilityToken) -> Bool {
        let lhs = Data(base64Encoded: rawValue)!
        let rhs = Data(base64Encoded: other.rawValue)!
        guard lhs.count == rhs.count else {
            return false
        }

        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(base64Encoded: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum IPCRequest: Codable, Equatable, Sendable {
    case status
    case workbenchStatus
    case inspectReference(reference: String)
    case reveal(reference: String, reason: String)
    case encrypt(label: String?, policy: SecretPolicy)
    case encryptText(plaintext: String, label: String?, policy: SecretPolicy)
    case revealReferences(references: [String], context: RevealContext)
    case restoreReferences(references: [String], context: RevealContext)
    case exportResolvedText(references: [String], context: RevealContext, destinationPath: String)
    case scanOrphans(markdownReferences: [String])
    case execute(ExecutionRequest)

    private enum CodingKeys: String, CodingKey {
        case type
        case plaintext
        case reference
        case references
        case reason
        case label
        case policy
        case context
        case destinationPath
        case markdownReferences
        case request
    }

    private enum RequestType: String, Codable {
        case status
        case workbenchStatus
        case inspectReference
        case reveal
        case encrypt
        case encryptText
        case revealReferences
        case restoreReferences
        case exportResolvedText
        case scanOrphans
        case execute
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .status:
            self = .status
        case .workbenchStatus:
            self = .workbenchStatus
        case .inspectReference:
            self = .inspectReference(
                reference: try container.decode(String.self, forKey: .reference)
            )
        case .reveal:
            self = .reveal(
                reference: try container.decode(String.self, forKey: .reference),
                reason: try container.decode(String.self, forKey: .reason)
            )
        case .encrypt:
            self = .encrypt(
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        case .encryptText:
            self = .encryptText(
                plaintext: try container.decode(String.self, forKey: .plaintext),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        case .revealReferences:
            self = .revealReferences(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context)
            )
        case .restoreReferences:
            self = .restoreReferences(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context)
            )
        case .exportResolvedText:
            self = .exportResolvedText(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context),
                destinationPath: try container.decode(String.self, forKey: .destinationPath)
            )
        case .scanOrphans:
            self = .scanOrphans(
                markdownReferences: try container.decode([String].self, forKey: .markdownReferences)
            )
        case .execute:
            self = .execute(try container.decode(ExecutionRequest.self, forKey: .request))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode(RequestType.status, forKey: .type)
        case .workbenchStatus:
            try container.encode(RequestType.workbenchStatus, forKey: .type)
        case let .inspectReference(reference):
            try container.encode(RequestType.inspectReference, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .reveal(reference, reason):
            try container.encode(RequestType.reveal, forKey: .type)
            try container.encode(reference, forKey: .reference)
            try container.encode(reason, forKey: .reason)
        case let .encrypt(label, policy):
            try container.encode(RequestType.encrypt, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .encryptText(plaintext, label, policy):
            try container.encode(RequestType.encryptText, forKey: .type)
            try container.encode(plaintext, forKey: .plaintext)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .revealReferences(references, context):
            try container.encode(RequestType.revealReferences, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
        case let .restoreReferences(references, context):
            try container.encode(RequestType.restoreReferences, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
        case let .exportResolvedText(references, context, destinationPath):
            try container.encode(RequestType.exportResolvedText, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
            try container.encode(destinationPath, forKey: .destinationPath)
        case let .scanOrphans(markdownReferences):
            try container.encode(RequestType.scanOrphans, forKey: .type)
            try container.encode(markdownReferences, forKey: .markdownReferences)
        case let .execute(request):
            try container.encode(RequestType.execute, forKey: .type)
            try container.encode(request, forKey: .request)
        }
    }
}

public struct WorkbenchStatus: Codable, Equatable, Sendable {
    public let locked: Bool
    public let ipcAvailable: Bool
    public let activeKnowledgeBaseRoot: String?
    public let pluginConnected: Bool

    private enum CodingKeys: String, CodingKey {
        case locked
        case ipcAvailable
        case activeKnowledgeBaseRoot
        case pluginConnected
    }

    public init(
        locked: Bool,
        ipcAvailable: Bool,
        activeKnowledgeBaseRoot: String?,
        pluginConnected: Bool
    ) {
        self.locked = locked
        self.ipcAvailable = ipcAvailable
        self.activeKnowledgeBaseRoot = activeKnowledgeBaseRoot
        self.pluginConnected = pluginConnected
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(locked, forKey: .locked)
        try container.encode(ipcAvailable, forKey: .ipcAvailable)
        if let activeKnowledgeBaseRoot {
            try container.encode(activeKnowledgeBaseRoot, forKey: .activeKnowledgeBaseRoot)
        } else {
            try container.encodeNil(forKey: .activeKnowledgeBaseRoot)
        }
        try container.encode(pluginConnected, forKey: .pluginConnected)
    }
}

public struct ReferenceRange: Codable, Equatable, Sendable {
    public let index: Int
    public let placeholder: String

    public init(index: Int, placeholder: String) {
        self.index = index
        self.placeholder = placeholder
    }
}

public struct RevealContext: Codable, Equatable, Sendable {
    public let reason: String
    public let template: String
    public let ranges: [ReferenceRange]

    public init(reason: String, template: String, ranges: [ReferenceRange]) {
        self.reason = reason
        self.template = template
        self.ranges = ranges
    }
}

public struct OrphanScanResult: Codable, Equatable, Sendable {
    public let missingRecords: [String]
    public let unreferencedRecords: [String]

    public init(missingRecords: [String], unreferencedRecords: [String]) {
        self.missingRecords = missingRecords
        self.unreferencedRecords = unreferencedRecords
    }
}

public struct SecretReferenceMetadata: Codable, Equatable, Sendable {
    public let reference: String
    public let policy: SecretPolicy
    public let label: String?
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        reference: String,
        policy: SecretPolicy,
        label: String?,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public enum IPCResponse: Codable, Equatable, Sendable {
    case status(locked: Bool)
    case workbenchStatus(WorkbenchStatus)
    case referenceMetadata(SecretReferenceMetadata)
    case displayedToUser
    case created(reference: String)
    case revealSessionOpened(sessionID: String)
    case restoredText(String)
    case exported(path: String)
    case orphanScan(OrphanScanResult)
    case execution(SanitizedExecutionResult)
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case locked
        case status
        case metadata
        case reference
        case sessionID
        case text
        case path
        case result
        case code
    }

    private enum ResponseType: String, Codable {
        case status
        case workbenchStatus
        case referenceMetadata
        case displayedToUser
        case created
        case revealSessionOpened
        case restoredText
        case exported
        case orphanScan
        case execution
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .status:
            self = .status(locked: try container.decode(Bool.self, forKey: .locked))
        case .workbenchStatus:
            self = .workbenchStatus(try container.decode(WorkbenchStatus.self, forKey: .status))
        case .referenceMetadata:
            self = .referenceMetadata(try container.decode(SecretReferenceMetadata.self, forKey: .metadata))
        case .displayedToUser:
            self = .displayedToUser
        case .created:
            self = .created(reference: try container.decode(String.self, forKey: .reference))
        case .revealSessionOpened:
            self = .revealSessionOpened(sessionID: try container.decode(String.self, forKey: .sessionID))
        case .restoredText:
            self = .restoredText(try container.decode(String.self, forKey: .text))
        case .exported:
            self = .exported(path: try container.decode(String.self, forKey: .path))
        case .orphanScan:
            self = .orphanScan(try container.decode(OrphanScanResult.self, forKey: .result))
        case .execution:
            self = .execution(try container.decode(SanitizedExecutionResult.self, forKey: .result))
        case .failure:
            self = .failure(code: try container.decode(String.self, forKey: .code))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .status(locked):
            try container.encode(ResponseType.status, forKey: .type)
            try container.encode(locked, forKey: .locked)
        case let .workbenchStatus(status):
            try container.encode(ResponseType.workbenchStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .referenceMetadata(metadata):
            try container.encode(ResponseType.referenceMetadata, forKey: .type)
            try container.encode(metadata, forKey: .metadata)
        case .displayedToUser:
            try container.encode(ResponseType.displayedToUser, forKey: .type)
        case let .created(reference):
            try container.encode(ResponseType.created, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .revealSessionOpened(sessionID):
            try container.encode(ResponseType.revealSessionOpened, forKey: .type)
            try container.encode(sessionID, forKey: .sessionID)
        case let .restoredText(text):
            try container.encode(ResponseType.restoredText, forKey: .type)
            try container.encode(text, forKey: .text)
        case let .exported(path):
            try container.encode(ResponseType.exported, forKey: .type)
            try container.encode(path, forKey: .path)
        case let .orphanScan(result):
            try container.encode(ResponseType.orphanScan, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .execution(result):
            try container.encode(ResponseType.execution, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .failure(code):
            try container.encode(ResponseType.failure, forKey: .type)
            try container.encode(code, forKey: .code)
        }
    }
}

public struct AuthenticatedIPCRequest: Codable, Equatable, Sendable {
    public let capabilityToken: CapabilityToken
    public let request: IPCRequest

    public init(capabilityToken: CapabilityToken, request: IPCRequest) {
        self.capabilityToken = capabilityToken
        self.request = request
    }
}

public enum IPCAuthenticationError: Error, Equatable, Sendable {
    case invalidCapabilityToken
}

public struct IPCAuthenticator: Sendable {
    public let expectedToken: CapabilityToken

    public init(expectedToken: CapabilityToken) {
        self.expectedToken = expectedToken
    }

    public func authenticate(_ request: AuthenticatedIPCRequest) throws -> IPCRequest {
        guard request.capabilityToken.constantTimeEquals(expectedToken) else {
            throw IPCAuthenticationError.invalidCapabilityToken
        }
        return request.request
    }
}
