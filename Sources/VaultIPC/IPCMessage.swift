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
    case reveal(reference: String, reason: String)
    case encrypt(label: String?, policy: SecretPolicy)
    case execute(ExecutionRequest)

    private enum CodingKeys: String, CodingKey {
        case type
        case reference
        case reason
        case label
        case policy
        case request
    }

    private enum RequestType: String, Codable {
        case status
        case reveal
        case encrypt
        case execute
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .status:
            self = .status
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
        case .execute:
            self = .execute(try container.decode(ExecutionRequest.self, forKey: .request))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode(RequestType.status, forKey: .type)
        case let .reveal(reference, reason):
            try container.encode(RequestType.reveal, forKey: .type)
            try container.encode(reference, forKey: .reference)
            try container.encode(reason, forKey: .reason)
        case let .encrypt(label, policy):
            try container.encode(RequestType.encrypt, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .execute(request):
            try container.encode(RequestType.execute, forKey: .type)
            try container.encode(request, forKey: .request)
        }
    }
}

public enum IPCResponse: Codable, Equatable, Sendable {
    case status(locked: Bool)
    case displayedToUser
    case created(reference: String)
    case execution(SanitizedExecutionResult)
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case locked
        case reference
        case result
        case code
    }

    private enum ResponseType: String, Codable {
        case status
        case displayedToUser
        case created
        case execution
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .status:
            self = .status(locked: try container.decode(Bool.self, forKey: .locked))
        case .displayedToUser:
            self = .displayedToUser
        case .created:
            self = .created(reference: try container.decode(String.self, forKey: .reference))
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
        case .displayedToUser:
            try container.encode(ResponseType.displayedToUser, forKey: .type)
        case let .created(reference):
            try container.encode(ResponseType.created, forKey: .type)
            try container.encode(reference, forKey: .reference)
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
