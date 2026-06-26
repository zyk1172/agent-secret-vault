import VaultAuthorization

public struct ExecutionTemplate: Codable, Sendable {
    public let id: String
    public let executable: String
    public let arguments: [ArgumentSlot]
    public let risk: RiskClass
    public let allowedHosts: Set<String>
    public let allowedPaths: Set<String>

    public init(
        id: String,
        executable: String,
        arguments: [ArgumentSlot],
        risk: RiskClass,
        allowedHosts: Set<String>,
        allowedPaths: Set<String>
    ) {
        self.id = id
        self.executable = executable
        self.arguments = arguments
        self.risk = risk
        self.allowedHosts = allowedHosts
        self.allowedPaths = allowedPaths
    }
}

public enum ArgumentSlot: Codable, Equatable, Sendable {
    case literal(String)
    case value(name: String)
    case secret(name: String)
}
