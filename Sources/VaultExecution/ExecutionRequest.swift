import VaultAuthorization
import VaultCore

public struct ExecutionRequest: Codable, Equatable, Sendable {
    public let templateID: String
    public var executable: String
    public var values: [String: String]
    public var secrets: [String: SecretReference]
    public var destinationHost: String?
    public var destinationPath: String?
    public var requestedRisk: RiskClass

    public init(
        templateID: String,
        executable: String,
        values: [String: String],
        secrets: [String: SecretReference],
        destinationHost: String?,
        destinationPath: String?,
        requestedRisk: RiskClass
    ) {
        self.templateID = templateID
        self.executable = executable
        self.values = values
        self.secrets = secrets
        self.destinationHost = destinationHost
        self.destinationPath = destinationPath
        self.requestedRisk = requestedRisk
    }
}
