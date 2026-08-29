import Foundation

/// The non-secret identity of one reusable Agent execution authorization.
///
/// A lease is deliberately bound to the complete set of opaque references,
/// normalized destination, protocol, operation family, caller principal and
/// security generation.  It must never contain resolved secret material.
public struct ExecutionAuthorizationScope: Hashable, Sendable {
    public let principal: String
    public let secretReferenceIDs: [String]
    public let normalizedDestination: String?
    public let port: Int?
    public let protocolType: String?
    public let actionFamily: String
    public let generation: UInt64

    public init(
        principal: String,
        secretReferenceIDs: [String],
        normalizedDestination: String?,
        port: Int?,
        protocolType: String?,
        actionFamily: String,
        generation: UInt64
    ) {
        self.principal = principal
        self.secretReferenceIDs = Array(Set(secretReferenceIDs)).sorted()
        self.normalizedDestination = normalizedDestination
        self.port = port
        self.protocolType = protocolType
        self.actionFamily = actionFamily
        self.generation = generation
    }
}
