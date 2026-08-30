import Foundation

/// The non-secret identity of one reusable, purpose-bound Agent authorization.
/// It covers purpose-built execution and the separately constrained local
/// export path; plaintext reveal/copy and other high-risk controls remain
/// exact one-shot approvals.
///
/// A lease is deliberately bound to the complete set of opaque references,
/// normalized destination, protocol, operation family, caller principal and
/// security generation.  It must never contain resolved secret material.
public struct ExecutionAuthorizationScope: Hashable, Sendable {
    public let principal: String
    public let secretReferenceIDs: [String]
    public let normalizedDestination: String?
    public let port: Int?
    public let username: String?
    public let protocolType: String?
    public let actionFamily: String
    /// Canonical operation identity for protocols where reusing an approval
    /// across paths, methods, headers, or bodies would be unsafe. SSH leaves
    /// this nil so ordinary policy-reviewed commands can share the lease.
    public let operationFingerprint: String?
    public let generation: UInt64

    public init(
        principal: String,
        secretReferenceIDs: [String],
        normalizedDestination: String?,
        port: Int?,
        username: String? = nil,
        protocolType: String?,
        actionFamily: String,
        operationFingerprint: String? = nil,
        generation: UInt64
    ) {
        self.principal = principal
        self.secretReferenceIDs = Array(Set(secretReferenceIDs)).sorted()
        self.normalizedDestination = normalizedDestination
        self.port = port
        self.username = username
        self.protocolType = protocolType
        self.actionFamily = actionFamily
        self.operationFingerprint = operationFingerprint
        self.generation = generation
    }
}
