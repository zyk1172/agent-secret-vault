import Foundation
import VaultCore

/// The capability inventory is derived from the daemon's actual adapters. It
/// is intentionally a projection: it contains no executable path, session
/// secret, or other internal implementation detail.
public enum SecretAdapterKind: String, Codable, CaseIterable, Sendable {
    case ssh
    case http
    case database
    case sftp
    case browser
    case localApp
    case export
    case trustedProcess
}

public struct SecretOperationCapability: Codable, Equatable, Sendable {
    public let kind: SecretAdapterKind
    public let status: SecretOperationExecutionCapability
    public let operations: [SecretOperationAction]
    public let reason: String?

    public init(
        kind: SecretAdapterKind,
        status: SecretOperationExecutionCapability,
        operations: [SecretOperationAction],
        reason: String? = nil
    ) {
        self.kind = kind
        self.status = status
        self.operations = operations
        self.reason = reason.map(Self.sanitizeReason)
    }

    private static func sanitizeReason(_ value: String) -> String {
        String(value
            .split(whereSeparator: { $0 == "\n" || $0 == "\r" || $0 == "\t" })
            .joined(separator: " ")
            .prefix(240))
    }
}

/// Every non-SSH operation is dispatched through a purpose-built adapter.
/// The adapter receives the already-authorized resolver, but it remains
/// responsible for keeping resolved bytes inside its own execution boundary.
public protocol SecretOperationAdapter: Sendable {
    var kind: SecretAdapterKind { get }
    var capability: SecretOperationCapability { get }

    func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput

    func invalidateSecurityState() async
}

/// A disabled adapter is explicit. It is never allowed to perform a no-op
/// "success" because that would prime an authorization lease for an action the
/// daemon cannot actually execute.
public struct UnavailableSecretOperationAdapter: SecretOperationAdapter {
    public let kind: SecretAdapterKind
    public let capability: SecretOperationCapability

    public init(
        kind: SecretAdapterKind,
        operations: [SecretOperationAction],
        reason: String
    ) {
        self.kind = kind
        self.capability = SecretOperationCapability(
            kind: kind,
            status: .unavailable,
            operations: operations,
            reason: reason
        )
    }

    public func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        .unavailable
    }

    public func execute(
        _: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        context _: SecretOperationExecutionContext,
        resolve _: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        throw SecretOperationExecutionError.unavailable
    }

    public func invalidateSecurityState() async {}
}

/// Central registry for purpose-built adapters. SSH remains owned by
/// LocalSecretOperationExecutor because it also owns the existing SSH session
/// manager; all other secret-bearing operations use this registry.
public struct SecretOperationAdapterRegistry: @unchecked Sendable {
    private let adapters: [any SecretOperationAdapter]

    public init(httpSessionManager: HTTPSessionManager = HTTPSessionManager()) {
        adapters = [
            HTTPSecretOperationAdapter(sessionManager: httpSessionManager),
            UnavailableSecretOperationAdapter(
                kind: .database,
                operations: [.databaseQuery],
                reason: "没有安装并启用受 SVLT 约束的 PostgreSQL/MySQL 只读 driver"
            ),
            UnavailableSecretOperationAdapter(
                kind: .sftp,
                operations: [.sftpTransfer],
                reason: "SFTP adapter 尚未启用安全的本地文件 grant 与 transport bridge"
            ),
            UnavailableSecretOperationAdapter(
                kind: .browser,
                operations: [.browserLogin],
                reason: "没有签名的 Browser Native Messaging executor"
            ),
            UnavailableSecretOperationAdapter(
                kind: .localApp,
                operations: [.localAppFill],
                reason: "没有完成目标 App 签名校验的 Accessibility executor"
            ),
            UnavailableSecretOperationAdapter(
                kind: .trustedProcess,
                operations: [.localExecution],
                reason: "没有配置 allowlisted signed trusted-process profile"
            )
        ]
    }

    public func capabilityManifest() -> [SecretOperationCapability] {
        adapters.map(\.capability)
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        guard let adapter = adapter(for: descriptor.actionType) else {
            return .unavailable
        }
        return adapter.preflight(descriptor)
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard let adapter = adapter(for: descriptor.actionType) else {
            throw SecretOperationExecutionError.unsupportedAction
        }
        return try await adapter.execute(
            descriptor,
            metadata: metadata,
            context: context,
            resolve: resolve
        )
    }

    public func invalidateSecurityState() async {
        for adapter in adapters {
            await adapter.invalidateSecurityState()
        }
    }

    private func adapter(for action: SecretOperationAction) -> (any SecretOperationAdapter)? {
        adapters.first { $0.capability.operations.contains(action) }
    }
}
