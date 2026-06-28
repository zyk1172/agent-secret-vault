import Foundation
import VaultCore

public protocol WorkbenchServicing: Sendable {
    func status() async -> WorkbenchStatus
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String
    func openRevealSession(references: [String], context: RevealContext) async throws -> String
    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult
}

public enum IPCRequestHandlerError: Error, Equatable, Sendable {
    case unsupportedRequest
}

public struct IPCRequestHandler: Sendable {
    private let service: any WorkbenchServicing

    public init(service: any WorkbenchServicing) {
        self.service = service
    }

    public func handle(_ request: IPCRequest) async throws -> IPCResponse {
        switch request {
        case .status:
            return .status(locked: await service.status().locked)
        case .workbenchStatus:
            return .workbenchStatus(await service.status())
        case let .reveal(reference, reason):
            _ = try await service.openRevealSession(
                references: [reference],
                context: RevealContext(
                    reason: reason,
                    template: "{{0}}",
                    ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
                )
            )
            return .displayedToUser
        case .encrypt:
            return .failure(code: "SELECTION_ENCRYPT_UNAVAILABLE")
        case let .encryptText(plaintext, label, policy):
            let reference = try await service.encryptText(plaintext, label: label, policy: policy)
            return .created(reference: reference)
        case let .revealReferences(references, context):
            let sessionID = try await service.openRevealSession(references: references, context: context)
            return .revealSessionOpened(sessionID: sessionID)
        case let .scanOrphans(markdownReferences):
            return .orphanScan(try await service.scanOrphans(markdownReferences: markdownReferences))
        case .execute:
            return .failure(code: "EXECUTE_UNAVAILABLE")
        }
    }
}
