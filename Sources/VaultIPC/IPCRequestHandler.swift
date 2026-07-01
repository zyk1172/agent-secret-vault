import Foundation
import VaultCore

public protocol WorkbenchServicing: Sendable {
    func recordPluginActivity() async
    func status() async -> WorkbenchStatus
    func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String
    func openRevealSession(references: [String], context: RevealContext) async throws -> String
    func restoreReferences(references: [String], context: RevealContext) async throws -> String
    func exportResolvedText(references: [String], context: RevealContext, destinationPath: String) async throws -> String
    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult
}

public extension WorkbenchServicing {
    func recordPluginActivity() async {}
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
        await service.recordPluginActivity()
        switch request {
        case .status:
            return .status(locked: await service.status().locked)
        case .workbenchStatus:
            return .workbenchStatus(await service.status())
        case let .inspectReference(reference):
            return .referenceMetadata(try await service.inspectReference(reference))
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
        case let .restoreReferences(references, context):
            return .restoredText(try await service.restoreReferences(references: references, context: context))
        case let .exportResolvedText(references, context, destinationPath):
            let path = try await service.exportResolvedText(
                references: references,
                context: context,
                destinationPath: destinationPath
            )
            return .exported(path: path)
        case let .scanOrphans(markdownReferences):
            return .orphanScan(try await service.scanOrphans(markdownReferences: markdownReferences))
        case .execute:
            return .failure(code: "EXECUTE_UNAVAILABLE")
        }
    }
}
