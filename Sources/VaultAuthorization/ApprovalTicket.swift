import CryptoKit
import Foundation
import VaultCore

public struct ApprovalTicket: Codable, Equatable, Sendable {
    public let operationHash: String
    public let action: SecretOperationAction
    public let secretReferenceIDs: [String]
    public let destination: String?
    public let port: Int?
    public let protocolType: SecretOperationProtocol?
    public let commandHash: String?
    public let httpMethod: String?
    public let path: String?
    public let databaseOperation: String?
    public let fileTarget: String?
    public let issuedAt: Date
    public let expiresAt: Date
    public let nonce: String

    public init(
        operationHash: String,
        action: SecretOperationAction,
        secretReferenceIDs: [String],
        destination: String?,
        port: Int?,
        protocolType: SecretOperationProtocol?,
        commandHash: String?,
        httpMethod: String?,
        path: String?,
        databaseOperation: String?,
        fileTarget: String?,
        issuedAt: Date,
        expiresAt: Date,
        nonce: String
    ) {
        self.operationHash = operationHash
        self.action = action
        self.secretReferenceIDs = secretReferenceIDs
        self.destination = destination
        self.port = port
        self.protocolType = protocolType
        self.commandHash = commandHash
        self.httpMethod = httpMethod
        self.path = path
        self.databaseOperation = databaseOperation
        self.fileTarget = fileTarget
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.nonce = nonce
    }

    public static func issue(
        for descriptor: SecretOperationDescriptor,
        now: Date = Date(),
        lifetime: TimeInterval = 90
    ) -> Self {
        Self(
            operationHash: descriptor.operationHash,
            action: descriptor.actionType,
            secretReferenceIDs: descriptor.secretReferences.map(\.id),
            destination: descriptor.normalizedDestination,
            port: descriptor.port,
            protocolType: descriptor.protocolType,
            commandHash: descriptor.commandHash,
            httpMethod: descriptor.httpMethod?.uppercased(),
            path: descriptor.normalizedPath,
            databaseOperation: descriptor.databaseStatement.flatMap(Self.databaseOperation),
            fileTarget: descriptor.fileTarget,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(lifetime),
            nonce: UUID().uuidString
        )
    }

    public func matches(_ descriptor: SecretOperationDescriptor, now: Date = Date()) -> Bool {
        guard now < expiresAt,
              operationHash == descriptor.operationHash,
              action == descriptor.actionType,
              secretReferenceIDs == descriptor.secretReferences.map(\.id),
              destination == descriptor.normalizedDestination,
              port == descriptor.port,
              protocolType == descriptor.protocolType,
              commandHash == descriptor.commandHash,
              httpMethod == descriptor.httpMethod?.uppercased(),
              path == descriptor.normalizedPath,
              databaseOperation == descriptor.databaseStatement.flatMap(Self.databaseOperation),
              fileTarget == descriptor.fileTarget
        else {
            return false
        }
        return !nonce.isEmpty
    }

    private static func databaseOperation(_ statement: String) -> String? {
        statement
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" })
            .first?
            .uppercased()
    }
}

/// One-time local ticket storage.  A ticket is consumed only after the exact
/// descriptor used for approval is presented again; it cannot be replayed or
/// transferred to another destination or Secret.
public actor ApprovalTicketStore {
    private let lifetime: TimeInterval
    private var activeTickets: [String: ApprovalTicket] = [:]

    public init(lifetime: TimeInterval = 90) {
        self.lifetime = lifetime
    }

    public func issue(
        for descriptor: SecretOperationDescriptor,
        now: Date = Date()
    ) -> ApprovalTicket {
        let ticket = ApprovalTicket.issue(for: descriptor, now: now, lifetime: lifetime)
        activeTickets[ticket.nonce] = ticket
        purgeExpired(now: now)
        return ticket
    }

    public func consume(
        _ ticket: ApprovalTicket,
        for descriptor: SecretOperationDescriptor,
        now: Date = Date()
    ) -> Bool {
        defer {
            activeTickets[ticket.nonce] = nil
            purgeExpired(now: now)
        }
        guard activeTickets[ticket.nonce] == ticket else {
            return false
        }
        return ticket.matches(descriptor, now: now)
    }

    public func activeTicketCount(now: Date = Date()) -> Int {
        purgeExpired(now: now)
        return activeTickets.count
    }

    private func purgeExpired(now: Date) {
        activeTickets = activeTickets.filter { $0.value.expiresAt > now }
    }
}
