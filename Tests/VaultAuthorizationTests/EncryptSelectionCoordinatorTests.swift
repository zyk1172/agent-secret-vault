import CryptoKit
import Foundation
import Testing
@testable import AgentSecretVaultApp
import VaultAuthorization
import VaultCore

@Test func encryptSelectionSavesRecordBeforeReplacingSelection() async throws {
    let log = OperationLog()
    let recordStore = RecordingRecordStore(log: log)
    let selectionReplacer = RecordingSelectionReplacer(log: log)
    let keyData = Data(repeating: 0x42, count: 32)
    let expectedReference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let coordinator = EncryptSelectionCoordinator(
        recordStore: recordStore,
        selectionReplacer: selectionReplacer,
        deviceKeyStore: StaticDeviceKeyStore(keyData: keyData),
        idGenerator: StaticSecretIDGenerator(id: expectedReference.id)
    )

    let result = try await coordinator.encryptAndReplace(
        plaintext: "sk-test-123",
        label: "OpenAI test key",
        policy: .credential
    )

    #expect(result == .replaced(expectedReference))
    #expect(await log.events == [
        "save:start",
        "save:end",
        "replace:start:secret://0123456789ABCDEFGHJKMNPQRS",
        "replace:end"
    ])

    let savedRecords = await recordStore.records
    #expect(savedRecords.count == 1)
    #expect(savedRecords.first?.id == expectedReference.id)
    #expect(savedRecords.first?.recordVersion == 1)
    #expect(savedRecords.first?.label == "OpenAI test key")
    #expect(savedRecords.first?.policy == .credential)

    let savedRecord = try #require(savedRecords.first)
    let decrypted = try VaultCipher().decrypt(savedRecord, masterKey: SymmetricKey(data: keyData))
    #expect(String(data: decrypted, encoding: .utf8) == "sk-test-123")
}

@Test func replacementFailureReturnsUnlinkedRecordWithoutRetryingReplacement() async throws {
    let log = OperationLog()
    let recordStore = RecordingRecordStore(log: log)
    let selectionReplacer = RecordingSelectionReplacer(log: log, behavior: .fail)
    let expectedReference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let coordinator = EncryptSelectionCoordinator(
        recordStore: recordStore,
        selectionReplacer: selectionReplacer,
        deviceKeyStore: StaticDeviceKeyStore(keyData: Data(repeating: 0x24, count: 32)),
        idGenerator: StaticSecretIDGenerator(id: expectedReference.id)
    )

    let result = try await coordinator.encryptAndReplace(
        plaintext: "private-token",
        label: "GitHub token",
        policy: .externalSend
    )

    #expect(result == .unlinkedRecord(expectedReference))
    #expect((await recordStore.records).count == 1)
    #expect(await selectionReplacer.replacementAttempts == 1)
    #expect(await log.events == [
        "save:start",
        "save:end",
        "replace:start:secret://0123456789ABCDEFGHJKMNPQRS"
    ])
}

@Test func emptyPlaintextIsRejectedBeforeSavingOrReplacing() async throws {
    let recordStore = RecordingRecordStore()
    let selectionReplacer = RecordingSelectionReplacer()
    let coordinator = EncryptSelectionCoordinator(
        recordStore: recordStore,
        selectionReplacer: selectionReplacer,
        deviceKeyStore: StaticDeviceKeyStore(keyData: Data(repeating: 0x12, count: 32)),
        idGenerator: StaticSecretIDGenerator(id: "0123456789ABCDEFGHJKMNPQRS")
    )

    await expectEncryptSelectionError(.emptyPlaintext) {
        _ = try await coordinator.encryptAndReplace(
            plaintext: "",
            label: "empty",
            policy: .credential
        )
    }

    #expect((await recordStore.records).isEmpty)
    #expect(await selectionReplacer.replacementAttempts == 0)
}

@Test func labelContainingPlaintextIsRejectedBeforeSavingOrReplacing() async throws {
    let recordStore = RecordingRecordStore()
    let selectionReplacer = RecordingSelectionReplacer()
    let coordinator = EncryptSelectionCoordinator(
        recordStore: recordStore,
        selectionReplacer: selectionReplacer,
        deviceKeyStore: StaticDeviceKeyStore(keyData: Data(repeating: 0x13, count: 32)),
        idGenerator: StaticSecretIDGenerator(id: "0123456789ABCDEFGHJKMNPQRS")
    )

    await expectEncryptSelectionError(.labelContainsPlaintext) {
        _ = try await coordinator.encryptAndReplace(
            plaintext: "sk-live-secret",
            label: "label leaks sk-live-secret",
            policy: .credential
        )
    }

    #expect((await recordStore.records).isEmpty)
    #expect(await selectionReplacer.replacementAttempts == 0)
}

private func expectEncryptSelectionError(
    _ expected: EncryptSelectionError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but operation succeeded.")
    } catch let error as EncryptSelectionError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private actor OperationLog {
    private var storedEvents: [String] = []

    var events: [String] {
        storedEvents
    }

    func append(_ event: String) {
        storedEvents.append(event)
    }
}

private actor RecordingRecordStore: RecordStore {
    private let log: OperationLog?
    private var storedRecords: [EncryptedRecord] = []

    init(log: OperationLog? = nil) {
        self.log = log
    }

    var records: [EncryptedRecord] {
        storedRecords
    }

    func save(_ record: EncryptedRecord) async throws {
        await log?.append("save:start")
        storedRecords.append(record)
        await log?.append("save:end")
    }

    func latest(id: String) async throws -> EncryptedRecord {
        guard let record = storedRecords.last(where: { $0.id == id }) else {
            throw RecordStoreFailure.missing
        }

        return record
    }

    func versions(id: String) async throws -> [Int] {
        storedRecords
            .filter { $0.id == id }
            .map(\.recordVersion)
    }
}

private enum ReplacementBehavior: Sendable {
    case succeed
    case fail
}

private actor RecordingSelectionReplacer: SelectionReplacing {
    private let log: OperationLog?
    private let behavior: ReplacementBehavior
    private var storedReplacementAttempts = 0

    init(log: OperationLog? = nil, behavior: ReplacementBehavior = .succeed) {
        self.log = log
        self.behavior = behavior
    }

    var replacementAttempts: Int {
        storedReplacementAttempts
    }

    func replaceSelection(with text: String) async throws {
        storedReplacementAttempts += 1
        await log?.append("replace:start:\(text)")

        guard behavior == .succeed else {
            throw ReplacementFailure.failed
        }

        await log?.append("replace:end")
    }
}

private enum ReplacementFailure: Error {
    case failed
}

private enum RecordStoreFailure: Error {
    case missing
}

private struct StaticDeviceKeyStore: DeviceKeyStoring {
    let keyData: Data

    func deviceKey(reason: String) async throws -> Data {
        keyData
    }
}

private struct StaticSecretIDGenerator: SecretIDGenerating {
    let id: String

    func nextID() throws -> String {
        id
    }
}
