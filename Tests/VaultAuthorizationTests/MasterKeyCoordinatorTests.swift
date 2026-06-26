import CryptoKit
import Foundation
import Testing
@testable import VaultAuthorization

@Test func newVaultCreatesLocalAndRecoveryWrappedMasterKey() async throws {
    let localKey = Data(repeating: 0x11, count: 32)
    let recoveryKey = Data(repeating: 0x22, count: 32)
    let store = MemoryWrappedMasterKeyStore()
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: localKey),
        recoveryKeyStore: MemoryRecoveryKeyStore(key: recoveryKey),
        wrappedStore: store,
        randomMasterKey: { Data(repeating: 0xA5, count: 32) }
    )

    #expect(try await coordinator.unlockState() == .ready)

    let masterKey = try await coordinator.unlock(reason: "Create vault")

    #expect(masterKey == Data(repeating: 0xA5, count: 32))
    let saved = try #require(await store.current)
    #expect(saved.local != nil)
    #expect(saved.recovery != nil)
    #expect(try saved.local?.open(using: localKey) == masterKey)
    #expect(try saved.recovery?.open(using: recoveryKey) == masterKey)
}

@Test func normalLocalUnlockDoesNotRequireRecoveryKey() async throws {
    let localKey = Data(repeating: 0x33, count: 32)
    let masterKey = Data(repeating: 0x44, count: 32)
    let wrapped = try WrappedMasterKeySet(local: .seal(masterKey, using: localKey), recovery: nil)
    let store = MemoryWrappedMasterKeyStore(initial: wrapped)
    let recoveryStore = MemoryRecoveryKeyStore(key: nil)
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: localKey),
        recoveryKeyStore: recoveryStore,
        wrappedStore: store
    )

    #expect(try await coordinator.unlockState() == .authenticationRequired)
    #expect(try await coordinator.unlock(reason: "Open vault") == masterKey)
    #expect(await recoveryStore.loadOrCreateCount == 0)
    #expect(await recoveryStore.loadCount == 0)
}

@Test func recoveryUnavailableWhenOnlyRecoveryWrapperExistsButRecoveryKeyIsMissing() async throws {
    let recoveryKey = Data(repeating: 0x55, count: 32)
    let masterKey = Data(repeating: 0x66, count: 32)
    let wrapped = try WrappedMasterKeySet(local: nil, recovery: .seal(masterKey, using: recoveryKey))
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: Data(repeating: 0x77, count: 32)),
        recoveryKeyStore: MemoryRecoveryKeyStore(key: nil),
        wrappedStore: MemoryWrappedMasterKeyStore(initial: wrapped)
    )

    #expect(try await coordinator.unlockState() == .recoveryRequired)
    await expectMasterKeyError(.recoveryUnavailable) {
        _ = try await coordinator.recover(reason: "Recover vault")
    }
}

@Test func recoveredMacCreatesANewLocalWrapper() async throws {
    let recoveryKey = Data(repeating: 0x88, count: 32)
    let newLocalKey = Data(repeating: 0x99, count: 32)
    let masterKey = Data(repeating: 0xAB, count: 32)
    let wrapped = try WrappedMasterKeySet(local: nil, recovery: .seal(masterKey, using: recoveryKey))
    let store = MemoryWrappedMasterKeyStore(initial: wrapped)
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: newLocalKey),
        recoveryKeyStore: MemoryRecoveryKeyStore(key: recoveryKey),
        wrappedStore: store
    )

    let recovered = try await coordinator.recover(reason: "Recover vault")

    #expect(recovered == masterKey)
    let saved = try #require(await store.current)
    #expect(try saved.local?.open(using: newLocalKey) == masterKey)
    #expect(try saved.recovery?.open(using: recoveryKey) == masterKey)
}

@Test func malformedRecoveryDataFailsClosed() async throws {
    let wrapped = WrappedMasterKeySet(
        local: nil,
        recovery: WrappedMasterKey(
            ciphertext: Data(repeating: 0x01, count: 12),
            nonce: Data(repeating: 0x02, count: 12),
            tag: Data(repeating: 0x03, count: 16)
        )
    )
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: Data(repeating: 0x04, count: 32)),
        recoveryKeyStore: MemoryRecoveryKeyStore(key: Data(repeating: 0x05, count: 32)),
        wrappedStore: MemoryWrappedMasterKeyStore(initial: wrapped)
    )

    await expectMasterKeyError(.malformedRecoveryData) {
        _ = try await coordinator.recover(reason: "Recover vault")
    }
}

@Test func unsupportedRequiredKeychainControlsFailClosedBeforeCreatingVault() async throws {
    let recoveryStore = MemoryRecoveryKeyStore(
        key: Data(repeating: 0x12, count: 32),
        supportsRequiredKeychainControls: false
    )
    let store = MemoryWrappedMasterKeyStore()
    let coordinator = MasterKeyCoordinator(
        deviceKeyStore: FixedDeviceKeyStore(key: Data(repeating: 0x13, count: 32)),
        recoveryKeyStore: recoveryStore,
        wrappedStore: store
    )

    await expectMasterKeyError(.unsupportedRequiredKeychainControls) {
        _ = try await coordinator.unlock(reason: "Create vault")
    }
    #expect(await store.current == nil)
    #expect(await recoveryStore.loadOrCreateCount == 0)
}

private func expectMasterKeyError(
    _ expected: MasterKeyCoordinatorError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but operation succeeded.")
    } catch let error as MasterKeyCoordinatorError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private actor MemoryWrappedMasterKeyStore: WrappedMasterKeyStoring {
    private var stored: WrappedMasterKeySet?

    init(initial: WrappedMasterKeySet? = nil) {
        stored = initial
    }

    var current: WrappedMasterKeySet? {
        stored
    }

    func loadWrappedMasterKeySet() async throws -> WrappedMasterKeySet? {
        stored
    }

    func saveWrappedMasterKeySet(_ wrapped: WrappedMasterKeySet) async throws {
        stored = wrapped
    }
}

private actor MemoryRecoveryKeyStore: RecoveryKeyStoring {
    private let key: Data?
    private let supported: Bool
    private var storedLoadCount = 0
    private var storedLoadOrCreateCount = 0

    init(key: Data?, supportsRequiredKeychainControls: Bool = true) {
        self.key = key
        supported = supportsRequiredKeychainControls
    }

    var loadCount: Int {
        storedLoadCount
    }

    var loadOrCreateCount: Int {
        storedLoadOrCreateCount
    }

    func supportsRequiredKeychainControls() async throws -> Bool {
        supported
    }

    func loadRecoveryKeyData() async throws -> Data? {
        storedLoadCount += 1
        return key
    }

    func loadOrCreateRecoveryKeyData() async throws -> Data {
        storedLoadOrCreateCount += 1
        if let key {
            return key
        }
        return Data(repeating: 0xFA, count: 32)
    }
}

private struct FixedDeviceKeyStore: DeviceKeyStoring {
    let key: Data

    func deviceKey(reason: String) async throws -> Data {
        key
    }
}
