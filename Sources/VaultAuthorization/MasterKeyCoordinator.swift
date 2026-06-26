import CryptoKit
import Foundation
import Security

public enum VaultUnlockState: Equatable, Sendable {
    case ready
    case authenticationRequired
    case recoveryRequired
    case recoveryUnavailable
}

public enum MasterKeyCoordinatorError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case unsupportedRequiredKeychainControls
    case recoveryUnavailable
    case missingWrappedMasterKey
    case malformedRecoveryData
    case integrityFailed
}

public struct WrappedMasterKey: Codable, Equatable, Sendable {
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data

    public init(ciphertext: Data, nonce: Data, tag: Data) {
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
    }

    public static func seal(_ masterKey: Data, using wrappingKey: Data) throws -> WrappedMasterKey {
        try validateKeySize(masterKey)
        try validateKeySize(wrappingKey)

        let sealed = try AES.GCM.seal(
            masterKey,
            using: SymmetricKey(data: wrappingKey),
            authenticating: Data("AgentSecretVault.MasterKeyWrapper.v1".utf8)
        )
        return WrappedMasterKey(
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
    }

    public func open(using wrappingKey: Data) throws -> Data {
        try Self.validateKeySize(wrappingKey)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            let opened = try AES.GCM.open(
                box,
                using: SymmetricKey(data: wrappingKey),
                authenticating: Data("AgentSecretVault.MasterKeyWrapper.v1".utf8)
            )
            try Self.validateKeySize(opened)
            return opened
        } catch is MasterKeyCoordinatorError {
            throw MasterKeyCoordinatorError.malformedRecoveryData
        } catch {
            throw MasterKeyCoordinatorError.malformedRecoveryData
        }
    }

    private static func validateKeySize(_ key: Data) throws {
        guard key.count == 32 else {
            throw MasterKeyCoordinatorError.invalidKeySize(key.count)
        }
    }
}

public struct WrappedMasterKeySet: Codable, Equatable, Sendable {
    public let local: WrappedMasterKey?
    public let recovery: WrappedMasterKey?

    public init(local: WrappedMasterKey?, recovery: WrappedMasterKey?) {
        self.local = local
        self.recovery = recovery
    }
}

public protocol WrappedMasterKeyStoring: Sendable {
    func loadWrappedMasterKeySet() async throws -> WrappedMasterKeySet?
    func saveWrappedMasterKeySet(_ wrapped: WrappedMasterKeySet) async throws
}

public struct MasterKeyCoordinator: Sendable {
    private let deviceKeyStore: any DeviceKeyStoring
    private let recoveryKeyStore: any RecoveryKeyStoring
    private let wrappedStore: any WrappedMasterKeyStoring
    private let randomMasterKey: @Sendable () throws -> Data

    public init(
        deviceKeyStore: any DeviceKeyStoring = DeviceKeyStore(),
        recoveryKeyStore: any RecoveryKeyStoring = KeychainRecoveryKeyStore(),
        wrappedStore: any WrappedMasterKeyStoring,
        randomMasterKey: @escaping @Sendable () throws -> Data = {
            try Self.generateRandomKey()
        }
    ) {
        self.deviceKeyStore = deviceKeyStore
        self.recoveryKeyStore = recoveryKeyStore
        self.wrappedStore = wrappedStore
        self.randomMasterKey = randomMasterKey
    }

    public func unlockState() async throws -> VaultUnlockState {
        guard let wrapped = try await wrappedStore.loadWrappedMasterKeySet() else {
            return .ready
        }
        if wrapped.local != nil {
            return .authenticationRequired
        }
        if wrapped.recovery != nil {
            return .recoveryRequired
        }
        return .recoveryUnavailable
    }

    public func unlock(reason: String) async throws -> Data {
        guard let wrapped = try await wrappedStore.loadWrappedMasterKeySet() else {
            return try await createNewVault(reason: reason)
        }

        guard let local = wrapped.local else {
            throw MasterKeyCoordinatorError.recoveryUnavailable
        }

        let localKey = try await validatedDeviceKey(reason: reason)
        do {
            return try local.open(using: localKey)
        } catch {
            throw MasterKeyCoordinatorError.integrityFailed
        }
    }

    public func recover(reason: String) async throws -> Data {
        guard try await recoveryKeyStore.supportsRequiredKeychainControls() else {
            throw MasterKeyCoordinatorError.unsupportedRequiredKeychainControls
        }
        guard let wrapped = try await wrappedStore.loadWrappedMasterKeySet() else {
            throw MasterKeyCoordinatorError.missingWrappedMasterKey
        }
        guard let recoveryWrapper = wrapped.recovery else {
            throw MasterKeyCoordinatorError.recoveryUnavailable
        }
        guard let recoveryKey = try await recoveryKeyStore.loadRecoveryKeyData() else {
            throw MasterKeyCoordinatorError.recoveryUnavailable
        }
        try validateKeySize(recoveryKey)

        let masterKey = try recoveryWrapper.open(using: recoveryKey)
        let localKey = try await validatedDeviceKey(reason: reason)
        let newLocalWrapper = try WrappedMasterKey.seal(masterKey, using: localKey)
        try await wrappedStore.saveWrappedMasterKeySet(WrappedMasterKeySet(
            local: newLocalWrapper,
            recovery: wrapped.recovery
        ))
        return masterKey
    }

    private func createNewVault(reason: String) async throws -> Data {
        guard try await recoveryKeyStore.supportsRequiredKeychainControls() else {
            throw MasterKeyCoordinatorError.unsupportedRequiredKeychainControls
        }

        let masterKey = try randomMasterKey()
        try validateKeySize(masterKey)
        let localKey = try await validatedDeviceKey(reason: reason)
        let recoveryKey = try await recoveryKeyStore.loadOrCreateRecoveryKeyData()
        try validateKeySize(recoveryKey)

        let wrapped = try WrappedMasterKeySet(
            local: .seal(masterKey, using: localKey),
            recovery: .seal(masterKey, using: recoveryKey)
        )
        try await wrappedStore.saveWrappedMasterKeySet(wrapped)
        return masterKey
    }

    private func validatedDeviceKey(reason: String) async throws -> Data {
        let key = try await deviceKeyStore.deviceKey(reason: reason)
        try validateKeySize(key)
        return key
    }

    private func validateKeySize(_ key: Data) throws {
        guard key.count == 32 else {
            throw MasterKeyCoordinatorError.invalidKeySize(key.count)
        }
    }

    public static func generateRandomKey() throws -> Data {
        var data = Data(count: 32)
        let status = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }

            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw MasterKeyCoordinatorError.randomGenerationFailed(status)
        }
        return data
    }
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
