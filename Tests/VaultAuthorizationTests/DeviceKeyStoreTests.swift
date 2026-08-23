import Foundation
import LocalAuthentication
import Testing
@testable import VaultAuthorization

@Test func deviceKeyStoreReturnsKeyAfterSuccessfulAuthentication() async throws {
    let expectedKey = Data(repeating: 0xA5, count: 32)
    let authenticator = FakeBiometricAuthorizer(result: .success(()))
    let materialStore = FakeDeviceKeyMaterialStore(result: .success(expectedKey))
    let store = DeviceKeyStore(authenticator: authenticator, materialStore: materialStore)

    let actualKey = try await store.deviceKey(reason: "Open vault")

    #expect(actualKey == expectedKey)
    #expect(await authenticator.evaluatedReasons == ["Open vault"])
    #expect(await materialStore.loadCount == 1)
}

@Test func deviceKeyStorePropagatesUserCancellationWithoutLoadingKey() async throws {
    let authenticator = FakeBiometricAuthorizer(result: .failure(BiometricAuthorizationError.cancelled))
    let materialStore = FakeDeviceKeyMaterialStore(result: .success(Data(repeating: 0x11, count: 32)))
    let store = DeviceKeyStore(authenticator: authenticator, materialStore: materialStore)

    await expectBiometricError(.cancelled) {
        _ = try await store.deviceKey(reason: "Send externally")
    }

    #expect(await materialStore.loadCount == 0)
}

@Test func deviceKeyStorePropagatesBiometricLockout() async throws {
    let authenticator = FakeBiometricAuthorizer(result: .failure(BiometricAuthorizationError.lockout))
    let materialStore = FakeDeviceKeyMaterialStore(result: .success(Data(repeating: 0x22, count: 32)))
    let store = DeviceKeyStore(authenticator: authenticator, materialStore: materialStore)

    await expectBiometricError(.lockout) {
        _ = try await store.deviceKey(reason: "Open vault")
    }

    #expect(await materialStore.loadCount == 0)
}

@Test func deviceKeyStorePropagatesUnavailableBiometrics() async throws {
    let authenticator = FakeBiometricAuthorizer(result: .failure(BiometricAuthorizationError.unavailable))
    let materialStore = FakeDeviceKeyMaterialStore(result: .success(Data(repeating: 0x33, count: 32)))
    let store = DeviceKeyStore(authenticator: authenticator, materialStore: materialStore)

    await expectBiometricError(.unavailable) {
        _ = try await store.deviceKey(reason: "Open vault")
    }

    #expect(await materialStore.loadCount == 0)
}

@Test func localAuthenticatorUsesSystemPasswordFallbackPolicy() {
    let authenticator = LocalAuthenticator()

    #expect(authenticator.policy == .deviceOwnerAuthentication)
}

@Test func localAuthenticatorMapsUserCancellation() async {
    let authenticator = LocalAuthenticator(
        evaluator: FakeLocalAuthenticationEvaluator(result: .laError(LAError.Code.userCancel.rawValue))
    )

    await expectBiometricError(.cancelled) {
        try await authenticator.evaluate(reason: "Open vault")
    }
}

@Test func localAuthenticatorMapsBiometricLockout() async {
    let authenticator = LocalAuthenticator(
        evaluator: FakeLocalAuthenticationEvaluator(result: .laError(LAError.Code.biometryLockout.rawValue))
    )

    await expectBiometricError(.lockout) {
        try await authenticator.evaluate(reason: "Open vault")
    }
}

@Test func localAuthenticatorMapsUnavailableBiometrics() async {
    let authenticator = LocalAuthenticator(
        evaluator: FakeLocalAuthenticationEvaluator(result: .laError(LAError.Code.biometryNotAvailable.rawValue))
    )

    await expectBiometricError(.unavailable) {
        try await authenticator.evaluate(reason: "Open vault")
    }
}

@Test func deviceKeyStorePassesOneEvaluatedContextIntoKeychainQuery() async throws {
    let expectedKey = Data(repeating: 0x4A, count: 32)
    let keychain = FakeKeychainClient(
        copyResults: [(errSecSuccess, expectedKey)],
        addResults: []
    )
    let materialStore = KeychainDeviceKeyMaterialStore(
        service: "com.agent-secret-vault.context-test",
        account: "device-wrapping-key",
        keychain: keychain,
        randomKeyData: { expectedKey }
    )
    let evaluator = CountingLocalAuthenticationEvaluator()
    let store = DeviceKeyStore(
        authenticator: LocalAuthenticator(evaluator: evaluator),
        materialStore: materialStore
    )

    #expect(try await store.deviceKey(reason: "one operation") == expectedKey)
    #expect(await evaluator.count == 1)
    #expect(keychain.copyQueries.count == 2)
    #expect(keychain.copyQueries[0][kSecUseAuthenticationContext as String] != nil)
    #expect(keychain.copyQueries[1][kSecUseAuthenticationContext as String] != nil)
}

@Test func existingAccessibleOnlyKeychainItemFailsClosed() async {
    let keychain = FakeKeychainClient(
        copyResults: [(errSecSuccess, Data(repeating: 0x55, count: 32))],
        addResults: [],
        attributeResults: [(errSecSuccess, [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly])]
    )
    let store = KeychainDeviceKeyMaterialStore(
        service: "com.agent-secret-vault.weak-item-test",
        account: "device-wrapping-key",
        keychain: keychain,
        randomKeyData: { Data(repeating: 0x55, count: 32) }
    )

    await #expect(throws: DeviceKeyStoreError.unsupportedRequiredKeychainControls) {
        _ = try await store.loadOrCreateDeviceKeyData()
    }
}

@Test func keychainMaterialStoreFailsClosedWhenAccessControlIsUnavailable() async {
    let expectedKey = Data(repeating: 0x44, count: 32)
    let keychain = FakeKeychainClient(
        copyResults: [(errSecItemNotFound, nil)],
        addResults: [errSecMissingEntitlement]
    )
    let store = KeychainDeviceKeyMaterialStore(
        service: "com.agent-secret-vault.test",
        account: "device-wrapping-key",
        keychain: keychain,
        randomKeyData: { expectedKey }
    )

    await #expect(throws: DeviceKeyStoreError.unsupportedRequiredKeychainControls) {
        _ = try await store.loadOrCreateDeviceKeyData()
    }
    #expect(keychain.addedAttributes.count == 1)
    #expect(keychain.addedAttributes[0][kSecAttrAccessControl as String] != nil)
}

@Test func recoveryKeyStoreFailsClosedWhenSynchronizableProtectionIsUnavailable() async {
    let expectedKey = Data(repeating: 0x45, count: 32)
    let keychain = FakeKeychainClient(
        copyResults: [(errSecItemNotFound, nil)],
        addResults: [errSecMissingEntitlement]
    )
    let store = KeychainRecoveryKeyStore(
        service: "com.agent-secret-vault.test.recovery",
        account: "icloud-recovery-wrapping-key",
        keychain: keychain,
        randomKeyData: { expectedKey }
    )

    await #expect(throws: RecoveryKeyStoreError.unsupportedRequiredKeychainControls) {
        _ = try await store.loadOrCreateRecoveryKeyData()
    }
    #expect(keychain.addedAttributes.count == 1)
    #expect((keychain.addedAttributes[0][kSecAttrSynchronizable as String] as? Bool) == true)
    #expect(keychain.addedAttributes[0][kSecAttrAccessControl as String] != nil)
}

@Test func auditKeyStoreUsesNoUserPresenceProtection() async throws {
    let expectedKey = Data(repeating: 0x49, count: 32)
    let keychain = FakeKeychainClient(
        copyResults: [(errSecItemNotFound, nil)],
        addResults: [errSecSuccess]
    )
    let store = KeychainAuditKeyStore(
        service: "com.agent-secret-vault.audit-test",
        account: "audit-encryption-key",
        keychain: keychain,
        randomKeyData: { expectedKey }
    )

    #expect(try await store.loadOrCreateAuditKeyData() == expectedKey)
    #expect(keychain.addedAttributes.count == 1)
    #expect(keychain.addedAttributes[0][kSecAttrAccessControl as String] == nil)
    #expect((keychain.addedAttributes[0][kSecAttrAccessible as String] as? String) == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String))
}

@Test func recoveryKeyStoreDoesNotUseAWeakerLocalFallback() async {
    let keychain = FakeKeychainClient(
        copyResults: [(errSecMissingEntitlement, nil)],
        addResults: []
    )
    let store = KeychainRecoveryKeyStore(
        service: "com.agent-secret-vault.test.recovery",
        account: "icloud-recovery-wrapping-key",
        keychain: keychain,
        randomKeyData: {
            Issue.record("Recovery key must fail closed before generation.")
            return Data(repeating: 0x00, count: 32)
        }
    )

    await #expect(throws: RecoveryKeyStoreError.unsupportedRequiredKeychainControls) {
        _ = try await store.loadRecoveryKeyData()
    }
    #expect(keychain.addedAttributes.isEmpty)
}

private func expectBiometricError(
    _ expected: BiometricAuthorizationError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but operation succeeded.")
    } catch let error as BiometricAuthorizationError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private actor FakeBiometricAuthorizer: BiometricAuthorizing {
    private let result: Result<Void, Error>
    private var storedReasons: [String] = []

    init(result: Result<Void, Error>) {
        self.result = result
    }

    var evaluatedReasons: [String] {
        storedReasons
    }

    func evaluate(reason: String) async throws {
        storedReasons.append(reason)
        try result.get()
    }
}

private actor FakeDeviceKeyMaterialStore: DeviceKeyMaterialStoring {
    private let result: Result<Data, Error>
    private var storedLoadCount = 0

    init(result: Result<Data, Error>) {
        self.result = result
    }

    var loadCount: Int {
        storedLoadCount
    }

    func loadOrCreateDeviceKeyData() async throws -> Data {
        storedLoadCount += 1
        return try result.get()
    }
}

private enum FakeLocalAuthenticationResult: Sendable {
    case success(Bool)
    case laError(Int)
}

private actor CountingLocalAuthenticationEvaluator: LocalAuthenticationEvaluating {
    private(set) var count = 0

    func evaluate(policy: LAPolicy, localizedReason: String) async throws -> Bool {
        count += 1
        return true
    }
}

private struct FakeLocalAuthenticationEvaluator: LocalAuthenticationEvaluating {
    let result: FakeLocalAuthenticationResult

    func evaluate(policy: LAPolicy, localizedReason: String) async throws -> Bool {
        switch result {
        case let .success(success):
            return success
        case let .laError(code):
            throw NSError(domain: LAError.errorDomain, code: code)
        }
    }
}

private final class FakeKeychainClient: KeychainClient, @unchecked Sendable {
    private var copyResults: [(OSStatus, Data?)]
    private var addResults: [OSStatus]
    private var attributeResults: [(OSStatus, [String: Any]?)]
    private(set) var addedAttributes: [[String: Any]] = []
    private(set) var copyQueries: [[String: Any]] = []

    init(
        copyResults: [(OSStatus, Data?)],
        addResults: [OSStatus],
        attributeResults: [(OSStatus, [String: Any]?)] = []
    ) {
        self.copyResults = copyResults
        self.addResults = addResults
        self.attributeResults = attributeResults
    }

    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        copyQueries.append(query)
        guard !copyResults.isEmpty else {
            return (errSecInteractionNotAllowed, nil)
        }
        return copyResults.removeFirst()
    }

    func copyAttributes(_ query: [String: Any]) -> (status: OSStatus, attributes: [String: Any]?) {
        if attributeResults.isEmpty {
            return (errSecSuccess, [kSecAttrAccessControl as String: NSObject()])
        }
        return attributeResults.removeFirst()
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        addedAttributes.append(attributes)
        return addResults.removeFirst()
    }
}
