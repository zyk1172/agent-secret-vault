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
