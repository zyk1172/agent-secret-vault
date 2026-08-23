import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore
import VaultIPC

public enum VaultDaemonCoreError: Error, Equatable, Sendable {
    case alreadyStarted
    case notStarted
}

public struct VaultDaemonConfiguration: Sendable, Equatable {
    public let vaultRootURL: URL
    public let auditRootURL: URL
    public let ipcConfiguration: UnixSocketServerConfiguration
    public let credentialAuthorizationTTL: TimeInterval
    public let externalSendAuthorizationTTL: TimeInterval
    public let readAuthorizationTTL: TimeInterval?

    public init(
        vaultRootURL: URL,
        auditRootURL: URL,
        ipcConfiguration: UnixSocketServerConfiguration,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        readAuthorizationTTL: TimeInterval? = nil
    ) {
        self.vaultRootURL = vaultRootURL.standardizedFileURL
        self.auditRootURL = auditRootURL.standardizedFileURL
        self.ipcConfiguration = ipcConfiguration
        self.credentialAuthorizationTTL = credentialAuthorizationTTL
        self.externalSendAuthorizationTTL = externalSendAuthorizationTTL
        self.readAuthorizationTTL = readAuthorizationTTL
    }

    public static func `default`() throws -> VaultDaemonConfiguration {
        let appSupport = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let applicationRoot = appSupport.appendingPathComponent(
            "AgentSecretVault",
            isDirectory: true
        )
        return VaultDaemonConfiguration(
            vaultRootURL: applicationRoot.appendingPathComponent("Vault", isDirectory: true),
            auditRootURL: applicationRoot.appendingPathComponent("Audit", isDirectory: true),
            ipcConfiguration: try .defaultConfiguration()
        )
    }
}

/// The only owner of VaultAppServices and the Unix socket in production. The
/// GUI application is a client and never constructs this core.
public actor VaultDaemonCore {
    public let configuration: VaultDaemonConfiguration

    private let controller: AppIPCController
    private let services: VaultAppServices
    private let protectionKeyStore: AppProtectionKeyStore
    private let lifecycleMonitor: VaultDaemonLifecycleMonitor
    private var started = false

    public init(configuration: VaultDaemonConfiguration? = nil) throws {
        let configuration = try configuration ?? VaultDaemonConfiguration.default()
        self.configuration = configuration

        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: configuration.vaultRootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.createDirectory(
            at: configuration.auditRootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: configuration.vaultRootURL.path
        )
        try fileManager.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: configuration.auditRootURL.path
        )

        let recordStore = FileRecordStore(baseDirectory: configuration.vaultRootURL)
        let deviceKeyStore = DeviceKeyStore()
        let protectionKeyStore = AppProtectionKeyStore(
            deviceKeyStore: deviceKeyStore,
            credentialTTL: configuration.credentialAuthorizationTTL,
            externalSendTTL: configuration.externalSendAuthorizationTTL
        )
        let wrappedMasterKeyStore = FileWrappedMasterKeyStore(
            fileURL: configuration.vaultRootURL
                .appendingPathComponent(".agent-secret-vault", isDirectory: true)
                .appendingPathComponent("master-key.json")
        )
        let masterKeyCoordinator = MasterKeyCoordinator(
            deviceKeyStore: deviceKeyStore,
            wrappedStore: wrappedMasterKeyStore
        )

        let unlockUsingWrappingKey: @Sendable (Data, String) async throws -> Data = {
            localWrappingKey,
            reason in
            let hasLegacyRecords = (try? await recordStore.recordIDs().isEmpty) == false
            if try await wrappedMasterKeyStore.loadWrappedMasterKeySet() == nil,
               hasLegacyRecords {
                return try await masterKeyCoordinator.adoptExistingVault(
                    reason: reason,
                    localWrappingKey: localWrappingKey,
                    existingMasterKey: localWrappingKey
                )
            }
            return try await masterKeyCoordinator.unlock(
                reason: reason,
                localWrappingKey: localWrappingKey
            )
        }

        let masterKeyProvider: @Sendable (SecretPolicy, String) async throws -> SymmetricKey = {
            policy,
            reason in
            let localWrappingKey = try await protectionKeyStore.deviceKey(
                for: policy,
                reason: reason
            )
            return SymmetricKey(
                data: try await unlockUsingWrappingKey(localWrappingKey, reason)
            )
        }
        let freshMasterKeyProvider: @Sendable (SecretPolicy, String) async throws -> SymmetricKey = {
            policy,
            reason in
            let localWrappingKey = try await protectionKeyStore.freshDeviceKey(
                for: policy,
                reason: reason
            )
            return SymmetricKey(
                data: try await unlockUsingWrappingKey(localWrappingKey, reason)
            )
        }

        let encryptor = EncryptSelectionCoordinator(
            recordStore: recordStore,
            selectionReplacer: NoopSelectionReplacer(),
            masterKeyProvider: { policy, reason in
                let key = try await masterKeyProvider(policy, reason)
                return key.withUnsafeBytes { Data($0) }
            }
        )
        let auditKeyStore = KeychainAuditKeyStore()
        let auditLog = EncryptedAuditLog(
            directoryURL: configuration.auditRootURL,
            auditKeyProvider: {
                SymmetricKey(data: try await auditKeyStore.loadOrCreateAuditKeyData())
            }
        )
        let services = VaultAppServices(
            textEncryptor: encryptor,
            activeRoot: configuration.vaultRootURL,
            recordLister: recordStore,
            recordDeleter: recordStore,
            recordResolver: VaultRecordResolver(recordStore: recordStore),
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
            clearProtectedKeyState: {
                await protectionKeyStore.clearAll()
            },
            isUnlockedProvider: {
                await protectionKeyStore.isUnlocked
            },
            revealSessionStore: RevealSessionStore(defaultTTLSeconds: 60),
            revealSessionPresenter: AgentUIRequestNotifier(),
            authorizationSession: AuthorizationSession(
                readTTL: configuration.readAuthorizationTTL,
                credentialTTL: configuration.credentialAuthorizationTTL,
                externalSendTTL: configuration.externalSendAuthorizationTTL
            ),
            credentialAuthorizationTTL: configuration.credentialAuthorizationTTL,
            externalSendAuthorizationTTL: configuration.externalSendAuthorizationTTL,
            auditLog: auditLog
        )
        let server = UnixSocketServer(configuration: configuration.ipcConfiguration)
        let controller = AppIPCController(
            server: server,
            handler: IPCRequestHandler(service: services)
        )
        let lifecycleMonitor = VaultDaemonLifecycleMonitor {
            await protectionKeyStore.clearAll()
            await services.clearRevealSessions()
            await services.invalidateSecurityState()
        }

        self.controller = controller
        self.services = services
        self.protectionKeyStore = protectionKeyStore
        self.lifecycleMonitor = lifecycleMonitor
    }

    public func start() throws {
        guard !started else {
            throw VaultDaemonCoreError.alreadyStarted
        }
        // Deliberately no unlock call here. The first protected request enters
        // the lazy master-key provider and only then asks LocalAuthentication.
        try controller.start()
        lifecycleMonitor.start()
        started = true
    }

    public func stop() async {
        guard started else {
            return
        }
        lifecycleMonitor.stop()
        controller.stop()
        await protectionKeyStore.clearAll()
        await services.clearRevealSessions()
        await services.invalidateSecurityState()
        started = false
    }

    public func status() async -> WorkbenchStatus {
        await services.status()
    }
}

private struct NoopSelectionReplacer: SelectionReplacing {
    func replaceSelection(with text: String) async throws {
        throw NoopSelectionReplacerError.unavailable
    }
}

private enum NoopSelectionReplacerError: Error {
    case unavailable
}
