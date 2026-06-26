import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore

public protocol ExecutionAuthorizing: Sendable {
    func consumeAuthorization(for risk: RiskClass) async -> Bool
}

extension AuthorizationSession: ExecutionAuthorizing {}

public protocol SecretResolving: Sendable {
    func resolve(_ reference: SecretReference, named name: String) async throws -> Data
}

public enum ExecutionBrokerError: Error, Equatable, Sendable {
    case authorizationRequired
    case invalidSecretUTF8(String)
    case sanitizedOutputInvalidUTF8
}

public enum SanitizedExecutionResult: Equatable, Sendable {
    case completed(exitCode: Int32, stdout: String, stderr: String)
    case quarantined(reason: OutputQuarantineReason)
}

public struct VaultSecretResolver: SecretResolving {
    private let recordStore: any RecordStore
    private let deviceKeyStore: any DeviceKeyStoring
    private let cipher: VaultCipher
    private let authenticationReason: String

    public init(
        recordStore: any RecordStore,
        deviceKeyStore: any DeviceKeyStoring,
        cipher: VaultCipher = VaultCipher(),
        authenticationReason: String = "Resolve a secret for approved local execution"
    ) {
        self.recordStore = recordStore
        self.deviceKeyStore = deviceKeyStore
        self.cipher = cipher
        self.authenticationReason = authenticationReason
    }

    public func resolve(_ reference: SecretReference, named name: String) async throws -> Data {
        let record = try await recordStore.latest(id: reference.id)
        let deviceKey = try await deviceKeyStore.deviceKey(reason: authenticationReason)

        return try cipher.decrypt(record, masterKey: SymmetricKey(data: deviceKey))
    }
}

public struct ExecutionBroker: Sendable {
    private let authorizer: any ExecutionAuthorizing
    private let secretResolver: any SecretResolving
    private let processRunner: any ProcessRunning
    private let sanitizer: OutputSanitizer
    private let validator: TemplateValidator
    private let timeout: Duration
    private let outputLimitBytes: Int

    public init(
        authorizer: any ExecutionAuthorizing,
        secretResolver: any SecretResolving,
        processRunner: any ProcessRunning,
        sanitizer: OutputSanitizer = OutputSanitizer(),
        validator: TemplateValidator = TemplateValidator(),
        timeout: Duration = .seconds(30),
        outputLimitBytes: Int = 1_048_576
    ) {
        self.authorizer = authorizer
        self.secretResolver = secretResolver
        self.processRunner = processRunner
        self.sanitizer = sanitizer
        self.validator = validator
        self.timeout = timeout
        self.outputLimitBytes = outputLimitBytes
    }

    public func validateAndExecute(
        _ request: ExecutionRequest,
        against template: ExecutionTemplate
    ) async throws -> SanitizedExecutionResult {
        let validated = try validator.validate(request, against: template)
        return try await execute(validated)
    }

    public func execute(_ execution: ValidatedExecution) async throws -> SanitizedExecutionResult {
        try Task.checkCancellation()

        guard await authorizer.consumeAuthorization(for: execution.risk) else {
            throw ExecutionBrokerError.authorizationRequired
        }

        try Task.checkCancellation()

        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        var invocationArguments: [String] = []
        for argument in execution.arguments {
            switch argument {
            case let .literal(value):
                invocationArguments.append(value)
            case let .value(_, value):
                invocationArguments.append(value)
            case let .secret(name, reference):
                let secret = try await secretResolver.resolve(reference, named: name)
                secretBuffers.append(secret)

                guard let secretString = String(data: secret, encoding: .utf8) else {
                    throw ExecutionBrokerError.invalidSecretUTF8(name)
                }

                invocationArguments.append(secretString)
            }

            try Task.checkCancellation()
        }

        let processResult = try await processRunner.run(
            ProcessInvocation(
                executable: execution.executable,
                arguments: invocationArguments
            ),
            stdin: Data(),
            timeout: timeout,
            outputLimitBytes: outputLimitBytes
        )

        switch sanitizer.sanitize(processResult, secrets: secretBuffers) {
        case let .quarantined(reason):
            return .quarantined(reason: reason)
        case let .sanitized(result):
            guard let stdout = String(data: result.stdout, encoding: .utf8),
                  let stderr = String(data: result.stderr, encoding: .utf8) else {
                throw ExecutionBrokerError.sanitizedOutputInvalidUTF8
            }

            return .completed(
                exitCode: result.exitCode,
                stdout: stdout,
                stderr: stderr
            )
        }
    }
}
