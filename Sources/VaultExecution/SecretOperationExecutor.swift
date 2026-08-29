import Foundation
import VaultAuthorization
import VaultCore

public enum SecretOperationExecutionError: Error, Equatable, Sendable {
    case unavailable
    case unsupportedAction
    case missingSecretReference
    case invalidSecretUTF8
    case invalidParameter
    case processFailed
    case outputQuarantined
    case redirectRequiresReview
}

public enum SecretOperationExecutionCapability: String, Codable, Equatable, Sendable {
    case supported
    case unavailable
}

public enum SecretOperationStage: String, Codable, Equatable, Sendable {
    case frameRead = "FRAME_READ"
    case frameDecode = "FRAME_DECODE"
    case argumentValidation = "ARGUMENT_VALIDATION"
    case authentication = "AUTHENTICATION"
    case timeout = "TIMEOUT"
    case sshWrapper = "SSH_WRAPPER"
    case remoteCommand = "REMOTE_COMMAND"
}

/// The only result shape returned from an Agent secret action.  It contains
/// sanitized output and never contains a resolved secret value.
public struct SecretOperationOutput: Codable, Equatable, Sendable {
    public let status: String
    public let exitCode: Int32?
    public let stage: SecretOperationStage?
    public let stdout: String?
    public let stderr: String?
    public let httpStatus: Int?
    public let contentType: String?
    public let bodyPreview: String?
    public let rowCount: Int?
    public let rowsPreview: String?
    public let listingPreview: String?
    public let localPath: String?
    public let remotePath: String?
    public let redacted: Bool

    public init(
        status: String,
        exitCode: Int32? = nil,
        stage: SecretOperationStage? = nil,
        stdout: String? = nil,
        stderr: String? = nil,
        httpStatus: Int? = nil,
        contentType: String? = nil,
        bodyPreview: String? = nil,
        rowCount: Int? = nil,
        rowsPreview: String? = nil,
        listingPreview: String? = nil,
        localPath: String? = nil,
        remotePath: String? = nil,
        redacted: Bool = true
    ) {
        self.status = status
        self.exitCode = exitCode
        self.stage = stage
        self.stdout = stdout
        self.stderr = stderr
        self.httpStatus = httpStatus
        self.contentType = contentType
        self.bodyPreview = bodyPreview
        self.rowCount = rowCount
        self.rowsPreview = rowsPreview
        self.listingPreview = listingPreview
        self.localPath = localPath
        self.remotePath = remotePath
        self.redacted = redacted
    }
}

private enum SSHWrapperExitCode {
    static let frameRead: Int32 = 121
    static let frameDecode: Int32 = 122
    static let argumentValidation: Int32 = 123
    static let timedOut: Int32 = 124
    static let wrapperFailed: Int32 = 125
    static let authenticationFailed: Int32 = 126
}

public protocol SecretOperationExecuting: Sendable {
    /// A side-effect-free capability check. It must not resolve a secret or
    /// perform any network/process operation. The service uses it before
    /// device-owner approval so an unavailable runner cannot prime a lease.
    func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput
}

public extension SecretOperationExecuting {
    /// Preserve the protocol for purpose-built test or future executors that
    /// are known to support every descriptor they receive.
    func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        .supported
    }
}

/// Runs only purpose-built actions.  It intentionally has no generic command
/// path that accepts a secret as a CLI argument, environment variable, URL
/// query, or log field.
public struct LocalSecretOperationExecutor: SecretOperationExecuting {
    private static let expectExecutablePath = "/usr/bin/expect"
    private let processRunner: any ProcessRunning
    private let outputSanitizer: OutputSanitizer
    private let timeout: Duration
    private let outputLimitBytes: Int

    public init(
        processRunner: any ProcessRunning = FoundationProcessRunner(),
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        timeout: Duration = .seconds(30),
        outputLimitBytes: Int = 1_048_576
    ) {
        self.processRunner = processRunner
        self.outputSanitizer = outputSanitizer
        self.timeout = timeout
        self.outputLimitBytes = outputLimitBytes
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        switch descriptor.actionType {
        case .sshCommand:
            return try await executeSSH(descriptor, resolve: resolve)
        case .httpRequest, .apiRequest:
            return try await executeHTTP(descriptor, resolve: resolve)
        case .sftpTransfer, .databaseQuery, .browserLogin, .localAppFill:
            throw SecretOperationExecutionError.unavailable
        default:
            throw SecretOperationExecutionError.unsupportedAction
        }
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        switch descriptor.actionType {
        case .sshCommand:
            if !FileManager.default.isExecutableFile(atPath: Self.expectExecutablePath) {
                return .unavailable
            }
            return .supported
        case .httpRequest, .apiRequest:
            return .supported
        case .sftpTransfer, .databaseQuery, .browserLogin, .localAppFill:
            return .unavailable
        default:
            return .unavailable
        }
    }

    private func executeSSH(
        _ descriptor: SecretOperationDescriptor,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard let host = descriptor.destination,
              let command = descriptor.command,
              let passwordReference = reference(for: "passwordRef", in: descriptor)
        else {
            throw SecretOperationExecutionError.invalidParameter
        }

        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        // OpenSSH requires the login name in its own argv. A username stored
        // as secret:// would therefore cross the SVLT boundary into a child
        // process command line. Keep that invariant explicit instead of
        // pretending the outer Expect stdin transport protects the child.
        guard reference(for: "usernameRef", in: descriptor) == nil else {
            throw SecretOperationExecutionError.invalidParameter
        }

        let username: String
        if let plainUsername = descriptor.parameters["username"],
           Self.isSafeSSHUsername(plainUsername) {
            username = plainUsername
        } else {
            throw SecretOperationExecutionError.invalidParameter
        }

        let passwordData = try await resolve(passwordReference)
        secretBuffers.append(passwordData)
        guard let password = String(data: passwordData, encoding: .utf8), !password.isEmpty else {
            throw SecretOperationExecutionError.invalidSecretUTF8
        }

        let port = descriptor.port ?? 22
        let operationTimeout = try timeout(for: descriptor)
        let script = Self.expectSSHScript()
        // `expect -c` executes only the static script. Every runtime field is
        // hex framing on stdin, so Tcl never reads argv and no
        // secret reaches the Expect command line or environment.
        let result: ProcessResult
        do {
            result = try await processRunner.run(
                ProcessInvocation(
                    executable: Self.expectExecutablePath,
                    arguments: ["-c", script]
                ),
                stdin: Self.expectSSHInput(
                    host: host,
                    port: port,
                    command: command,
                    username: username,
                    password: password,
                    timeoutSeconds: Self.expectTimeoutSeconds(for: operationTimeout)
                ),
                timeout: operationTimeout,
                outputLimitBytes: outputLimitBytes
            )
        } catch ProcessRunError.timedOut {
            return SecretOperationOutput(status: "TIMED_OUT", stage: .timeout, redacted: true)
        }

        switch outputSanitizer.sanitize(result, secrets: secretBuffers) {
        case .quarantined:
            throw SecretOperationExecutionError.outputQuarantined
        case let .sanitized(result):
            guard let stdout = String(data: result.stdout, encoding: .utf8),
                  let stderr = String(data: result.stderr, encoding: .utf8)
            else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            let outcome = Self.sshOutcome(for: result.exitCode)
            return SecretOperationOutput(
                status: outcome.status,
                exitCode: result.exitCode,
                stage: outcome.stage,
                stdout: stdout,
                stderr: stderr,
                redacted: true
            )
        }
    }

    private func executeHTTP(
        _ descriptor: SecretOperationDescriptor,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard let rawURL = descriptor.url,
              let url = URL(string: rawURL),
              url.user == nil,
              url.password == nil
        else {
            throw SecretOperationExecutionError.invalidParameter
        }

        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        let operationTimeout = try timeout(for: descriptor)
        var request = URLRequest(url: url)
        request.httpMethod = (descriptor.httpMethod ?? "GET").uppercased()
        request.timeoutInterval = operationTimeout.timeInterval
        if let body = descriptor.parameters["body"] {
            guard !body.contains("secret://") else {
                throw SecretOperationExecutionError.invalidParameter
            }
            request.httpBody = Data(body.utf8)
        }

        if descriptor.actionType == .httpRequest,
           let passwordReference = reference(for: "passwordRef", in: descriptor) {
            let passwordData = try await resolve(passwordReference)
            secretBuffers.append(passwordData)
            let username: String
            if let usernameReference = reference(for: "usernameRef", in: descriptor) {
                let usernameData = try await resolve(usernameReference)
                secretBuffers.append(usernameData)
                guard let resolvedUsername = String(data: usernameData, encoding: .utf8) else {
                    throw SecretOperationExecutionError.invalidSecretUTF8
                }
                username = resolvedUsername
            } else if let plainUsername = descriptor.parameters["username"], !plainUsername.isEmpty {
                username = plainUsername
            } else {
                throw SecretOperationExecutionError.invalidParameter
            }
            guard let password = String(data: passwordData, encoding: .utf8)
            else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            let basicCredentials = "\(username):\(password)"
            secretBuffers.append(Data(basicCredentials.utf8))
            let basic = Data(basicCredentials.utf8).base64EncodedString()
            secretBuffers.append(Data("Basic \(basic)".utf8))
            request.setValue("Basic \(basic)", forHTTPHeaderField: "Authorization")
        } else if descriptor.actionType == .apiRequest,
                  let tokenReference = reference(for: "tokenRef", in: descriptor) {
            let tokenData = try await resolve(tokenReference)
            secretBuffers.append(tokenData)
            guard let token = String(data: tokenData, encoding: .utf8) else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            let headerName = descriptor.parameters["headerName"] ?? "Authorization"
            let scheme = descriptor.parameters["headerScheme"] ?? "Bearer"
            let headerValue = scheme.isEmpty ? token : "\(scheme) \(token)"
            secretBuffers.append(Data(headerValue.utf8))
            request.setValue(headerValue, forHTTPHeaderField: headerName)
        }

        let session = URLSession(
            configuration: .ephemeral,
            delegate: NoRedirectURLSessionDelegate(),
            delegateQueue: nil
        )
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SecretOperationExecutionError.processFailed
        }

        guard data.count <= outputLimitBytes else {
            throw SecretOperationExecutionError.outputQuarantined
        }

        if (300...399).contains(httpResponse.statusCode) {
            // We intentionally stop before sending the credential to a new
            // host.  The caller must submit a new descriptor so the local
            // engine can evaluate the new destination and, if appropriate,
            // request a fresh approval.
            throw SecretOperationExecutionError.redirectRequiresReview
        }

        let sanitized = try sanitize(
            ProcessResult(exitCode: 0, stdout: data, stderr: Data()),
            secrets: secretBuffers
        )
        guard case let .sanitized(result) = sanitized,
              let body = String(data: result.stdout, encoding: .utf8)
        else {
            throw SecretOperationExecutionError.outputQuarantined
        }

        let bodyPreview = descriptor.parameters["includeBodyPreview"] == "true" ? body : nil
        return SecretOperationOutput(
            status: "COMPLETED",
            httpStatus: httpResponse.statusCode,
            contentType: httpResponse.value(forHTTPHeaderField: "Content-Type"),
            bodyPreview: bodyPreview.map { String($0.prefix(16_384)) },
            redacted: true
        )
    }

    private func sanitize(
        _ result: ProcessResult,
        secrets: [Data]
    ) throws -> SanitizedProcessResult {
        outputSanitizer.sanitize(result, secrets: secrets)
    }

    private func reference(
        for parameter: String,
        in descriptor: SecretOperationDescriptor
    ) -> SecretReference? {
        guard let rawReference = descriptor.parameters[parameter] else {
            return nil
        }
        return descriptor.secretReferences.first { $0.description == rawReference }
    }

    private func timeout(for descriptor: SecretOperationDescriptor) throws -> Duration {
        guard let rawTimeout = descriptor.parameters["timeoutMs"] else {
            return timeout
        }
        guard let milliseconds = Int64(rawTimeout),
              (100...30_000).contains(milliseconds)
        else {
            throw SecretOperationExecutionError.invalidParameter
        }
        return .milliseconds(milliseconds)
    }

    static func expectSSHInput(
        host: String,
        port: Int,
        command: String,
        username: String,
        password: String,
        timeoutSeconds: Int
    ) -> Data {
        let fields = [
            host,
            String(port),
            command,
            username,
            password,
            String(timeoutSeconds)
        ]
        return Data(fields.map {
            hexEncoded(Data($0.utf8))
        }.joined(separator: "\n").appending("\n").utf8)
    }

    static func expectTimeoutSeconds(for timeout: Duration) -> Int {
        max(1, Int(timeout.timeInterval.rounded(.up)))
    }

    private static func hexEncoded(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func sshOutcome(for exitCode: Int32) -> (status: String, stage: SecretOperationStage?) {
        switch exitCode {
        case 0:
            return ("COMPLETED", nil)
        case SSHWrapperExitCode.frameRead:
            return ("WRAPPER_FAILED", .frameRead)
        case SSHWrapperExitCode.frameDecode:
            return ("WRAPPER_FAILED", .frameDecode)
        case SSHWrapperExitCode.argumentValidation:
            return ("WRAPPER_FAILED", .argumentValidation)
        case SSHWrapperExitCode.timedOut:
            return ("TIMED_OUT", .timeout)
        case SSHWrapperExitCode.wrapperFailed:
            return ("WRAPPER_FAILED", .sshWrapper)
        case SSHWrapperExitCode.authenticationFailed:
            return ("AUTH_FAILED", .authentication)
        default:
            return ("FAILED", .remoteCommand)
        }
    }

    private static func isSafeSSHUsername(_ username: String) -> Bool {
        let bytes = username.utf8
        guard (1...256).contains(bytes.count),
              let first = bytes.first,
              (first >= 48 && first <= 57) || (first >= 65 && first <= 90) || (first >= 97 && first <= 122)
        else {
            return false
        }
        return bytes.allSatisfy { byte in
            (byte >= 48 && byte <= 57)
                || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || byte == 46 || byte == 95 || byte == 45
        }
    }

    static func expectSSHScript() -> String {
        return """
        proc readHexField {} {
            if {[gets stdin encoded] < 0 || $encoded eq ""} { exit \(SSHWrapperExitCode.frameRead) }
            if {[regexp {[^0-9A-Fa-f]} $encoded]} { exit \(SSHWrapperExitCode.frameDecode) }
            if {([string length $encoded] % 2) != 0} { exit \(SSHWrapperExitCode.frameDecode) }
            if {[catch {binary format H* $encoded} value]} { exit \(SSHWrapperExitCode.frameDecode) }
            return $value
        }
        set host [readHexField]
        set port [readHexField]
        set command [readHexField]
        set username [readHexField]
        set password [readHexField]
        set timeoutSeconds [readHexField]
        if {$host eq "" || $command eq "" || $username eq "" || $password eq ""} { exit \(SSHWrapperExitCode.argumentValidation) }
        if {![string is integer -strict $port] || $port < 1 || $port > 65535} { exit \(SSHWrapperExitCode.argumentValidation) }
        if {![string is integer -strict $timeoutSeconds] || $timeoutSeconds < 1 || $timeoutSeconds > 30} { exit \(SSHWrapperExitCode.argumentValidation) }
        set timeout $timeoutSeconds
        log_user 1
        if {[catch {spawn /usr/bin/ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=$timeoutSeconds -p $port -- "$username@$host" $command}]} {
            exit \(SSHWrapperExitCode.wrapperFailed)
        }
        expect {
            -re "(?i)permission denied" { exit \(SSHWrapperExitCode.authenticationFailed) }
            -re "(?i)(password|passphrase).*:" { send -- "$password\\r" }
            eof {}
            timeout { exit \(SSHWrapperExitCode.timedOut) }
        }
        # After the one authentication response, recognize authentication
        # failure but never send the credential a second time. A remote command
        # that prints "password:" must not receive the credential again.
        expect {
            -re "(?i)permission denied" { exit \(SSHWrapperExitCode.authenticationFailed) }
            -re "(?i)(password|passphrase).*:" { exit \(SSHWrapperExitCode.authenticationFailed) }
            eof {}
            timeout { exit \(SSHWrapperExitCode.timedOut) }
        }
        if {[catch {wait} result]} { exit \(SSHWrapperExitCode.wrapperFailed) }
        exit [lindex $result 3]
        """
    }
}

private final class NoRedirectURLSessionDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
