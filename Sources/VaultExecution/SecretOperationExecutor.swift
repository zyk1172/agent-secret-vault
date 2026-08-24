import Foundation
import VaultAuthorization
import VaultCore

public enum SecretOperationExecutionError: Error, Equatable, Sendable {
    case unsupportedAction
    case missingSecretReference
    case invalidSecretUTF8
    case invalidParameter
    case processFailed
    case outputQuarantined
    case redirectRequiresReview
}

/// The only result shape returned from an Agent secret action.  It contains
/// sanitized output and never contains a resolved secret value.
public struct SecretOperationOutput: Codable, Equatable, Sendable {
    public let status: String
    public let exitCode: Int32?
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

public protocol SecretOperationExecuting: Sendable {
    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput
}

/// Runs only purpose-built actions.  It intentionally has no generic command
/// path that accepts a secret as a CLI argument, environment variable, URL
/// query, or log field.
public struct LocalSecretOperationExecutor: SecretOperationExecuting {
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
            return SecretOperationOutput(status: "ACTION_EXECUTOR_UNAVAILABLE")
        default:
            throw SecretOperationExecutionError.unsupportedAction
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

        let username: String
        if let usernameReference = reference(for: "usernameRef", in: descriptor) {
            let usernameData = try await resolve(usernameReference)
            secretBuffers.append(usernameData)
            guard let value = String(data: usernameData, encoding: .utf8), !value.isEmpty else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            username = value
        } else if let plainUsername = descriptor.parameters["username"], !plainUsername.isEmpty {
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
        let script = Self.expectSSHScript()
        // The expect script is passed as an argument, while secret material is
        // supplied only through the process stdin.  The command line never
        // contains username/password data.
        let result = try await processRunner.run(
            ProcessInvocation(
                executable: "/usr/bin/expect",
                arguments: ["-c", script, "--", host, command, String(port)]
            ),
            stdin: Data(username.utf8) + Data([0x0A]) + Data(password.utf8) + Data([0x0A]),
            timeout: timeout,
            outputLimitBytes: outputLimitBytes
        )

        switch outputSanitizer.sanitize(result, secrets: secretBuffers) {
        case .quarantined:
            throw SecretOperationExecutionError.outputQuarantined
        case let .sanitized(result):
            guard let stdout = String(data: result.stdout, encoding: .utf8),
                  let stderr = String(data: result.stderr, encoding: .utf8)
            else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            return SecretOperationOutput(
                status: "COMPLETED",
                exitCode: result.exitCode,
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

        var request = URLRequest(url: url)
        request.httpMethod = (descriptor.httpMethod ?? "GET").uppercased()
        request.timeoutInterval = timeout.timeInterval
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

    private static func expectSSHScript() -> String {
        return """
        set timeout 30
        if {[llength $argv] != 3} { exit 125 }
        set host [lindex $argv 0]
        set command [lindex $argv 1]
        set port [lindex $argv 2]
        if {[gets stdin username] < 0} { exit 125 }
        if {[gets stdin password] < 0} { exit 125 }
        log_user 1
        spawn /usr/bin/ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p $port "$username@$host" $command
        expect {
            -re "(?i)(password|passphrase).*:" { send -- "$password\\r"; exp_continue }
            eof {}
            timeout { exit 124 }
        }
        catch wait result
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
