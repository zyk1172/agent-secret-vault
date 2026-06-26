import Foundation

public struct ProcessInvocation: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }
}

public struct ProcessResult: Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum ProcessRunError: Error, Equatable, Sendable {
    case timedOut
    case outputLimitExceeded
    case launchFailed(String)
}

public protocol ProcessRunning: Sendable {
    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration,
        outputLimitBytes: Int
    ) async throws -> ProcessResult
}
