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
    /// The executable could not be started. No child process was available
    /// to receive the supplied input.
    case processLaunchFailed(String)
    /// The child process was started, but writing or closing its stdin failed.
    /// This is deliberately distinct from a launch failure because the child
    /// may already have performed work before its input pipe disappeared.
    case stdinWriteFailed(String)
    /// Kept for source compatibility with older ProcessRunning clients. New
    /// runners must use one of the two explicit failure cases above.
    @available(*, deprecated, message: "Use processLaunchFailed or stdinWriteFailed")
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
