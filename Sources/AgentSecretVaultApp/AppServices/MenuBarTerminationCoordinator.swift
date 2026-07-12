import Foundation

@MainActor
public final class MenuBarTerminationCoordinator {
    public typealias Cleanup = @MainActor @Sendable () async -> Void
    public typealias TerminateAction = @MainActor @Sendable () -> Void

    public private(set) var permitsTermination = false
    private var terminationRequestPending = false
    private let terminate: TerminateAction

    public init(terminate: @escaping TerminateAction) {
        self.terminate = terminate
    }

    public func requestTermination(cleanup: @escaping Cleanup) async {
        guard !terminationRequestPending else {
            return
        }

        terminationRequestPending = true
        await cleanup()
        permitsTermination = true
        terminate()
    }
}
