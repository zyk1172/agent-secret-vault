import Darwin
import Dispatch
import Foundation
import os
import VaultService

@main
struct SVLTAgentMain {
    private static let logger = Logger(
        subsystem: "com.agent-secret-vault.SVLT.agent",
        category: "lifecycle"
    )

    static func main() async {
        do {
            let daemon = try VaultDaemonCore()
            try await daemon.start()
            let terminationWaiter = AgentTerminationWaiter()
            await terminationWaiter.wait()
            await daemon.stop()
        } catch VaultDaemonCoreError.alreadyStarted {
            logger.error("SVLT_AGENT_ALREADY_STARTED")
            exit(EXIT_FAILURE)
        } catch {
            logger.error("SVLT_AGENT_START_FAILED")
            exit(EXIT_FAILURE)
        }
    }
}

/// Blocks on OS termination signals only. It is not a heartbeat or polling
/// loop, and allows the daemon to close its socket cleanly on launchd stop.
private final class AgentTerminationWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var didReceiveSignal = false
    private var sources: [DispatchSourceSignal] = []

    init() {
        for signalNumber in [SIGTERM, SIGINT] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(
                signal: signalNumber,
                queue: DispatchQueue.global(qos: .utility)
            )
            source.setEventHandler { [weak self] in
                self?.resume()
            }
            source.resume()
            sources.append(source)
        }
    }

    deinit {
        for source in sources {
            source.cancel()
        }
    }

    func wait() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if didReceiveSignal {
                    lock.unlock()
                    continuation.resume()
                    return
                }
                self.continuation = continuation
                lock.unlock()
            }
        } onCancel: {
            resume()
        }
    }

    private func resume() {
        lock.lock()
        didReceiveSignal = true
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume()
    }
}
