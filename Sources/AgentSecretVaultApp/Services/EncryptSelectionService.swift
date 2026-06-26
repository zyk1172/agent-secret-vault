import AppKit
import Foundation
import VaultCore

@objc public final class EncryptSelectionService: NSObject {
    private let coordinator: (any EncryptSelectionCoordinating)?

    public override init() {
        self.coordinator = nil
        super.init()
    }

    public init(coordinator: any EncryptSelectionCoordinating) {
        self.coordinator = coordinator
        super.init()
    }

    @objc public func encryptSelection(
        _ pasteboard: NSPasteboard,
        userData: String?,
        error: AutoreleasingUnsafeMutablePointer<NSString?>
    ) {
        guard let plaintext = pasteboard.string(forType: .string), !plaintext.isEmpty else {
            error.pointee = "No UTF-8 text selection was provided." as NSString
            return
        }

        guard let coordinator else {
            error.pointee = "Encrypt selection coordinator has not been configured." as NSString
            return
        }

        let resultBox = ServiceResultBox()
        let semaphore = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                _ = try await coordinator.encryptAndReplace(
                    plaintext: plaintext,
                    label: nil,
                    policy: .credential
                )
            } catch {
                resultBox.set(error)
            }

            semaphore.signal()
        }
        semaphore.wait()

        if let serviceError = resultBox.error {
            error.pointee = "\(serviceError)" as NSString
        }
    }
}

private final class ServiceResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storedError: (any Error)?

    var error: (any Error)? {
        lock.withLock {
            storedError
        }
    }

    func set(_ error: any Error) {
        lock.withLock {
            storedError = error
        }
    }
}
