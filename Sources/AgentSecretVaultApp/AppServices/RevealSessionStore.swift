import Foundation

public actor RevealSessionStore {
    public typealias ClearHandler = @Sendable () async -> Void

    private var sessions: [String: String] = [:]
    private var clearTasks: [String: Task<Void, Never>] = [:]
    private var clearHandlers: [String: ClearHandler] = [:]
    private let defaultTTLNanoseconds: UInt64?

    public init(defaultTTLSeconds: TimeInterval? = nil) {
        if let defaultTTLSeconds {
            self.defaultTTLNanoseconds = UInt64(max(0, defaultTTLSeconds) * 1_000_000_000)
        } else {
            self.defaultTTLNanoseconds = nil
        }
    }

    public func create(resolvedParagraph: String) -> String {
        let id = "session-\(UUID().uuidString)"
        sessions[id] = resolvedParagraph
        scheduleClearIfNeeded(id: id)
        return id
    }

    public func paragraph(id: String) -> String? {
        sessions[id]
    }

    public func setClearHandler(id: String, handler: @escaping ClearHandler) async {
        guard sessions[id] != nil else {
            await handler()
            return
        }
        clearHandlers[id] = handler
    }

    public func clear(id: String) async {
        let handler = clearHandlers[id]
        sessions[id] = nil
        clearTasks[id]?.cancel()
        clearTasks[id] = nil
        clearHandlers[id] = nil
        await handler?()
    }

    public func clearAll() async {
        let handlers = Array(clearHandlers.values)
        sessions.removeAll()
        for task in clearTasks.values {
            task.cancel()
        }
        clearTasks.removeAll()
        clearHandlers.removeAll()
        for handler in handlers {
            await handler()
        }
    }

    private func scheduleClearIfNeeded(id: String) {
        guard let defaultTTLNanoseconds else {
            return
        }
        clearTasks[id]?.cancel()
        clearTasks[id] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: defaultTTLNanoseconds)
            await self?.clear(id: id)
        }
    }
}
