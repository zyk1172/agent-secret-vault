import Foundation

public actor RevealSessionStore {
    private var sessions: [String: String] = [:]
    private var clearTasks: [String: Task<Void, Never>] = [:]
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

    public func clear(id: String) {
        sessions[id] = nil
        clearTasks[id]?.cancel()
        clearTasks[id] = nil
    }

    public func clearAll() {
        sessions.removeAll()
        for task in clearTasks.values {
            task.cancel()
        }
        clearTasks.removeAll()
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
