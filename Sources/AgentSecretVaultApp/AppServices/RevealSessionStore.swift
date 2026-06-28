import Foundation

public actor RevealSessionStore {
    private var sessions: [String: String] = [:]

    public init() {}

    public func create(resolvedParagraph: String) -> String {
        let id = "session-\(UUID().uuidString)"
        sessions[id] = resolvedParagraph
        return id
    }

    public func paragraph(id: String) -> String? {
        sessions[id]
    }

    public func clear(id: String) {
        sessions[id] = nil
    }

    public func clearAll() {
        sessions.removeAll()
    }
}
