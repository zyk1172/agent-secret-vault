public protocol SelectionReplacing: Sendable {
    func replaceSelection(with text: String) async throws
}
