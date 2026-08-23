import Foundation

public struct RestoredParagraph: Codable, Equatable, Sendable {
    public let text: String
    public let values: [String]

    public init(text: String, values: [String]) {
        self.text = text
        self.values = values
    }
}
