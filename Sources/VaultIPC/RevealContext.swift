import Foundation

public struct RevealContext: Codable, Equatable, Sendable {
    public let reason: String
    public let template: String
    public let ranges: [ReferenceRange]
    public let destination: String?

    public init(
        reason: String,
        template: String,
        ranges: [ReferenceRange],
        destination: String? = nil
    ) {
        self.reason = reason
        self.template = template
        self.ranges = ranges
        self.destination = destination
    }

    private enum CodingKeys: String, CodingKey {
        case reason
        case template
        case ranges
        case destination
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        reason = try container.decode(String.self, forKey: .reason)
        template = try container.decode(String.self, forKey: .template)
        ranges = try container.decode([ReferenceRange].self, forKey: .ranges)
        destination = try container.decodeIfPresent(String.self, forKey: .destination)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(reason, forKey: .reason)
        try container.encode(template, forKey: .template)
        try container.encode(ranges, forKey: .ranges)
        try container.encodeIfPresent(destination, forKey: .destination)
    }
}
