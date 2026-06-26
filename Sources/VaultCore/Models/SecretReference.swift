public struct SecretReference: Codable, Hashable, Sendable, CustomStringConvertible {
    public enum Error: Swift.Error, Equatable {
        case invalidFormat
    }

    private static let scheme = "secret://"
    private static let idLength = 26
    private static let allowedCharacters = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    public let id: String

    public init(_ value: String) throws {
        guard value.hasPrefix(Self.scheme) else {
            throw Error.invalidFormat
        }

        let id = String(value.dropFirst(Self.scheme.count))
        guard id.count == Self.idLength,
              id.allSatisfy({ Self.allowedCharacters.contains($0) })
        else {
            throw Error.invalidFormat
        }

        self.id = id
    }

    public var description: String {
        "\(Self.scheme)\(id)"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        try self.init(value)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
