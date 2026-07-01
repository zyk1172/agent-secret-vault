import Foundation
import VaultCore
import VaultIPC

public enum ParagraphRestoreBuilderError: Error, Equatable, Sendable {
    case noSecretReferences
    case invalidReference
}

public enum ParagraphRestoreBuilder {
    private static let referencePattern = #"secret://[0-9A-HJKMNP-TV-Z]{26}"#

    public static func build(from paragraph: String) throws -> (references: [String], context: RevealContext) {
        let regex = try NSRegularExpression(pattern: referencePattern)
        let fullRange = NSRange(paragraph.startIndex..<paragraph.endIndex, in: paragraph)
        let matches = regex.matches(in: paragraph, range: fullRange)

        guard !matches.isEmpty else {
            throw ParagraphRestoreBuilderError.noSecretReferences
        }

        var references: [String] = []
        references.reserveCapacity(matches.count)

        for match in matches {
            guard let range = Range(match.range, in: paragraph) else {
                throw ParagraphRestoreBuilderError.invalidReference
            }
            let reference = String(paragraph[range])
            do {
                references.append(try SecretReference(reference).description)
            } catch {
                throw ParagraphRestoreBuilderError.invalidReference
            }
        }

        var template = paragraph
        var ranges: [ReferenceRange] = Array(
            repeating: ReferenceRange(index: 0, placeholder: ""),
            count: matches.count
        )

        for (index, match) in matches.enumerated().reversed() {
            guard let range = Range(match.range, in: template) else {
                throw ParagraphRestoreBuilderError.invalidReference
            }
            let placeholder = "{{\(index)}}"
            template.replaceSubrange(range, with: placeholder)
            ranges[index] = ReferenceRange(index: index, placeholder: placeholder)
        }

        return (
            references,
            RevealContext(
                reason: "在本应用中解密段落",
                template: template,
                ranges: ranges
            )
        )
    }
}
