import Foundation

public enum MarkdownReferenceScanner {
    private static let scheme = "secret://"
    private static let idLength = 26
    private static let allowedIDCharacters = Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let tokenBoundaryCharacters = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/-")

    public static func references(in markdown: String) -> [String] {
        var references: [String] = []
        var seen: Set<String> = []
        var searchStart = markdown.startIndex

        while let schemeRange = markdown.range(of: scheme, range: searchStart..<markdown.endIndex) {
            defer {
                searchStart = schemeRange.upperBound
            }

            guard isBoundary(previousIndex(before: schemeRange.lowerBound, in: markdown), in: markdown) else {
                continue
            }

            var idEnd = schemeRange.upperBound
            var id = ""
            for _ in 0..<idLength {
                guard idEnd < markdown.endIndex else {
                    id = ""
                    break
                }
                let character = markdown[idEnd]
                guard allowedIDCharacters.contains(character) else {
                    id = ""
                    break
                }
                id.append(character)
                idEnd = markdown.index(after: idEnd)
            }

            guard id.count == idLength,
                  isBoundary(idEnd, in: markdown),
                  let reference = try? SecretReference("\(scheme)\(id)").description,
                  seen.insert(reference).inserted
            else {
                continue
            }

            references.append(reference)
        }

        return references
    }

    static func referenceIDs(in markdown: String) -> Set<String> {
        Set(references(in: markdown).compactMap { reference in
            try? SecretReference(reference).id
        })
    }

    private static func isBoundary(_ index: String.Index?, in text: String) -> Bool {
        guard let index,
              index >= text.startIndex,
              index < text.endIndex
        else {
            return true
        }
        return !tokenBoundaryCharacters.contains(text[index])
    }

    private static func previousIndex(before index: String.Index, in text: String) -> String.Index? {
        guard index > text.startIndex else {
            return nil
        }
        return text.index(before: index)
    }
}
