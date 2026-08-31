import Foundation
import Testing
@testable import VaultCore

@Test func documentedCatalogV3TemplatePassesCoreValidation() throws {
    let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let documentationURL = repositoryRoot.appendingPathComponent("docs/svlt-catalog-schema-v3.md")
    let documentation = try String(contentsOf: documentationURL, encoding: .utf8)

    let opening = try #require(documentation.range(of: "```markdown\n"))
    let afterOpening = documentation[opening.upperBound...]
    let closing = try #require(afterOpening.range(of: "\n```"))
    let template = String(afterOpening[..<closing.lowerBound])
    let data = Data(template.utf8)

    let report = SensitiveCatalogDocumentCodec.validateDetailed(data)
    #expect(report.status == .found)

    let document = try SensitiveCatalogDocumentCodec.decode(template)
    #expect(document.indexes.count == 1)
    #expect(document.entries.count == 1)
    #expect(document.entries.flatMap(\.fields).contains { field in
        field.type == .secret && field.secretRef == nil
    })
}
