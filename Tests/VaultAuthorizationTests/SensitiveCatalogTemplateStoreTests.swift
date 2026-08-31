import Foundation
import Testing
@testable import AgentSecretVaultApp
@testable import VaultCore

@Test func packagedSensitiveCatalogTemplateIsValidAndContainsNoSecretReferences() throws {
    let store = SensitiveCatalogTemplateStore()
    let packagedURL = try store.packagedTemplateURL()
    let packagedData = try Data(contentsOf: packagedURL)
    let report = SensitiveCatalogDocumentCodec.validateDetailed(packagedData)
    #expect(report.status == .found)
    let document = try SensitiveCatalogDocumentCodec.decode(String(data: packagedData, encoding: .utf8) ?? "")
    #expect(document.indexes.count == 1)
    #expect(document.entries.count == 1)
    #expect(document.entries.flatMap(\.fields).contains { field in
        field.type == .secret && field.secretRef == nil
    })
    #expect(document.entries.flatMap(\.fields).allSatisfy { $0.secretRef == nil })
    #expect(MarkdownReferenceScanner.references(in: String(data: packagedData, encoding: .utf8) ?? "").isEmpty)
}
