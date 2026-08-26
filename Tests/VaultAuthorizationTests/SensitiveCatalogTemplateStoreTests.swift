import Foundation
import Testing
@testable import AgentSecretVaultApp
@testable import VaultCore

@Test func packagedSensitiveCatalogTemplateMatchesCanonicalEmptyCatalog() throws {
    let store = SensitiveCatalogTemplateStore()
    let packagedURL = try store.packagedTemplateURL()
    let packagedData = try Data(contentsOf: packagedURL)
    let canonicalData = try SensitiveCatalogDocumentCodec.canonicalData(SecretCatalogDocument())

    #expect(packagedData == canonicalData)
    let report = SensitiveCatalogDocumentCodec.validateDetailed(packagedData)
    #expect(report.status == .found)
    let document = try SensitiveCatalogDocumentCodec.decode(String(data: packagedData, encoding: .utf8) ?? "")
    #expect(document.indexes.isEmpty)
    #expect(document.entries.isEmpty)
    #expect(MarkdownReferenceScanner.references(in: String(data: packagedData, encoding: .utf8) ?? "").isEmpty)
}
