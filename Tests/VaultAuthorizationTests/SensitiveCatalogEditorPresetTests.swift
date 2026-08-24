import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func appEntryCreationUsesOneInitialFieldPerPreset() {
    for preset in SensitiveCatalogEntryPreset.all {
        let field = preset.makeInitialField()
        #expect(!field.key.isEmpty)
        #expect(!field.label.isEmpty)
    }

    let custom = SensitiveCatalogEntryPreset.all.first(where: { $0.id == "custom" })
    #expect(custom?.makeInitialField().key == "value")
    #expect(custom?.makeInitialField().type == .text)
}

@Test func existingEntryEditExpandsItsDisclosureGroup() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("expanded = true"))
    #expect(source.contains("newly-created entries"))
}
