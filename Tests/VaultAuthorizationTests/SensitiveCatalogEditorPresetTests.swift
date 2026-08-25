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

    #expect(source.contains("DisclosureGroup(isExpanded: $expanded)"))
    #expect(source.contains("expanded = true"))
    #expect(source.contains("commitEntryEdit"))
    #expect(source.contains("TextField(\"输入密码\""))
    #expect(source.contains("pendingSecretInputs.removeAll()"))
    #expect(!source.contains("填写密码"))
}

@Test func catalogEditorUsesExplicitSelectionModesAndSafeDeleteConfirmation() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("isSelectingIndexes"))
    #expect(source.contains("isSelectingEntries"))
    #expect(!source.contains(".aspectRatio(1.618"))
    #expect(source.contains(".flexible(minimum: 0, maximum: .infinity)"))
    #expect(source.contains("minHeight: 120"))
    #expect(source.contains(".alert(item: $pendingIndexDeletion)"))
    #expect(source.contains(".alert(item: $pendingEntryDeletion)"))
    #expect(source.contains("frame(maxHeight: 520)"))
    #expect(source.contains("删除 \\(request.itemCount) 个分组？"))
    #expect(source.contains("删除 \\(request.itemCount) 个条目？"))
}
