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

@Test func existingEntryEditOpensDetailAndKeepsEditingSeparate() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("showingDetails = true"))
    #expect(source.contains("entryDetails"))
    #expect(source.contains("commitEntryEdit"))
    #expect(source.contains("revealCatalogField"))
    #expect(source.contains("\"解密\""))
    #expect(source.contains("draftFields = CatalogFieldDraft.make(from: updated.fields, endpoints: updated.endpoints)"))
    #expect(!source.contains("draftEndpoints"))
    #expect(!source.contains("服务地址：type|host|port"))
    #expect(source.contains("填写密码"))
    #expect(!source.contains("minHeight: 132"))
    #expect(source.contains("contentShape(Rectangle())"))
    #expect(source.contains("Button { showingDetails = true } label: {\n                    HStack(alignment: .top, spacing: 8)"))
    #expect(source.contains("entryCounts\n                        .frame(maxWidth: .infinity, alignment: .leading)\n                        .contentShape(Rectangle())"))
    #expect(!source.contains("复制 Entry ID"))
    #expect(!source.contains("entryAdvancedMenu"))
    #expect(source.contains("Image(systemName: \"pencil\")"))
    #expect(source.contains("Image(systemName: \"trash\")"))
    #expect(source.contains("Button(\"删除\", role: .destructive, action: requestDelete)"))
    #expect(source.contains("count: 2"))
    #expect(!source.contains("DisclosureGroup(isExpanded: $expanded)"))
}

@Test func catalogEditorUsesDirectCardsAndEntryBatchEditing() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("CatalogBatchSelectionState"))
    #expect(source.contains("CatalogBatchActionBar"))
    #expect(source.contains("actionTitle: \"批量编辑\""))
    #expect(source.contains("Button(\"删除所选\""))
    #expect(source.contains("entrySelection.isSelecting"))
    #expect(source.contains("Button(\"批量编辑\")"))
    #expect(source.contains("requestEntryDeletion"))
    #expect(source.contains("Button(\"完成\", action: finish)"))
    #expect(!source.contains("Menu {"))
    #expect(source.contains("Text(index.title)"))
    #expect(source.contains("Text(\"\\(entries.count) 个条目\")"))
    #expect(source.contains("Image(systemName: \"trash\")"))
    #expect(!source.contains("Image(systemName: \"ellipsis.circle\")"))
    #expect(!source.contains(".overlay(alignment: .topTrailing)"))
    #expect(!source.contains(".overlay(alignment: .bottomTrailing)"))
    #expect(source.contains("查看该分组中的条目"))
    #expect(source.contains(".accessibilityHint(\"打开条目详情\")"))
    #expect(source.contains(".onHover"))
    #expect(!source.contains("CatalogCardPalette"))
    #expect(source.contains("prepareIndexDeletion(for: index, snapshot: snapshot)"))
    #expect(!source.contains(".aspectRatio(1.618"))
    #expect(source.contains(".flexible(minimum: 0, maximum: .infinity)"))
    #expect(source.contains("titleBlockHeight: CGFloat = 40"))
    #expect(!source.contains("minHeight: 96"))
    #expect(source.contains(".alert(item: $pendingDeletion)"))
    #expect(!source.contains(".alert(item: $pendingIndexDeletion)"))
    #expect(!source.contains(".alert(item: $pendingEntryDeletion)"))
    #expect(source.contains("switch request.kind"))
    #expect(source.contains(".frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)"))
    #expect(source.contains(".layoutPriority(1)"))
    #expect(source.contains("删除 \\(request.itemCount) 个分组？"))
    #expect(source.contains("删除 \\(request.itemCount) 个条目？"))
}
