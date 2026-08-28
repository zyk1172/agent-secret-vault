import Foundation
import Testing
@testable import AgentSecretVaultApp
import VaultCore

@Test func pendingSecretResolverUsesAuthoritativeSourceOrder() {
    let document = fixtureDocument(
        indexes: ["index-a", "index-b"],
        entries: [
            entry("entry-a", index: "index-a", fields: [
                SecretCatalogFieldValue(key: "filled", label: "已填", type: .secret, secretRef: "secret://filled"),
                SecretCatalogFieldValue(key: "first", label: "密码", type: .secret)
            ]),
            entry("entry-b", index: "index-b", fields: [
                SecretCatalogFieldValue(key: "second", label: "Token", type: .secret)
            ])
        ]
    )

    let pending = PendingCatalogSecretResolver.resolve(in: document)
    #expect(pending?.indexID == "index-a")
    #expect(pending?.entryID == "entry-a")
    #expect(pending?.fieldKey == "first")
    #expect(pending?.remainingCount == 2)
}

@Test func pendingSecretResolverAdvancesAfterFirstPlaceholderIsFilled() {
    let first = SecretCatalogFieldValue(key: "first", label: "密码", type: .secret)
    let second = SecretCatalogFieldValue(key: "second", label: "Token", type: .secret)
    let base = entry("entry", index: "index", fields: [first, second])
    let document = fixtureDocument(indexes: ["index"], entries: [base])
    #expect(PendingCatalogSecretResolver.resolve(in: document)?.remainingCount == 2)

    let filled = entry("entry", index: "index", fields: [
        SecretCatalogFieldValue(key: "first", label: "密码", type: .secret, secretRef: "secret://first"),
        second
    ])
    let advanced = fixtureDocument(indexes: ["index"], entries: [filled])
    #expect(PendingCatalogSecretResolver.resolve(in: advanced)?.fieldKey == "second")
    #expect(PendingCatalogSecretResolver.resolve(in: advanced)?.remainingCount == 1)
}

@Test func batchSelectionHasExplicitBeginSelectAllAndFinishState() {
    var state = CatalogBatchSelectionState()
    state.begin()
    state.toggle("a")
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["a"])
    state.selectAll(["a", "b"])
    #expect(state.selectedIDs == ["a", "b"])
    state.deleteSucceeded(["a"])
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["b"])
    state.finish()
    #expect(!state.isSelecting)
    #expect(state.selectedIDs.isEmpty)
}

@Test func deletionSummaryCountsGroupsEntriesAndSecretFields() {
    let entries = [
        entry("a", index: "one", fields: [SecretCatalogFieldValue(key: "secret", label: "密码", type: .secret)]),
        entry("b", index: "two", fields: [SecretCatalogFieldValue(key: "name", label: "用户名", type: .text)])
    ]
    let document = fixtureDocument(indexes: ["one", "two"], entries: entries)
    #expect(CatalogDeletionSummary.indexes(ids: ["one", "two"], in: document) == .init(itemCount: 2, entryCount: 2, secretFieldCount: 1))
    #expect(CatalogDeletionSummary.entries(ids: ["a", "b"], in: entries) == .init(itemCount: 2, entryCount: 0, secretFieldCount: 1))
}

@Test func mainWindowUsesHiddenTitleBarWithoutRemovingMacOSChrome() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)
    #expect(source.contains("Window(\"SVLT\", id: MenuBarPresentation.mainWindowID)"))
    #expect(source.contains(".windowStyle(.hiddenTitleBar)"))
    #expect(source.contains("MenuBarExtra(\"SVLT\""))
}

private func fixtureDocument(indexes: [String], entries: [SecretCatalogEntry]) -> SecretCatalogDocument {
    SecretCatalogDocument(indexes: indexes.map { SecretCatalogIndex(id: $0, title: $0) }, entries: entries)
}

private func entry(_ id: String, index: String, fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(id: id, indexId: index, title: id, fields: fields)
}
