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

@Test func catalogFieldPresentationUsesSemanticValuesForOrdinaryFields() {
    let cases: [(SecretCatalogValue, String)] = [
        (.string("QNAP NAS"), "QNAP NAS"),
        (.number(192.0), "192.0"),
        (.boolean(true), "是"),
        (.list(["admin", "operator"]), "admin, operator")
    ]

    for (value, expected) in cases {
        let field = SecretCatalogFieldValue(
            key: "metadata",
            label: "元数据",
            type: .text,
            value: value
        )
        let presentation = CatalogFieldPresentation.resolve(field: field)
        #expect(presentation.displayText == expected)
        #expect(presentation.actionKind == .copy)
        #expect(presentation.allowsCopy)
        #expect(!presentation.isSecret)
    }
}

@Test func catalogFieldPresentationSeparatesSecretPlaceholderBoundAndRevealedStates() {
    let placeholder = SecretCatalogFieldValue(key: "secret", label: "密码", type: .secret)
    let placeholderPresentation = CatalogFieldPresentation.resolve(field: placeholder)
    #expect(placeholderPresentation.displayText == "未填写")
    #expect(placeholderPresentation.actionKind == .fillSecret)
    #expect(!placeholderPresentation.allowsCopy)
    let stalePlaceholderPresentation = CatalogFieldPresentation.resolve(
        field: placeholder,
        revealedPlaintext: "stale-transient-value"
    )
    #expect(stalePlaceholderPresentation.displayText == "未填写")
    #expect(stalePlaceholderPresentation.actionKind == .fillSecret)

    let bound = SecretCatalogFieldValue(
        key: "secret",
        label: "密码",
        type: .secret,
        secretRef: "secret://opaque"
    )
    let boundPresentation = CatalogFieldPresentation.resolve(field: bound)
    #expect(boundPresentation.displayText == "已加密")
    #expect(boundPresentation.actionKind == .reveal)
    #expect(!boundPresentation.allowsCopy)

    let revealedPresentation = CatalogFieldPresentation.resolve(
        field: bound,
        revealedPlaintext: "transient-value"
    )
    #expect(revealedPresentation.displayText == "transient-value")
    #expect(revealedPresentation.isRevealed)
    #expect(revealedPresentation.actionKind == .copy)
    #expect(revealedPresentation.allowsCopy)
}

@Test func catalogDetailColumnWidthsKeepValueColumnAsTheFlexibleColumn() {
    let widths = CatalogDetailColumnWidths.calculate(availableWidth: 760)
    #expect(widths.name < widths.value)
    #expect(widths.action < widths.value)
    #expect(abs((widths.name + widths.value + widths.action) - 728) < 0.001)

    let narrow = CatalogDetailColumnWidths.calculate(availableWidth: 300)
    #expect(narrow.name >= 90)
    #expect(narrow.action >= 72)
    #expect(narrow.value >= 0)
}

@Test func batchSelectionRetainsVisibleIDsAfterAuthoritativeRefresh() {
    var state = CatalogBatchSelectionState()
    state.begin()
    state.selectAll(["still-present", "removed"])
    state.retainVisibleIDs(["still-present", "new"])
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["still-present"])
}

@Test func auditRefreshReducerPreservesEntriesAcrossIndependentFailures() {
    let previous = [fixtureAuditEntry(target: "previous")]
    let current = [fixtureAuditEntry(target: "current")]

    let healthy = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .normal
    )
    #expect(healthy.entries == current)
    #expect(healthy.warning == nil)

    let partiallyReadable = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .partial(
            entries: current,
            diagnostics: AuditReadDiagnostics(unreadableRecordCount: 1, integrityFailureCount: 2)
        ),
        health: .normal
    )
    #expect(partiallyReadable.entries == current)
    #expect(partiallyReadable.warning?.contains("无法读取 1 条") == true)
    #expect(partiallyReadable.warning?.contains("完整性验证失败 2 条") == true)

    let appendFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .appendFailed
    )
    #expect(appendFailed.entries == current)
    #expect(appendFailed.warning?.contains("写入异常") == true)

    let healthFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .failure
    )
    #expect(healthFailed.entries == current)
    #expect(healthFailed.warning?.contains("AUDIT_HEALTH_READ_FAILED") == true)

    let activityFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .failure(code: "AUDIT_READ_FAILED")
    )
    #expect(activityFailed.entries == previous)
    #expect(activityFailed.warning?.contains("AUDIT_READ_FAILED") == true)

    let unavailable = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .unavailable
    )
    #expect(unavailable.entries == previous)
    #expect(unavailable.warning?.contains("APP_CONTROL_UNAVAILABLE") == true)
}

@Test func overviewKeepsRecentAutomationBeforeConditionalPendingSecretCard() throws {
    let source = try workbenchSource()
    guard let overviewStart = source.range(of: "private var overviewPage") else {
        Issue.record("overviewPage not found")
        return
    }
    let overview = source[overviewStart.lowerBound...]
    guard let hero = overview.range(of: "OverviewHero("),
          let activity = overview.range(of: "CompactAuditPreviewCard("),
          let pending = overview.range(of: "PendingSecretFillCard(")
    else {
        Issue.record("overview cards not found")
        return
    }
    #expect(hero.lowerBound < activity.lowerBound)
    #expect(activity.lowerBound < pending.lowerBound)
    #expect(overview.contains(".layoutPriority(1)"))
    #expect(overview.contains("maxHeight: .infinity"))
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

private func workbenchSource() throws -> String {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}

private func entry(_ id: String, index: String, fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(id: id, indexId: index, title: id, fields: fields)
}

private func fixtureAuditEntry(target: String) -> CatalogSecurityAuditEntry {
    CatalogSecurityAuditEntry(
        id: UUID(),
        timestamp: Date(timeIntervalSince1970: 0),
        source: .agent,
        operation: .status,
        authorizationOutcome: .notRequired,
        result: .completed,
        target: target,
        referenceCount: 0
    )
}
