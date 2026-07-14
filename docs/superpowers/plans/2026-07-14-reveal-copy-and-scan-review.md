# Reveal Copy and Scan Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide ordered one-click plaintext copy controls for each reference in a decrypted paragraph and show exact, reviewable Obsidian scan findings without persisting them.

**Architecture:** Introduce a local `RestoredParagraph` model that carries both final paragraph text and ordered resolved values. Keep the existing IPC string contract unchanged, but pass this local model through the App runtime, reveal session store, and SwiftUI views. Extend process-local Obsidian scan state with a bounded line excerpt and clear both exact-value fields when the review modal closes.

**Tech Stack:** Swift 6, SwiftUI, AppKit `NSPasteboard`, Swift Testing, TypeScript, Obsidian API, Vitest.

## Global Constraints

- The `secret://` reference remains opaque and is never copied by numbered copy controls; each control copies only its corresponding resolved plaintext.
- Keep plaintext inside App memory only; do not add it to IPC payloads, records, audit logs, metadata, settings, notices, or serialized scan state.
- Agent temporary-reveal copy requires the existing explicit confirmation; workbench and menu-bar copy preserve their existing direct-copy behavior.
- Existing lifecycle clears must invalidate all local restored values.
- Obsidian review text is available only while the modal is open and is released by `onClose`.

---

### Task 1: Model resolved paragraphs and preserve IPC compatibility

**Files:**
- Create: `Sources/AgentSecretVaultApp/Workbench/RestoredParagraph.swift`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift:220-305`
- Modify: `Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift:3-65`
- Modify: `Sources/AgentSecretVaultApp/Workbench/RevealSessionPresenter.swift:10-49`
- Test: `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`

**Interfaces:**
- Produces `public struct RestoredParagraph: Equatable, Sendable { public let text: String; public let values: [String] }`.
- Produces `VaultAppServices.restoreReferencesWithValues(references:context:) async throws -> RestoredParagraph` for in-App callers.
- Keeps `WorkbenchServicing.restoreReferences(references:context:) async throws -> String` unchanged for IPC callers.
- Changes `RevealSessionStore.create(resolvedParagraph:)` and `restoreResult(id:)` to use `RestoredParagraph`.

- [ ] **Step 1: Write failing service and session tests**

```swift
@Test func revealSessionStoreKeepsOrderedCopyValuesAndClearsThem() async {
    let store = RevealSessionStore()
    let expected = RestoredParagraph(text: "账号: alice，密码: hunter2", values: ["alice", "hunter2"])
    let id = await store.create(resolvedParagraph: expected)

    #expect(await store.restoredParagraph(id: id) == expected)
    await store.clear(id: id)
    #expect(await store.restoredParagraph(id: id) == nil)
}

@Test func vaultAppServicesRestoresOrderedValuesWithoutChangingIPCStringRestore() async throws {
    let restored = try await services.restoreReferencesWithValues(references: references, context: context)
    #expect(restored.text == "账号: ASV_CANARY_USER，密码: ASV_CANARY_PASSWORD")
    #expect(restored.values == ["ASV_CANARY_USER", "ASV_CANARY_PASSWORD"])
    #expect(try await services.restoreReferences(references: references, context: context) == restored.text)
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/RevealSessionStoreTests`

Expected: compile/test failure because `RestoredParagraph`, `restoredParagraph(id:)`, and `restoreReferencesWithValues` do not exist.

- [ ] **Step 3: Implement the local restored-value model and data flow**

```swift
public struct RestoredParagraph: Equatable, Sendable {
    public let text: String
    public let values: [String]

    public init(text: String, values: [String]) {
        self.text = text
        self.values = values
    }
}

public func restoreReferencesWithValues(
    references: [String], context: RevealContext
) async throws -> RestoredParagraph {
    try await resolveReferencesWithValues(references: references, context: context)
}

public func restoreReferences(references: [String], context: RevealContext) async throws -> String {
    try await restoreReferencesWithValues(references: references, context: context).text
}
```

Make the resolver return `RestoredParagraph(text: try resolveTemplate(...), values: plaintexts)`. Update `openRevealSession` to store that value, and update the session-store dictionary and presenter to retrieve `RestoredParagraph` rather than a bare string. Leave export behavior based on `.text`.

- [ ] **Step 4: Run focused tests and verify they pass**

Run: `xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/RevealSessionStoreTests`

Expected: PASS; existing IPC test targets compile without changing their `restoreReferences` spy signature.

- [ ] **Step 5: Commit the model layer**

```bash
git add Sources/AgentSecretVaultApp/Workbench/RestoredParagraph.swift \
  Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift \
  Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift \
  Sources/AgentSecretVaultApp/Workbench/RevealSessionPresenter.swift \
  Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift
git commit -m "feat: retain ordered values for paragraph restore"
```

### Task 2: Render numbered copy controls in all macOS reveal surfaces

**Files:**
- Modify: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift:18-26,189-198`
- Modify: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift:120-240`
- Modify: `Sources/AgentSecretVaultApp/Workbench/ParagraphRestoreView.swift`
- Modify: `Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift:10-90`
- Modify: `Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreState.swift`
- Modify: `Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreView.swift`
- Modify: `Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift`
- Test: `Tests/VaultAuthorizationTests/MenuBarPanelTests.swift`
- Test: `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`

**Interfaces:**
- Changes App and workbench closures from `(String) async throws -> String` to `(String) async throws -> RestoredParagraph`.
- `MenuBarParagraphRestoreState.restoredParagraph: RestoredParagraph?` replaces string-only output and `clearSensitiveOutput()` sets it to `nil`.
- `RevealSessionWindow(restoredParagraph:close:)` renders copy actions from `restoredParagraph.values`.

- [ ] **Step 1: Write failing UI contract tests**

```swift
@Test func menuBarRestoreRendersOneNumberedCopyControlPerResolvedValue() throws {
    let source = try menuBarSource(named: "MenuBarParagraphRestoreView.swift")
    #expect(source.contains("ForEach(Array(restoredParagraph.values.enumerated()), id: \\.offset)"))
    #expect(source.contains("复制密文 \\(index + 1)"))
}

@Test func temporaryRevealKeepsConfirmationBeforeCopyingIndividualValues() throws {
    let source = try workbenchSource(named: "RevealSessionWindow.swift")
    #expect(source.contains("确认复制明文到剪贴板？"))
    #expect(source.contains("复制密文 \\(index + 1)"))
}
```

Add a state test that a successful restore sets `restoredParagraph` and `clearSensitiveOutput()` returns it to `nil`, including duplicate values at separate indices.

- [ ] **Step 2: Run focused tests and verify they fail**

Run: `xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/MenuBarPanelTests`

Expected: FAIL because the views have no `RestoredParagraph` or numbered copy controls.

- [ ] **Step 3: Implement direct workbench copy and confirmed temporary-reveal copy**

```swift
ForEach(Array(restoredParagraph.values.enumerated()), id: \.offset) { index, value in
    Button("复制密文 \(index + 1)") {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}
```

In `RevealSessionWindow`, keep `@State private var pendingCopyIndex: Int?`; opening a numbered action sets this index. Its confirmation dialog copies `restoredParagraph.values[index]` only when the index is valid. Keep the existing close action. Update App runtime to call `services.restoreReferencesWithValues`, and make both workbench views render `restoredParagraph.text` while their existing whole-result action copies `.text`.

- [ ] **Step 4: Run focused tests and verify they pass**

Run: `xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/MenuBarPanelTests`

Expected: PASS; the temporary reveal keeps explicit confirmation and menu-bar clear paths invalidate `RestoredParagraph`.

- [ ] **Step 5: Commit the macOS UI change**

```bash
git add Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift \
  Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Sources/AgentSecretVaultApp/Workbench/ParagraphRestoreView.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreState.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarParagraphRestoreView.swift \
  Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift \
  Tests/VaultAuthorizationTests/MenuBarPanelTests.swift \
  Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift
git commit -m "feat: add per-reference reveal copy controls"
```

### Task 3: Show process-local scan text and release it on modal close

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/scan/scanState.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts`
- Test: `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`
- Test: `obsidian-plugin/agent-secret-vault/test/reviewModal.test.ts`

**Interfaces:**
- Adds optional `sourceExcerptForCurrentProcessOnly?: string` to `ScanFindingState`.
- `scanMarkdownFile` fills it with the source line containing the finding, limited to 240 characters around the finding.
- `ReviewModal.onClose()` clears both process-local fields on every finding, replaces its findings array with `[]`, and empties `contentEl`.

- [ ] **Step 1: Write failing scanner and modal tests**

```ts
it("keeps a bounded source excerpt only in process-local scan state", () => {
  const findings = scanMarkdownFile("Daily.md", "服务账号：alice，密码：hunter2\n");
  expect(findings[0].sourceExcerptForCurrentProcessOnly).toContain("密码：hunter2");
  expect(serializeScanState(findings)).not.toContain("服务账号：alice");
  expect(serializeScanState(findings)).not.toContain("hunter2");
});

it("shows exact review text and clears it when closed", () => {
  const candidate = finding({
    plaintextForCurrentProcessOnly: "hunter2",
    sourceExcerptForCurrentProcessOnly: "NAS 密码：hunter2"
  });
  const modal = new ReviewModal({} as never, [candidate]);
  modal.onOpen();
  expect(modalMock.latestContentEl?.allText()).toContain("命中内容：hunter2");
  expect(modalMock.latestContentEl?.allText()).toContain("所在内容：NAS 密码：hunter2");
  modal.onClose();
  expect(candidate.plaintextForCurrentProcessOnly).toBeUndefined();
  expect(candidate.sourceExcerptForCurrentProcessOnly).toBeUndefined();
});
```

- [ ] **Step 2: Run focused tests and verify they fail**

Run: `npm test -- --run test/scanState.test.ts test/reviewModal.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: FAIL because no excerpt field, rendered exact text, or close cleanup exists.

- [ ] **Step 3: Implement bounded excerpts, display fallback, and close cleanup**

```ts
function sourceExcerpt(text: string, start: number, end: number): string {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const nextLineBreak = text.indexOf("\n", end);
  const lineEnd = nextLineBreak === -1 ? text.length : nextLineBreak;
  const line = text.slice(lineStart, lineEnd);
  if (line.length <= 240) return line;
  const matchStart = start - lineStart;
  const excerptStart = Math.max(0, Math.min(matchStart - 100, line.length - 240));
  const excerptEnd = Math.min(line.length, excerptStart + 240);
  return `${excerptStart > 0 ? "..." : ""}${line.slice(excerptStart, excerptEnd)}${excerptEnd < line.length ? "..." : ""}`;
}

override onClose(): void {
  for (const finding of this.findings) {
    finding.plaintextForCurrentProcessOnly = undefined;
    finding.sourceExcerptForCurrentProcessOnly = undefined;
  }
  this.findings = [];
  this.contentEl.empty();
}
```

Render `命中内容：${finding.plaintextForCurrentProcessOnly ?? finding.redactedPreview}` and `所在内容：${finding.sourceExcerptForCurrentProcessOnly ?? finding.redactedPreview}`. Update serialization to omit both process-local fields.

- [ ] **Step 4: Run focused tests and verify they pass**

Run: `npm test -- --run test/scanState.test.ts test/reviewModal.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: PASS; serialized output contains neither exact match nor context after scanning.

- [ ] **Step 5: Commit the Obsidian review change**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan/scanState.ts \
  obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts \
  obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts \
  obsidian-plugin/agent-secret-vault/test/scanState.test.ts \
  obsidian-plugin/agent-secret-vault/test/reviewModal.test.ts
git commit -m "feat: show reviewable scan findings"
```

### Task 4: Run full verification and record evidence

**Files:**
- No planned source edits; investigate and correct any failed verification in the file that produced it before repeating the relevant command.

**Interfaces:**
- Consumes the completed macOS and Obsidian changes.
- Produces verified test, typecheck, build, and plaintext-scan evidence.

- [ ] **Step 1: Run all macOS tests**

Run: `xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test`

Expected: PASS for VaultCore, VaultAuthorization, VaultIPC, and leak tests.

- [ ] **Step 2: Run all Obsidian verification**

Run: `npm test && npm run typecheck && npm run build && npm run check:build-artifact`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: all Vitest suites pass, TypeScript has no errors, and `main.js` exists.

- [ ] **Step 3: Run repository hygiene and plaintext checks**

```bash
git diff --check
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build dist test-artifacts
git status -sb
```

Expected: no whitespace errors, canary scanner exits 0 without output, and only intended commits are ahead of `origin/main`.
