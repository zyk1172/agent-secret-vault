# Central Sensitive Index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a user-selected `敏感信息.md` the sole source of encrypted records, add an explicit macOS review workflow, and retain Obsidian manual encryption, reveal, and restore.

**Architecture:** A selected-index actor owns the selected Markdown file and implements the existing record-store protocols. It stores one encrypted envelope and visible metadata per entry, so the resolver and crypto code continue to consume `EncryptedRecord`. App scan candidates are process-local, rule-generated, and explicitly committed through the index before a source file is rewritten. IPC returns a safe display presentation so Obsidian can write readable Markdown links while retaining the existing opaque reference in the link target.

**Tech Stack:** Swift 6, SwiftUI, CryptoKit, Foundation, Obsidian API, TypeScript 5.9, Vitest 4.

## Global Constraints

- The selected `敏感信息.md` is the only active record source after setup; legacy Application Support records are migration input only.
- Each entry has one independently encrypted `EncryptedRecord` envelope and never stores plaintext.
- Rules run locally and generate candidates only. Nothing is auto-selected, encrypted, or replaced without an explicit user action.
- Original notes use `[S-001 Title](secret://...)`; agents interact only with the opaque `secret://` target.
- Index writes are verified temporary-file writes with symlink rejection. Source-note replacement remains a separate hash-validated step and may leave a recoverable unreferenced index entry on failure.
- Process-local plaintext, candidate paragraphs, and source snapshots are not serialised, logged, included in notices, or sent through IPC except the plaintext of an explicit local encrypt request.
- Obsidian retains manual encryption, temporary reveal, and explicit restore; App owns central scan and maintenance.

---

### Task 1: Model and codec for visible indexed encrypted records

**Files:**
- Create: `Sources/VaultCore/Models/IndexedEncryptedRecord.swift`
- Create: `Sources/VaultCore/Store/MarkdownSensitiveIndexCodec.swift`
- Test: `Tests/VaultCoreTests/MarkdownSensitiveIndexCodecTests.swift`

**Interfaces:**
- Produces `IndexedEncryptedRecord(displayID:category:title:source:record:)`.
- Produces `SensitiveSourceLocation(filePath:line:)`.
- Produces `MarkdownSensitiveIndexCodec.decode(_:) throws -> [IndexedEncryptedRecord]` and `encode(_:) throws -> String`.

- [ ] **Step 1: Write failing round-trip and invalid-index tests**

```swift
@Test func markdownIndexRoundTripsVisibleMetadataAndEncryptedEnvelope() throws {
    let entry = IndexedEncryptedRecord(
        displayID: "S-001",
        category: "API Key",
        title: "OpenAI API Key",
        source: SensitiveSourceLocation(filePath: "AI/工具与服务.md", line: 23),
        record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    )
    let text = try MarkdownSensitiveIndexCodec.encode([entry])
    #expect(text.contains("## S-001 · OpenAI API Key"))
    #expect(text.contains("secret://0123456789ABCDEFGHJKMNPQRS"))
    #expect(text.contains("```asv-record"))
    #expect(try MarkdownSensitiveIndexCodec.decode(text) == [entry])
}

@Test func markdownIndexRejectsDuplicateDisplayIDsAndReferences() {
    let first = IndexedEncryptedRecord(displayID: "S-001", category: "API Key", title: "First", source: nil, record: fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS"))
    let second = IndexedEncryptedRecord(displayID: "S-002", category: "API Key", title: "Second", source: nil, record: fixtureRecord(id: "ABCDEFGHJKMNPQRSTVWXYZ0123"))
    let firstText = try MarkdownSensitiveIndexCodec.encode([first])
    let secondEntry = try MarkdownSensitiveIndexCodec.encode([second])
        .components(separatedBy: "\n\n").dropFirst().joined(separator: "\n\n")
    let duplicate = firstText + "\n\n" + secondEntry.replacingOccurrences(of: "## S-002", with: "## S-001")
    #expect(throws: MarkdownSensitiveIndexError.duplicateDisplayID("S-001")) {
        _ = try MarkdownSensitiveIndexCodec.decode(duplicate.replacingOccurrences(of: "## S-002", with: "## S-001"))
    }
}

private func fixtureRecord(id: String) -> EncryptedRecord {
    EncryptedRecord(formatVersion: 1, id: id, recordVersion: 1,
                    ciphertext: Data([1]), nonce: Data([2]), tag: Data([3]),
                    wrappedDataKey: Data([4]), wrappedDataKeyNonce: Data([5]),
                    wrappedDataKeyTag: Data([6]), label: "OpenAI API Key",
                    policy: .credential, createdAt: .distantPast, updatedAt: .distantPast)
}
```

- [ ] **Step 2: Run the focused codec test and verify it fails**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultCore -destination 'platform=macOS' test -only-testing:VaultCoreTests/MarkdownSensitiveIndexCodecTests`

Expected: compile failure because the indexed-record model and codec do not exist.

- [ ] **Step 3: Implement the canonical Markdown codec**

```swift
public struct IndexedEncryptedRecord: Equatable, Sendable {
    public let displayID: String
    public let category: String
    public let title: String
    public let source: SensitiveSourceLocation?
    public let record: EncryptedRecord
}

public enum MarkdownSensitiveIndexCodec {
    public static func encode(_ entries: [IndexedEncryptedRecord]) throws -> String
    public static func decode(_ text: String) throws -> [IndexedEncryptedRecord]
}
```

Emit the header marker, then entries sorted by numeric display ID. Encode the existing `EncryptedRecord` with a stable JSON encoder and Base64 inside each `asv-record` fence. Parse only the exact canonical entry fields; reject malformed headings, duplicated IDs/references, invalid `SecretReference`, invalid Base64/JSON, and an envelope whose record ID disagrees with its reference. Use `ISO8601DateFormatter` for visible timestamps.

- [ ] **Step 4: Run the focused codec test and verify it passes**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultCore -destination 'platform=macOS' test -only-testing:VaultCoreTests/MarkdownSensitiveIndexCodecTests`

Expected: PASS; the encoded output contains metadata and ciphertext only, while the test confirms exact record equality after decoding.

- [ ] **Step 5: Commit the index data format**

```bash
git add Sources/VaultCore/Models/IndexedEncryptedRecord.swift \
  Sources/VaultCore/Store/MarkdownSensitiveIndexCodec.swift \
  Tests/VaultCoreTests/MarkdownSensitiveIndexCodecTests.swift
git commit -m "feat: encode encrypted records in markdown index"
```

### Task 2: Selected Markdown index record store and legacy migration

**Files:**
- Create: `Sources/VaultCore/Store/SelectedMarkdownRecordStore.swift`
- Create: `Sources/AgentSecretVaultApp/AppServices/SensitiveIndexSelectionStore.swift`
- Create: `Sources/AgentSecretVaultApp/AppServices/LegacyRecordMigration.swift`
- Test: `Tests/VaultCoreTests/SelectedMarkdownRecordStoreTests.swift`
- Test: `Tests/VaultAuthorizationTests/LegacyRecordMigrationTests.swift`

**Interfaces:**
- Produces `SelectedMarkdownRecordStore: RecordStore, RecordListing`.
- Produces `IndexedRecordMetadata(category:title:source:)` and
  `IndexedRecordStoring.save(_:metadata:) async throws`.
- Produces `select(indexURL:) async throws`, `indexURL() async -> URL?`, and `entries() async throws -> [IndexedEncryptedRecord]`.
- Produces `LegacyRecordMigration.migrate(from:to:) async throws -> Int`.

- [ ] **Step 1: Write failing record-store and migration tests**

```swift
@Test func selectedMarkdownStoreSavesAndResolvesOnlyThroughSelectedIndex() async throws {
    let store = SelectedMarkdownRecordStore(selectionStore: InMemoryIndexSelectionStore())
    try await store.select(indexURL: temporaryDirectory.appendingPathComponent("敏感信息.md"))
    let record = fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    try await store.save(record, metadata: .init(category: "API Key", title: "OpenAI", source: nil))
    #expect(try await store.latest(id: record.id) == record)
    #expect(try await store.entries().first?.displayID == "S-001")
}

@Test func migrationKeepsLegacyFilesWhenIndexWriteFails() async throws {
    let record = fixtureRecord(id: "0123456789ABCDEFGHJKMNPQRS")
    let legacyStore = InMemoryLegacyRecordStore(records: [record])
    let indexStore = FailingIndexedRecordStore()
    do {
        _ = try await LegacyRecordMigration.migrate(from: legacyStore, to: indexStore)
        Issue.record("Expected index migration to fail")
    } catch {
        #expect(error is FailingIndexedRecordStore.Error)
    }
    #expect(try await legacyStore.latest(id: record.id) == record)
}

private actor InMemoryLegacyRecordStore: RecordStore, RecordListing {
    let records: [EncryptedRecord]
    init(records: [EncryptedRecord]) { self.records = records }
    func save(_ record: EncryptedRecord) async throws { fatalError("not used") }
    func latest(id: String) async throws -> EncryptedRecord { try #require(records.first { $0.id == id }) }
    func versions(id: String) async throws -> [Int] { records.filter { $0.id == id }.map(\.recordVersion) }
    func recordIDs() async throws -> [String] { records.map(\.id) }
}

private actor FailingIndexedRecordStore: IndexedRecordStoring {
    enum Error: Swift.Error { case write }
    func save(_ record: EncryptedRecord, metadata: IndexedRecordMetadata) async throws { throw Error.write }
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultCoreTests/SelectedMarkdownRecordStoreTests -only-testing:VaultAuthorizationTests/LegacyRecordMigrationTests`

Expected: compile failure because no selected-index store or migration service exists.

- [ ] **Step 3: Implement selected-file access and safe writes**

```swift
public protocol SensitiveIndexSelecting: Sendable {
    func selectedBookmark() async throws -> Data?
    func saveSelectedBookmark(_ bookmark: Data) async throws
}

public struct IndexedRecordMetadata: Equatable, Sendable {
    public let category: String
    public let title: String
    public let source: SensitiveSourceLocation?
}

public protocol IndexedRecordStoring: Sendable {
    func save(_ record: EncryptedRecord, metadata: IndexedRecordMetadata) async throws
}

public actor SelectedMarkdownRecordStore: RecordStore, RecordListing, IndexedRecordStoring {
    public func select(indexURL: URL) async throws
    public func latest(id: String) async throws -> EncryptedRecord
    public func save(_ record: EncryptedRecord) async throws
    public func entries() async throws -> [IndexedEncryptedRecord]
}
```

Resolve and start access to the stored security-scoped bookmark only for each operation. Reject a selected file or parent directory that is a symbolic link. On save, read and decode the current file, append or version the entry, write a decoded-and-re-encoded temporary sibling, verify the temporary content, then atomically rename it. Generate the next display ID from the maximum numeric `S-` ID. Add `save(_:metadata:)` for App and IPC callers; plain `save(_:)` uses a `未分类` / `未命名` migration-safe default. Migration copies every valid legacy record into the selected index with preserved envelope bytes, a safe existing label as title when available, and no source location; it never deletes legacy files.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultCoreTests/SelectedMarkdownRecordStoreTests -only-testing:VaultAuthorizationTests/LegacyRecordMigrationTests`

Expected: PASS; corrupt selected files fail closed, saves survive a store reload, and migration failure leaves legacy content intact.

- [ ] **Step 5: Commit the selected index store**

```bash
git add Sources/VaultCore/Store/SelectedMarkdownRecordStore.swift \
  Sources/AgentSecretVaultApp/AppServices/SensitiveIndexSelectionStore.swift \
  Sources/AgentSecretVaultApp/AppServices/LegacyRecordMigration.swift \
  Tests/VaultCoreTests/SelectedMarkdownRecordStoreTests.swift \
  Tests/VaultAuthorizationTests/LegacyRecordMigrationTests.swift
git commit -m "feat: store records in selected markdown index"
```

### Task 3: Route App services and IPC through index metadata

**Files:**
- Modify: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Modify: `Sources/VaultIPC/IPCMessage.swift`
- Modify: `Sources/VaultIPC/IPCRequestHandler.swift`
- Modify: `mcp-server/src/protocol.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/ipc/protocol.ts`
- Test: `Tests/VaultIPCTests/IPCMessageTests.swift`
- Test: `Tests/VaultIPCTests/IPCRequestHandlerTests.swift`
- Test: `obsidian-plugin/agent-secret-vault/test/protocol.test.ts`

**Interfaces:**
- Produces `SecretReferencePresentation(reference:displayID:title:)`.
- Changes `encryptText` response from a bare reference to a presentation while retaining `reference` for compatibility.
- Adds `VaultAppServices.selectSensitiveIndex(url:) async throws` and `sensitiveIndexEntries() async throws`.

- [ ] **Step 1: Write failing IPC presentation tests**

```swift
@Test func encryptTextResponseIncludesReadableReferencePresentation() throws {
    let encoded = try JSONEncoder().encode(
        IPCResponse.created(.init(reference: "secret://0123456789ABCDEFGHJKMNPQRS", displayID: "S-001", title: "OpenAI API Key"))
    )
    #expect(try JSONDecoder().decode(IPCResponse.self, from: encoded) == .created(.init(reference: "secret://0123456789ABCDEFGHJKMNPQRS", displayID: "S-001", title: "OpenAI API Key")))
}
```

```ts
expect(IpcResponse.parse({
  type: "created",
  reference: "secret://0123456789ABCDEFGHJKMNPQRS",
  displayID: "S-001",
  title: "OpenAI API Key"
})).toMatchObject({ type: "created", displayID: "S-001" });
```

- [ ] **Step 2: Run the focused IPC tests and verify they fail**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultIPC -destination 'platform=macOS' test -only-testing:VaultIPCTests/IPCMessageTests -only-testing:VaultIPCTests/IPCRequestHandlerTests && cd obsidian-plugin/agent-secret-vault && npm test -- --run test/protocol.test.ts`

Expected: compile or assertion failure because a created response has only `reference`.

- [ ] **Step 3: Implement presentation-aware encryption without changing secret resolution**

```swift
public struct SecretReferencePresentation: Codable, Equatable, Sendable {
    public let reference: String
    public let displayID: String
    public let title: String
}
```

Make the App runtime inject `SelectedMarkdownRecordStore` into both `EncryptSelectionCoordinator` and `VaultRecordResolver`; do not construct `FileRecordStore` as the active source. Have `encryptText` save index metadata then return a `SecretReferencePresentation`. Update IPC's `created` payload and both TypeScript zod schemas to require `displayID` and `title` while keeping the existing `reference` field. Return `SENSITIVE_INDEX_NOT_SELECTED` when encryption or resolution occurs before a file is configured. Keep all reveal, restore, MCP, orphan-scan, and policy authorization paths resolving the same `secret://` ID through the selected store.

- [ ] **Step 4: Run the focused IPC tests and verify they pass**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultIPC -destination 'platform=macOS' test -only-testing:VaultIPCTests/IPCMessageTests -only-testing:VaultIPCTests/IPCRequestHandlerTests && cd obsidian-plugin/agent-secret-vault && npm test -- --run test/protocol.test.ts`

Expected: PASS; created messages preserve the opaque reference and expose only safe display metadata.

- [ ] **Step 5: Commit service and IPC routing**

```bash
git add Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift \
  Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift \
  Sources/VaultIPC/IPCMessage.swift Sources/VaultIPC/IPCRequestHandler.swift \
  mcp-server/src/protocol.ts obsidian-plugin/agent-secret-vault/src/ipc/protocol.ts \
  Tests/VaultIPCTests/IPCMessageTests.swift Tests/VaultIPCTests/IPCRequestHandlerTests.swift \
  obsidian-plugin/agent-secret-vault/test/protocol.test.ts
git commit -m "feat: return indexed secret presentations"
```

### Task 4: Build local App scan models and source-replacement transaction

**Files:**
- Create: `Sources/AgentSecretVaultApp/SensitiveIndex/SensitiveCandidateScanner.swift`
- Create: `Sources/AgentSecretVaultApp/SensitiveIndex/SensitiveScanCandidate.swift`
- Create: `Sources/AgentSecretVaultApp/SensitiveIndex/SourceMarkdownReplacement.swift`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Test: `Tests/VaultAuthorizationTests/SensitiveCandidateScannerTests.swift`
- Test: `Tests/VaultAuthorizationTests/SourceMarkdownReplacementTests.swift`

**Interfaces:**
- Produces `SensitiveScanCandidate(sourceURL:range:paragraph:category:risk:contentHash:)`.
- Produces `SensitiveRisk = .critical | .high | .review`.
- Produces `commitCandidate(_:category:title:) async throws -> SecretReferencePresentation`.
- Produces `commitManual(plaintext:category:title:) async throws -> SecretReferencePresentation`.

- [ ] **Step 1: Write failing local-scan and source-write tests**

```swift
@Test func scannerReturnsSortedCredentialCandidatesWithoutSelectingThem() {
    let candidates = SensitiveCandidateScanner().scan(
        text: "联系 user@example.com\n密码：example-password",
        sourceURL: URL(fileURLWithPath: "/tmp/notes.md")
    )
    #expect(candidates.map(\.risk) == [.high, .review])
    #expect(candidates.allSatisfy { !$0.isSelected })
}

@Test func sourceReplacementUsesReadableLinkOnlyWhenSnapshotMatches() throws {
    let candidate = SensitiveScanCandidate(
        sourceURL: URL(fileURLWithPath: "/tmp/notes.md"), range: 3..<19,
        paragraph: "密码：example-password", category: "密码", risk: .high,
        contentHash: "fixture", isSelected: false
    )
    let updated = try SourceMarkdownReplacement.replace(
        text: "密码：example-password",
        candidate: candidate,
        presentation: .init(reference: "secret://0123456789ABCDEFGHJKMNPQRS", displayID: "S-001", title: "NAS 密码")
    )
    #expect(updated == "密码：[S-001 NAS 密码](secret://0123456789ABCDEFGHJKMNPQRS)")
}

@Test func manualCommitWritesAnIndexedRecordWithoutCreatingASourceReplacement() async throws {
    let presentation = try await service.commitManual(
        plaintext: "example-password", category: "密码", title: "NAS 密码"
    )
    #expect(presentation.displayID == "S-001")
    #expect(try await selectedStore.entries().count == 1)
}
```

- [ ] **Step 2: Run the focused App-model tests and verify they fail**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/SensitiveCandidateScannerTests -only-testing:VaultAuthorizationTests/SourceMarkdownReplacementTests`

Expected: compile failure because there is no App-side candidate model, scanner, or readable-link replacement.

- [ ] **Step 3: Implement deterministic candidate generation and explicit commit**

Implement Foundation regular-expression rules for password assignments, API keys, bearer tokens, private keys, JWTs, secret URL parameters, and personal identifiers. Suppress valid `secret://` targets and placeholders. Derive a full paragraph plus adjacent Markdown heading for context, a SHA-256 snapshot hash, line number, source range, category, and risk. Do not create selection state that defaults to true.

`commitCandidate` must verify the on-disk source hash before requesting encryption through the selected index store; it stores safe category/title/source metadata, then atomically writes the source replacement link. If the source changed or write fails after index success, return a recoverable `unlinkedIndexEntry` result that includes the safe presentation and never deletes the indexed secret.

`commitManual` uses the same selected-index encryption path with no source metadata and never opens or modifies a source note. It validates non-empty plaintext, category, and title before requesting the encryption key.

- [ ] **Step 4: Run the focused App-model tests and verify they pass**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/SensitiveCandidateScannerTests -only-testing:VaultAuthorizationTests/SourceMarkdownReplacementTests`

Expected: PASS; rules sort candidates, protected references do not appear, no candidate starts selected, and a changed source is rejected without replacement.

- [ ] **Step 5: Commit candidate scanning and transactions**

```bash
git add Sources/AgentSecretVaultApp/SensitiveIndex \
  Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift \
  Tests/VaultAuthorizationTests/SensitiveCandidateScannerTests.swift \
  Tests/VaultAuthorizationTests/SourceMarkdownReplacementTests.swift
git commit -m "feat: scan and commit sensitive note candidates"
```

### Task 5: Implement the macOS central-index workspace

**Files:**
- Create: `Sources/AgentSecretVaultApp/SensitiveIndex/SensitiveIndexWorkspaceModel.swift`
- Create: `Sources/AgentSecretVaultApp/SensitiveIndex/SensitiveIndexWorkspaceView.swift`
- Modify: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`
- Modify: `Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift`
- Test: `Tests/VaultAuthorizationTests/SensitiveIndexWorkspaceModelTests.swift`
- Test: `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`

**Interfaces:**
- Produces `@MainActor final class SensitiveIndexWorkspaceModel: ObservableObject`.
- Produces `SensitiveIndexWorkspaceView` using `NavigationSplitView` and an AppKit file/folder picker.
- Adds the workbench section `.sensitiveIndex`.

- [ ] **Step 1: Write failing workspace-model and navigation tests**

```swift
@Test func workspaceRequiresExplicitCommitAndShowsRecoverableWriteFailure() async {
    let candidate = SensitiveScanCandidate(
        sourceURL: URL(fileURLWithPath: "/tmp/notes.md"), range: 3..<19,
        paragraph: "密码：example-password", category: "密码", risk: .high,
        contentHash: "fixture", isSelected: false
    )
    let model = SensitiveIndexWorkspaceModel(service: FailingSourceWorkspaceService())
    await model.load(candidates: [candidate])
    #expect(model.selectedCandidate == candidate)
    #expect(model.canCommit == false)
    model.category = "API Key"
    model.title = "OpenAI API Key"
    #expect(model.canCommit)
    await model.commitSelected()
    #expect(model.result?.state == .needsSourceRepair)
}

@Test func workbenchExposesCentralSensitiveIndexSection() throws {
    let workbenchURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: workbenchURL)
    #expect(source.contains("case sensitiveIndex"))
    #expect(source.contains("敏感信息"))
}
```

- [ ] **Step 2: Run the focused workspace tests and verify they fail**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/SensitiveIndexWorkspaceModelTests -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests`

Expected: compile or assertion failure because the central-index view and workbench section do not exist.

- [ ] **Step 3: Build the compact five-area App UI**

Use `NavigationSplitView` with a narrow left scan-scope/file list, a risk-sorted candidate table, a fixed inspector for category/title and `写入敏感信息.md` / `忽略`, a compact result panel, and a source-link preview. Keep candidate text in model memory only. Use `NSOpenPanel` for selecting the index file and scan scope, show the selected path in the toolbar, and present empty, locked, malformed-index, and write-repair states. The primary write button remains disabled until a candidate is selected and both category and title are non-empty. Put compact index search/manual-entry/maintenance controls in the same section; keep menu-bar views compact and do not render scan plaintext there.

The manual-entry sheet requires plaintext, category, and title, calls `commitManual`, clears its plaintext state after success, cancellation, lock, or error dismissal, and shows only the resulting display ID and reference preview after completion.

- [ ] **Step 4: Run the focused workspace tests and verify they pass**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test -only-testing:VaultAuthorizationTests/SensitiveIndexWorkspaceModelTests -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests`

Expected: PASS; committing is explicit, failures remain actionable, and the workbench exposes the new central workspace.

- [ ] **Step 5: Commit the App workspace**

```bash
git add Sources/AgentSecretVaultApp/SensitiveIndex \
  Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift \
  Tests/VaultAuthorizationTests/SensitiveIndexWorkspaceModelTests.swift \
  Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift
git commit -m "feat: add central sensitive index workspace"
```

### Task 6: Preserve Obsidian manual fallback with readable links

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/encrypt/encryptSelection.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts`
- Modify: `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`
- Modify: `obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts`
- Modify: `obsidian-plugin/agent-secret-vault/manifest.json`

**Interfaces:**
- Produces `formatIndexedReferenceLink(presentation): string`.
- `encryptTextRange` returns `{ updatedText, presentation }`.
- Keeps manual `encrypt-selection`, `reveal-selection`, `reveal-current-paragraph`, `restore-selection`, and `restore-current-paragraph` commands.

- [ ] **Step 1: Write failing readable-link and command-scope tests**

```ts
it("replaces selected text with a readable indexed reference link", async () => {
  const result = await encryptTextRange({
    documentText: "token = example-token",
    range: { start: 8, end: 21, text: "example-token" },
    label: "token = [[ASV_REFERENCE]]",
    policy: "credential",
    client: {
      request: async () => ({
        type: "created",
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        displayID: "S-001",
        title: "OpenAI API Key"
      })
    }
  });
  expect(result.updatedText).toBe("token = [S-001 OpenAI API Key](secret://0123456789ABCDEFGHJKMNPQRS)");
});

it("keeps only manual encryption and reveal or restore commands in Obsidian", () => {
  expect(commandDefinitions.map((command) => command.id)).toEqual([
    "encrypt-selection", "reveal-selection", "reveal-current-paragraph", "restore-selection", "restore-current-paragraph"
  ]);
});
```

- [ ] **Step 2: Run the focused Obsidian tests and verify they fail**

Run: `npm test -- --run test/encryptSelection.test.ts test/pluginCommands.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: FAIL because encryption writes a bare reference and scan commands are still registered.

- [ ] **Step 3: Format safe links and remove plugin-owned scan flow**

```ts
export function formatIndexedReferenceLink(presentation: SecretReferencePresentation): string {
  return `[${escapeMarkdown(presentation.displayID)} ${escapeMarkdown(presentation.title)}](${presentation.reference})`;
}
```

Escape link-label brackets and backslashes, but never alter the validated `secret://` target. Update manual selection encryption to replace with this link after verifying the selected editor range remains unchanged. Remove current-paragraph and all-vault scan commands from the command palette and context menu; retain manual encrypt, temporary reveal, and restore. Update manifest copy and tests. The existing reference extractor and paragraph restore builder continue to find `secret://` inside the Markdown link target.

- [ ] **Step 4: Run the focused Obsidian tests and verify they pass**

Run: `npm test -- --run test/encryptSelection.test.ts test/pluginCommands.test.ts test/paragraphReveal.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: PASS; manual encryption writes a readable link and reveal/restore still use the opaque reference target.

- [ ] **Step 5: Commit the Obsidian fallback**

```bash
git add obsidian-plugin/agent-secret-vault/src/encrypt/encryptSelection.ts \
  obsidian-plugin/agent-secret-vault/src/main.ts \
  obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts \
  obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts \
  obsidian-plugin/agent-secret-vault/manifest.json
git commit -m "feat: write readable indexed obsidian links"
```

### Task 7: Full verification, generated artifacts, and release readiness

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/main.js`
- Verify: `README.md`
- Verify: `docs/security/release-checklist.md`

- [ ] **Step 1: Regenerate the Obsidian plugin artifact**

Run: `npm run build`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: `main.js` is regenerated only after TypeScript compilation succeeds.

- [ ] **Step 2: Run the complete verification suite**

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/agent-secret-vault && npm test && npm run typecheck && npm run build && npm run check:build-artifact
cd ../..
git diff --check
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/main.js obsidian-plugin/agent-secret-vault/dist
```

Expected: every command exits `0`, no plaintext canary is found, and the App/UI tests cover the source-of-truth, explicit-commit, and readable-link paths.

- [ ] **Step 3: Review release documentation and commit generated output**

Update `README.md` and `docs/security/release-checklist.md` only where the old Application Support record source or Obsidian-owned scan workflow is described. Stage the generated `main.js` with source, tests, and documentation; commit with:

```bash
git add README.md docs/security/release-checklist.md \
  obsidian-plugin/agent-secret-vault/main.js
git commit -m "docs: describe central sensitive index workflow"
```
