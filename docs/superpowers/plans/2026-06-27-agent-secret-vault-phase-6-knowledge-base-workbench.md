# Agent Secret Vault Phase 6 Knowledge-base Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a usable local knowledge-base encryption workflow: app-owned IPC, Obsidian plugin pairing, selected-text encryption, app-owned paragraph reveal, scan/review/batch replacement, context-leak warnings, and MCP safety updates.

**Architecture:** Keep the macOS app as the only decryption authority. The Obsidian plugin may send selected plaintext to the app for encryption and may modify Markdown after explicit confirmation, but app-to-plugin responses contain only references, statuses, and non-sensitive scan metadata. The plan proceeds as vertical slices so each task leaves a testable product state.

**Tech Stack:** SwiftUI, Swift Testing, CryptoKit, local Unix-domain IPC, TypeScript, Vitest, Obsidian plugin API, CodeMirror editor APIs, Zod, Node.js 24, XcodeGen.

---

## File structure map

### Swift app and shared libraries

- `Sources/VaultIPC/IPCMessage.swift`: extend request/response cases for plugin status, text encryption, app-owned reveal sessions, and orphan scans.
- `Sources/VaultIPC/IPCRequestHandler.swift`: new request router that authenticates IPC requests and calls app services.
- `Sources/VaultAuthorization/AuthorizationSession.swift`: reuse existing risk separation; add tests only if handler exposes incorrect reuse.
- `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`: new dependency container for record store, cipher, authorization, reveal sessions, and IPC server lifecycle.
- `Sources/AgentSecretVaultApp/AppServices/VaultRecordResolver.swift`: new service for loading and decrypting records by `secret://` reference inside the app boundary.
- `Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift`: new in-memory store for app-owned temporary reveal sessions.
- `Sources/AgentSecretVaultApp/IPC/AppIPCController.swift`: new app-side IPC startup and request handling coordinator.
- `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`: new real dashboard shell replacing placeholder workflow sections.
- `Sources/AgentSecretVaultApp/Workbench/ConnectionStatusCard.swift`: app/plugin/IPC status.
- `Sources/AgentSecretVaultApp/Workbench/SetupGuideView.swift`: Obsidian pairing instructions and active vault root display.
- `Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift`: app-owned temporary paragraph reveal surface.
- `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift`: wire to real orphan scan state instead of static guidance.
- `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`: instantiate app services and workbench.
- `project.yml`: include new Swift files and test targets if needed.

### Swift tests

- `Tests/VaultIPCTests/IPCWorkbenchMessageTests.swift`: protocol round-trips and plaintext-field rejection.
- `Tests/VaultIPCTests/IPCRequestHandlerTests.swift`: handler routes status, encrypt, reveal, and failure responses.
- `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`: temporary reveal sessions clear correctly.
- `Tests/VaultAuthorizationTests/VaultRecordResolverTests.swift`: app can decrypt records internally without exposing plaintext in response types.
- `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`: UI copy does not overclaim security boundaries.
- `Tests/VaultCoreTests/MarkdownReferenceScannerTests.swift`: shared orphan/reference scanning if implemented in Swift.

### Obsidian plugin

- `obsidian-plugin/agent-secret-vault/package.json`: plugin scripts and test dependencies.
- `obsidian-plugin/agent-secret-vault/tsconfig.json`: TypeScript config.
- `obsidian-plugin/agent-secret-vault/manifest.json`: Obsidian plugin manifest.
- `obsidian-plugin/agent-secret-vault/src/main.ts`: plugin entrypoint and command registration.
- `obsidian-plugin/agent-secret-vault/src/ipc/protocol.ts`: Zod schemas matching Swift IPC.
- `obsidian-plugin/agent-secret-vault/src/ipc/client.ts`: local app IPC client.
- `obsidian-plugin/agent-secret-vault/src/pairing/pairing.ts`: pairing and status logic.
- `obsidian-plugin/agent-secret-vault/src/editor/selection.ts`: editor selection, paragraph extraction, and safe replacement helpers.
- `obsidian-plugin/agent-secret-vault/src/encrypt/encryptSelection.ts`: selected text and paragraph encryption.
- `obsidian-plugin/agent-secret-vault/src/reveal/paragraphReveal.ts`: paragraph reveal request builder; never receives plaintext.
- `obsidian-plugin/agent-secret-vault/src/scan/detectors.ts`: deterministic local secret detectors.
- `obsidian-plugin/agent-secret-vault/src/scan/contextLeak.ts`: semantic leakage detection and neutral rewrite suggestions.
- `obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts`: current-note and whole-vault scanner.
- `obsidian-plugin/agent-secret-vault/src/scan/scanState.ts`: non-sensitive resumable scan state.
- `obsidian-plugin/agent-secret-vault/src/replace/transactionalReplace.ts`: per-file replacement with rollback.
- `obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts`: review queue UI.
- `obsidian-plugin/agent-secret-vault/src/ui/statusBar.ts`: app connection and vault lock status.

### Obsidian plugin tests

- `obsidian-plugin/agent-secret-vault/test/protocol.test.ts`
- `obsidian-plugin/agent-secret-vault/test/selection.test.ts`
- `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`
- `obsidian-plugin/agent-secret-vault/test/paragraphReveal.test.ts`
- `obsidian-plugin/agent-secret-vault/test/detectors.test.ts`
- `obsidian-plugin/agent-secret-vault/test/contextLeak.test.ts`
- `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`
- `obsidian-plugin/agent-secret-vault/test/transactionalReplace.test.ts`

### MCP and docs

- `mcp-server/src/protocol.ts`: add paragraph reveal status-only schema if exposed.
- `mcp-server/src/server.ts`: add safe tool or update descriptions after app/plugin flow exists.
- `mcp-server/test/tools.test.ts`: canary tests for new tool contracts.
- `plugins/agent-secret-vault/skills/agent-secret-vault/SKILL.md`: update agent rules for Obsidian/plugin workflow and context leakage.
- `docs/security/threat-model.md`: move Phase 6 features from first-release exclusions into explicit scope and keep excluded local attacker classes.
- `docs/security/release-checklist.md`: add Obsidian plugin and scan-state leakage gates.
- `README.md`: update setup and usage after implementation is functional.

---

### Task 1: Extend IPC protocol for workbench operations

**Files:**
- Modify: `Sources/VaultIPC/IPCMessage.swift`
- Create: `Tests/VaultIPCTests/IPCWorkbenchMessageTests.swift`
- Modify: `mcp-server/src/protocol.ts`
- Modify: `project.yml`

- [ ] **Step 1: Write Swift IPC round-trip tests**

Add `Tests/VaultIPCTests/IPCWorkbenchMessageTests.swift`:

```swift
import Testing
import VaultIPC

@Test func workbenchRequestsRoundTripWithoutPlaintextResponseFields() throws {
    let requests: [IPCRequest] = [
        .workbenchStatus,
        .encryptText(plaintext: "local-only plaintext", label: nil, policy: .credential),
        .revealReferences(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "Paragraph reveal",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            )
        ),
        .scanOrphans(markdownReferences: ["secret://0123456789ABCDEFGHJKMNPQRS"])
    ]

    for request in requests {
        let encoded = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(IPCRequest.self, from: encoded)
        #expect(decoded == request)
    }

    let responses: [IPCResponse] = [
        .workbenchStatus(WorkbenchStatus(
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: "/tmp/kb",
            pluginConnected: true
        )),
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .revealSessionOpened(sessionID: "session-1"),
        .orphanScan(OrphanScanResult(missingRecords: [], unreferencedRecords: [])),
        .failure(code: "APP_LOCKED")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let json = String(decoding: encoded, as: UTF8.self)
        #expect(!json.contains("plaintext"))
        #expect(!json.contains("resolvedValue"))
        #expect(!json.contains("secretValue"))
        _ = try JSONDecoder().decode(IPCResponse.self, from: encoded)
    }
}
```

- [ ] **Step 2: Run Swift test and confirm failure**

Run:

```bash
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultIPCTests
```

Expected: failure because `workbenchStatus`, `encryptText`, `revealReferences`, `scanOrphans`, and supporting structs are not defined.

- [ ] **Step 3: Implement Swift protocol additions**

In `Sources/VaultIPC/IPCMessage.swift`, add:

```swift
public struct WorkbenchStatus: Codable, Equatable, Sendable {
    public let locked: Bool
    public let ipcAvailable: Bool
    public let activeKnowledgeBaseRoot: String?
    public let pluginConnected: Bool
}

public struct ReferenceRange: Codable, Equatable, Sendable {
    public let index: Int
    public let placeholder: String
}

public struct RevealContext: Codable, Equatable, Sendable {
    public let reason: String
    public let template: String
    public let ranges: [ReferenceRange]
}

public struct OrphanScanResult: Codable, Equatable, Sendable {
    public let missingRecords: [String]
    public let unreferencedRecords: [String]
}
```

Extend `IPCRequest`:

```swift
case workbenchStatus
case encryptText(plaintext: String, label: String?, policy: SecretPolicy)
case revealReferences(references: [String], context: RevealContext)
case scanOrphans(markdownReferences: [String])
```

Extend `IPCResponse`:

```swift
case workbenchStatus(WorkbenchStatus)
case revealSessionOpened(sessionID: String)
case orphanScan(OrphanScanResult)
```

Encoding rules:

- `encryptText` is the only new request allowed to carry plaintext, and it is plugin-to-app only.
- No response case may contain plaintext or decrypted values.
- Preserve all existing request/response cases for MCP compatibility.

- [ ] **Step 4: Update MCP TypeScript protocol schemas**

Modify `mcp-server/src/protocol.ts` so the shared Zod schemas recognize the new status-only response cases:

```typescript
export const WorkbenchStatus = z.object({
  locked: z.boolean(),
  ipcAvailable: z.boolean(),
  activeKnowledgeBaseRoot: z.string().nullable(),
  pluginConnected: z.boolean()
}).strict();

export const RevealSessionOpened = z.object({
  type: z.literal("revealSessionOpened"),
  sessionID: z.string().min(1)
}).strict();
```

Keep all existing MCP-facing output schemas free of plaintext fields.

- [ ] **Step 5: Run protocol tests**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultIPCTests
cd mcp-server && npm test -- protocol.test.ts && npm run typecheck
```

Expected: Swift IPC tests pass and MCP protocol tests/typecheck pass.

- [ ] **Step 6: Commit**

```bash
git add Sources/VaultIPC/IPCMessage.swift Tests/VaultIPCTests/IPCWorkbenchMessageTests.swift mcp-server/src/protocol.ts project.yml
git commit -m "feat: extend vault ipc for knowledge workbench"
```

### Task 2: Add app-side IPC request handler and service container

**Files:**
- Create: `Sources/VaultIPC/IPCRequestHandler.swift`
- Create: `Tests/VaultIPCTests/IPCRequestHandlerTests.swift`
- Create: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Create: `Sources/AgentSecretVaultApp/AppServices/VaultRecordResolver.swift`
- Create: `Tests/VaultAuthorizationTests/VaultRecordResolverTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write handler routing tests**

Add `Tests/VaultIPCTests/IPCRequestHandlerTests.swift`:

```swift
import Testing
import VaultCore
import VaultIPC

private actor SpyWorkbenchService: WorkbenchServicing {
    var encryptCalls: [String] = []

    func status() async -> WorkbenchStatus {
        WorkbenchStatus(locked: false, ipcAvailable: true, activeKnowledgeBaseRoot: "/tmp/kb", pluginConnected: true)
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        encryptCalls.append(plaintext)
        return "secret://0123456789ABCDEFGHJKMNPQRS"
    }

    func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-1"
    }

    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}

@Test func handlerReturnsStatusAndNeverPlaintextInEncryptResponse() async throws {
    let service = SpyWorkbenchService()
    let handler = IPCRequestHandler(service: service)

    let status = try await handler.handle(.workbenchStatus)
    #expect(status == .workbenchStatus(WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: "/tmp/kb",
        pluginConnected: true
    )))

    let encrypted = try await handler.handle(.encryptText(
        plaintext: "ASV_CANARY_HANDLER",
        label: nil,
        policy: .credential
    ))
    #expect(encrypted == .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"))
    let encoded = try JSONEncoder().encode(encrypted)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("ASV_CANARY_HANDLER"))
}
```

- [ ] **Step 2: Run handler test and confirm failure**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultIPCTests/handlerReturnsStatusAndNeverPlaintextInEncryptResponse
```

Expected: failure because `IPCRequestHandler` and `WorkbenchServicing` do not exist.

- [ ] **Step 3: Implement request handler**

Create `Sources/VaultIPC/IPCRequestHandler.swift`:

```swift
import Foundation
import VaultCore

public protocol WorkbenchServicing: Sendable {
    func status() async -> WorkbenchStatus
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String
    func openRevealSession(references: [String], context: RevealContext) async throws -> String
    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult
}

public enum IPCRequestHandlerError: Error, Equatable, Sendable {
    case unsupportedRequest
}

public struct IPCRequestHandler: Sendable {
    private let service: any WorkbenchServicing

    public init(service: any WorkbenchServicing) {
        self.service = service
    }

    public func handle(_ request: IPCRequest) async throws -> IPCResponse {
        switch request {
        case .workbenchStatus:
            return .workbenchStatus(await service.status())
        case let .encryptText(plaintext, label, policy):
            let reference = try await service.encryptText(plaintext, label: label, policy: policy)
            return .created(reference: reference)
        case let .revealReferences(references, context):
            let sessionID = try await service.openRevealSession(references: references, context: context)
            return .revealSessionOpened(sessionID: sessionID)
        case let .scanOrphans(markdownReferences):
            return .orphanScan(try await service.scanOrphans(markdownReferences: markdownReferences))
        default:
            throw IPCRequestHandlerError.unsupportedRequest
        }
    }
}
```

- [ ] **Step 4: Write resolver tests**

Add `Tests/VaultAuthorizationTests/VaultRecordResolverTests.swift`:

```swift
import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import AgentSecretVaultApp

@Test func resolverDecryptsInternallyByReference() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_RESOLVER".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await store.save(record)

    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let plaintext = try await resolver.resolve(
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        masterKey: key
    )
    #expect(String(decoding: plaintext, as: UTF8.self) == "ASV_CANARY_RESOLVER")
}
```

- [ ] **Step 5: Implement resolver**

Create `Sources/AgentSecretVaultApp/AppServices/VaultRecordResolver.swift`:

```swift
import CryptoKit
import Foundation
import VaultCore

public struct VaultRecordResolver: Sendable {
    private let recordStore: any RecordStore
    private let cipher: VaultCipher

    public init(recordStore: any RecordStore, cipher: VaultCipher = VaultCipher()) {
        self.recordStore = recordStore
        self.cipher = cipher
    }

    public func resolve(reference: String, masterKey: SymmetricKey) async throws -> Data {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        return try cipher.decrypt(record, masterKey: masterKey)
    }
}
```

- [ ] **Step 6: Add app service container skeleton**

Create `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`:

```swift
import Foundation
import VaultCore
import VaultIPC

public actor VaultAppServices: WorkbenchServicing {
    private let encryptSelection: any EncryptSelectionCoordinating
    private let activeRoot: URL?

    public init(encryptSelection: any EncryptSelectionCoordinating, activeRoot: URL?) {
        self.encryptSelection = encryptSelection
        self.activeRoot = activeRoot
    }

    public func status() async -> WorkbenchStatus {
        WorkbenchStatus(
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: activeRoot?.path,
            pluginConnected: false
        )
    }

    public func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        let result = try await encryptSelection.encryptAndReplace(
            plaintext: plaintext,
            label: label,
            policy: policy
        )
        switch result {
        case let .replaced(reference), let .unlinkedRecord(reference):
            return reference.description
        }
    }

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-\(UUID().uuidString)"
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}
```

This skeleton is acceptable for Task 2 because reveal/orphan behavior is tested in later dedicated tasks.

- [ ] **Step 7: Run tests**

Run:

```bash
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultIPCTests -only-testing:VaultAuthorizationTests
```

Expected: all selected tests pass.

- [ ] **Step 8: Commit**

```bash
git add Sources/VaultIPC/IPCRequestHandler.swift Sources/AgentSecretVaultApp/AppServices Tests/VaultIPCTests/IPCRequestHandlerTests.swift Tests/VaultAuthorizationTests/VaultRecordResolverTests.swift project.yml
git commit -m "feat: add app ipc workbench handler"
```

### Task 3: Replace placeholder dashboard with real workbench status

**Files:**
- Create: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`
- Create: `Sources/AgentSecretVaultApp/Workbench/ConnectionStatusCard.swift`
- Create: `Sources/AgentSecretVaultApp/Workbench/SetupGuideView.swift`
- Modify: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
- Modify: `Sources/AgentSecretVaultApp/Dashboard/VaultDashboardView.swift`
- Create: `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write copy tests**

Add `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`:

```swift
import Testing
@testable import AgentSecretVaultApp

@Test func workbenchCopyDoesNotPretendDisconnectedToolsAreReady() {
    let copy = VaultWorkbenchCopy.disconnected
    #expect(copy.primaryAction.contains("Install Obsidian plugin"))
    #expect(!copy.status.lowercased().contains("ready to encrypt"))
}

@Test func workbenchCopySaysPluginNeverReceivesDecryptedValues() {
    let boundary = VaultWorkbenchCopy.securityBoundary
    #expect(boundary.contains("plugin does not receive decrypted values"))
    #expect(!boundary.contains("plugin decrypts"))
}
```

- [ ] **Step 2: Run copy tests and confirm failure**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests
```

Expected: failure because workbench copy does not exist.

- [ ] **Step 3: Add copy model and workbench views**

Create `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`:

```swift
import SwiftUI
import VaultIPC

public enum VaultWorkbenchCopy {
    public static let disconnected = (
        status: "Obsidian plugin is not connected.",
        primaryAction: "Install Obsidian plugin and pair it with this Mac app."
    )

    public static let securityBoundary =
        "The plugin does not receive decrypted values. Paragraph reveal opens an app-owned temporary window."
}

public struct VaultWorkbenchView: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Agent Secret Vault Workbench · 知识库加密工作台")
                    .font(.largeTitle.weight(.bold))
                ConnectionStatusCard(status: status)
                SetupGuideView(status: status)
                Text(VaultWorkbenchCopy.securityBoundary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .padding(28)
        }
        .frame(minWidth: 920, minHeight: 620)
    }
}
```

Create `Sources/AgentSecretVaultApp/Workbench/ConnectionStatusCard.swift`:

```swift
import SwiftUI
import VaultIPC

public struct ConnectionStatusCard: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(status.pluginConnected ? "Plugin connected · 插件已连接" : "Plugin not connected · 插件未连接",
                  systemImage: status.pluginConnected ? "checkmark.seal.fill" : "exclamationmark.triangle")
            Text("Vault: \(status.locked ? "Locked" : "Unlocked")")
            Text("Knowledge base: \(status.activeKnowledgeBaseRoot ?? "Not selected")")
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}
```

Create `Sources/AgentSecretVaultApp/Workbench/SetupGuideView.swift`:

```swift
import SwiftUI
import VaultIPC

public struct SetupGuideView: View {
    let status: WorkbenchStatus

    public init(status: WorkbenchStatus) {
        self.status = status
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Next steps · 下一步")
                .font(.title3.weight(.semibold))
            Text(status.pluginConnected
                 ? "Use Obsidian commands to encrypt selections, scan notes, and request app-owned paragraph reveal."
                 : VaultWorkbenchCopy.disconnected.primaryAction)
            Text("No placeholder page is treated as a working encryption tool.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18))
    }
}
```

- [ ] **Step 4: Wire app entrypoint to real workbench**

Modify `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift` so `WindowGroup` instantiates `VaultWorkbenchView` with a real status from services. If async service state is not ready yet, use:

```swift
VaultWorkbenchView(status: WorkbenchStatus(
    locked: true,
    ipcAvailable: false,
    activeKnowledgeBaseRoot: nil,
    pluginConnected: false
))
```

Then remove or demote placeholder sections in `VaultDashboardView` so users cannot mistake explanatory pages for working tools.

- [ ] **Step 5: Run UI copy tests**

Run:

```bash
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Sources/AgentSecretVaultApp/Workbench Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift Sources/AgentSecretVaultApp/Dashboard/VaultDashboardView.swift Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift project.yml
git commit -m "feat: add real vault workbench status ui"
```

### Task 4: Scaffold Obsidian plugin and local test harness

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/package.json`
- Create: `obsidian-plugin/agent-secret-vault/tsconfig.json`
- Create: `obsidian-plugin/agent-secret-vault/manifest.json`
- Create: `obsidian-plugin/agent-secret-vault/src/main.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/ipc/protocol.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/ui/statusBar.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/protocol.test.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts`

- [ ] **Step 1: Add package and config**

Create `obsidian-plugin/agent-secret-vault/package.json`:

```json
{
  "name": "obsidian-agent-secret-vault",
  "version": "0.1.0",
  "type": "module",
  "private": true,
  "scripts": {
    "test": "vitest run",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "build": "tsc -p tsconfig.json"
  },
  "devDependencies": {
    "@types/node": "^24.0.0",
    "obsidian": "^1.8.7",
    "typescript": "^5.9.0",
    "vitest": "^4.1.0",
    "zod": "^4.1.0"
  }
}
```

Create `obsidian-plugin/agent-secret-vault/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "strict": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": ".",
    "types": ["node", "vitest"]
  },
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

Create `obsidian-plugin/agent-secret-vault/manifest.json`:

```json
{
  "id": "agent-secret-vault",
  "name": "Agent Secret Vault",
  "version": "0.1.0",
  "minAppVersion": "1.8.0",
  "description": "Encrypt sensitive knowledge-base text into local Agent Secret Vault references.",
  "author": "Agent Secret Vault",
  "isDesktopOnly": true
}
```

- [ ] **Step 2: Write command registration test**

Add `obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { commandDefinitions } from "../src/main";

describe("plugin commands", () => {
  it("registers core workbench commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "encrypt-selection",
      "encrypt-current-paragraph",
      "scan-current-note",
      "scan-vault",
      "reveal-current-paragraph"
    ]);
  });
});
```

- [ ] **Step 3: Add plugin IPC protocol tests**

Add `obsidian-plugin/agent-secret-vault/test/protocol.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { IpcResponse, IpcRequest } from "../src/ipc/protocol";

describe("IPC protocol", () => {
  it("allows plugin-to-app encryptText but rejects plaintext-shaped responses", () => {
    expect(IpcRequest.parse({
      type: "encryptText",
      plaintext: "local-only selected text",
      label: null,
      policy: "credential"
    })).toBeTruthy();

    expect(() => IpcResponse.parse({
      type: "revealSessionOpened",
      plaintext: "must not return"
    })).toThrow();
  });

  it("parses status-only reveal responses", () => {
    expect(IpcResponse.parse({
      type: "revealSessionOpened",
      sessionID: "session-1"
    })).toEqual({
      type: "revealSessionOpened",
      sessionID: "session-1"
    });
  });
});
```

- [ ] **Step 4: Implement plugin IPC schemas**

Create `obsidian-plugin/agent-secret-vault/src/ipc/protocol.ts`:

```typescript
import { z } from "zod";

export const SecretReference = z.string().regex(/^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/);
export const SecretPolicy = z.enum(["credential", "externalSend", "localOnly"]);

export const RevealContext = z.object({
  reason: z.string().min(1),
  template: z.string().min(1),
  ranges: z.array(z.object({
    index: z.number().int().nonnegative(),
    placeholder: z.string().min(1)
  }).strict())
}).strict();

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("workbenchStatus") }).strict(),
  z.object({
    type: z.literal("encryptText"),
    plaintext: z.string().min(1),
    label: z.string().nullable(),
    policy: SecretPolicy
  }).strict(),
  z.object({
    type: z.literal("revealReferences"),
    references: z.array(SecretReference).min(1),
    context: RevealContext
  }).strict(),
  z.object({
    type: z.literal("scanOrphans"),
    markdownReferences: z.array(SecretReference)
  }).strict()
]);

export const IpcResponse = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("workbenchStatus"),
    locked: z.boolean(),
    ipcAvailable: z.boolean(),
    activeKnowledgeBaseRoot: z.string().nullable(),
    pluginConnected: z.boolean()
  }).strict(),
  z.object({ type: z.literal("created"), reference: SecretReference }).strict(),
  z.object({ type: z.literal("revealSessionOpened"), sessionID: z.string().min(1) }).strict(),
  z.object({
    type: z.literal("orphanScan"),
    missingRecords: z.array(SecretReference),
    unreferencedRecords: z.array(SecretReference)
  }).strict(),
  z.object({ type: z.literal("failure"), code: z.string().min(1) }).strict()
]);

export type IpcRequest = z.infer<typeof IpcRequest>;
export type IpcResponse = z.infer<typeof IpcResponse>;
```

- [ ] **Step 5: Implement plugin command definitions**

Create `obsidian-plugin/agent-secret-vault/src/main.ts`:

```typescript
import { Plugin } from "obsidian";
import { updateStatusBar } from "./ui/statusBar";

export const commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
] as const;

export default class AgentSecretVaultPlugin extends Plugin {
  async onload(): Promise<void> {
    const status = this.addStatusBarItem();
    updateStatusBar(status, { connected: false, locked: true });

    for (const definition of commandDefinitions) {
      this.addCommand({
        id: definition.id,
        name: definition.name,
        callback: () => {
          console.log(`Agent Secret Vault command pending implementation: ${definition.id}`);
        }
      });
    }
  }
}
```

Create `obsidian-plugin/agent-secret-vault/src/ui/statusBar.ts`:

```typescript
export interface StatusBarState {
  connected: boolean;
  locked: boolean;
}

export function updateStatusBar(element: HTMLElement, state: StatusBarState): void {
  const connection = state.connected ? "connected" : "not connected";
  const lock = state.locked ? "locked" : "unlocked";
  element.setText(`ASV: ${connection}, ${lock}`);
}
```

- [ ] **Step 6: Run plugin tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault
npm install
npm test
npm run typecheck
npm run build
```

Expected: test, typecheck, and build pass.

- [ ] **Step 7: Commit**

```bash
git add obsidian-plugin/agent-secret-vault
git commit -m "feat: scaffold obsidian secret vault plugin"
```

### Task 5: Pair Obsidian plugin with app IPC status

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/src/ipc/client.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/pairing/pairing.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/pairing.test.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts`
- Modify: `Sources/AgentSecretVaultApp/IPC/AppIPCController.swift`
- Create: `Sources/AgentSecretVaultApp/IPC/AppIPCController.swift`
- Create: `Tests/VaultAuthorizationTests/AppIPCControllerTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write plugin pairing tests**

Add `obsidian-plugin/agent-secret-vault/test/pairing.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { interpretWorkbenchStatus } from "../src/pairing/pairing";

describe("pairing", () => {
  it("blocks operations when the app is locked or unreachable", () => {
    expect(interpretWorkbenchStatus({ reachable: false })).toEqual({
      canOperate: false,
      message: "Agent Secret Vault is unavailable."
    });

    expect(interpretWorkbenchStatus({
      reachable: true,
      status: {
        type: "workbenchStatus",
        locked: true,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    })).toEqual({
      canOperate: false,
      message: "Unlock Agent Secret Vault to continue."
    });
  });
});
```

- [ ] **Step 2: Implement pairing interpretation**

Create `obsidian-plugin/agent-secret-vault/src/pairing/pairing.ts`:

```typescript
import type { z } from "zod";
import { IpcResponse } from "../ipc/protocol";

export type WorkbenchStatusResponse = Extract<z.infer<typeof IpcResponse>, { type: "workbenchStatus" }>;

export type Reachability =
  | { reachable: false }
  | { reachable: true; status: WorkbenchStatusResponse };

export function interpretWorkbenchStatus(input: Reachability): { canOperate: boolean; message: string } {
  if (!input.reachable) {
    return { canOperate: false, message: "Agent Secret Vault is unavailable." };
  }
  if (input.status.locked) {
    return { canOperate: false, message: "Unlock Agent Secret Vault to continue." };
  }
  return { canOperate: true, message: "Agent Secret Vault is ready." };
}
```

- [ ] **Step 3: Implement IPC client**

Create `obsidian-plugin/agent-secret-vault/src/ipc/client.ts`:

```typescript
import net from "node:net";
import { IpcRequest, IpcResponse } from "./protocol";

export class LocalVaultClient {
  constructor(private readonly socketPath: string) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    const payload = Buffer.from(JSON.stringify(request), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      const chunks: Buffer[] = [];
      socket.on("connect", () => socket.write(frame));
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.on("error", reject);
      socket.on("end", () => {
        const data = Buffer.concat(chunks);
        const length = data.readUInt32BE(0);
        const json = data.subarray(4, 4 + length).toString("utf8");
        resolve(IpcResponse.parse(JSON.parse(json)));
      });
    });
  }
}
```

- [ ] **Step 4: Write App IPC controller test**

Add `Tests/VaultAuthorizationTests/AppIPCControllerTests.swift`:

```swift
import Testing
@testable import AgentSecretVaultApp

@Test func appIPCControllerPublishesEndpointMetadataWithoutSecrets() throws {
    let metadata = AppIPCController.EndpointMetadata(socketPath: "/tmp/asv.sock")
    let encoded = try JSONEncoder().encode(metadata)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(json.contains("/tmp/asv.sock"))
    #expect(!json.contains("capability"))
    #expect(!json.contains("token"))
}
```

- [ ] **Step 5: Implement AppIPCController endpoint metadata**

Create `Sources/AgentSecretVaultApp/IPC/AppIPCController.swift`:

```swift
import Foundation
import VaultIPC

public final class AppIPCController: Sendable {
    public struct EndpointMetadata: Codable, Equatable, Sendable {
        public let socketPath: String
    }

    private let server: UnixSocketServer
    private let handler: IPCRequestHandler

    public init(server: UnixSocketServer, handler: IPCRequestHandler) {
        self.server = server
        self.handler = handler
    }

    public var endpointMetadata: EndpointMetadata {
        EndpointMetadata(socketPath: server.configuration.socketURL.path)
    }
}
```

- [ ] **Step 6: Run pairing tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault && npm test -- pairing.test.ts && npm run typecheck
cd ../..
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/AppIPCControllerTests
```

Expected: all selected tests pass.

- [ ] **Step 7: Commit**

```bash
git add obsidian-plugin/agent-secret-vault/src/ipc obsidian-plugin/agent-secret-vault/src/pairing obsidian-plugin/agent-secret-vault/test/pairing.test.ts Sources/AgentSecretVaultApp/IPC Tests/VaultAuthorizationTests/AppIPCControllerTests.swift project.yml
git commit -m "feat: pair obsidian plugin with vault status"
```

### Task 6: Implement encrypt selection and encrypt paragraph

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/src/editor/selection.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/encrypt/encryptSelection.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/selection.test.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Modify: `Tests/VaultAuthorizationTests/EncryptSelectionCoordinatorTests.swift`

- [ ] **Step 1: Write selection helper tests**

Add `obsidian-plugin/agent-secret-vault/test/selection.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { extractCurrentParagraph } from "../src/editor/selection";

describe("selection helpers", () => {
  it("extracts paragraph around cursor", () => {
    const text = "alpha\n\npassword = hunter2\napi token here\n\nomega";
    expect(extractCurrentParagraph(text, text.indexOf("token"))).toEqual({
      start: 7,
      end: 35,
      text: "password = hunter2\napi token here"
    });
  });
});
```

- [ ] **Step 2: Implement selection helpers**

Create `obsidian-plugin/agent-secret-vault/src/editor/selection.ts`:

```typescript
export interface TextRange {
  start: number;
  end: number;
  text: string;
}

export function extractCurrentParagraph(documentText: string, cursorOffset: number): TextRange {
  const before = documentText.lastIndexOf("\n\n", Math.max(0, cursorOffset - 1));
  const after = documentText.indexOf("\n\n", cursorOffset);
  const start = before === -1 ? 0 : before + 2;
  const end = after === -1 ? documentText.length : after;
  return { start, end, text: documentText.slice(start, end) };
}

export function replaceRange(documentText: string, range: TextRange, replacement: string): string {
  return `${documentText.slice(0, range.start)}${replacement}${documentText.slice(range.end)}`;
}
```

- [ ] **Step 3: Write encrypt workflow tests**

Add `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { encryptTextRange } from "../src/encrypt/encryptSelection";

describe("encrypt selection", () => {
  it("replaces selected plaintext with returned reference", async () => {
    const result = await encryptTextRange({
      documentText: "token = ASV_CANARY_PLUGIN",
      range: { start: 8, end: 25, text: "ASV_CANARY_PLUGIN" },
      label: null,
      policy: "credential",
      client: {
        request: async () => ({
          type: "created",
          reference: "secret://0123456789ABCDEFGHJKMNPQRS"
        })
      }
    });

    expect(result.updatedText).toBe("token = secret://0123456789ABCDEFGHJKMNPQRS");
    expect(JSON.stringify(result)).not.toContain("ASV_CANARY_PLUGIN");
  });
});
```

- [ ] **Step 4: Implement encrypt workflow**

Create `obsidian-plugin/agent-secret-vault/src/encrypt/encryptSelection.ts`:

```typescript
import { replaceRange, type TextRange } from "../editor/selection";
import type { IpcRequest, IpcResponse } from "../ipc/protocol";

export interface VaultClientLike {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export async function encryptTextRange(input: {
  documentText: string;
  range: TextRange;
  label: string | null;
  policy: "credential" | "externalSend" | "localOnly";
  client: VaultClientLike;
}): Promise<{ updatedText: string; reference: string }> {
  const response = await input.client.request({
    type: "encryptText",
    plaintext: input.range.text,
    label: input.label,
    policy: input.policy
  });

  if (response.type !== "created") {
    throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
  }

  return {
    updatedText: replaceRange(input.documentText, input.range, response.reference),
    reference: response.reference
  };
}
```

- [ ] **Step 5: Fix app-side encryptText so it does not require editor replacement**

Modify `VaultAppServices.encryptText` so it saves encrypted records and returns references without calling `SelectionReplacing`. Extract a new app service if needed:

```swift
public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}
```

Acceptance requirement: `encryptText` must not call Obsidian replacement logic; the plugin owns Markdown replacement.

- [ ] **Step 6: Run tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault && npm test -- selection.test.ts encryptSelection.test.ts && npm run typecheck
cd ../..
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/EncryptSelectionCoordinatorTests
```

Expected: plugin tests and selected Swift tests pass.

- [ ] **Step 7: Commit**

```bash
git add obsidian-plugin/agent-secret-vault/src/editor obsidian-plugin/agent-secret-vault/src/encrypt obsidian-plugin/agent-secret-vault/test/selection.test.ts obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts Sources/AgentSecretVaultApp/AppServices Sources/AgentSecretVaultApp/EncryptSelectionCoordinator.swift Tests/VaultAuthorizationTests/EncryptSelectionCoordinatorTests.swift
git commit -m "feat: encrypt obsidian selections into secret references"
```

### Task 7: Implement app-owned paragraph reveal sessions

**Files:**
- Create: `Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift`
- Create: `Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift`
- Create: `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`
- Create: `obsidian-plugin/agent-secret-vault/src/reveal/paragraphReveal.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/paragraphReveal.test.ts`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts`

- [ ] **Step 1: Write plugin reveal request test**

Add `obsidian-plugin/agent-secret-vault/test/paragraphReveal.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { buildParagraphRevealRequest } from "../src/reveal/paragraphReveal";

describe("paragraph reveal", () => {
  it("sends references and template without asking plugin to receive plaintext", () => {
    const request = buildParagraphRevealRequest("Login with secret://0123456789ABCDEFGHJKMNPQRS now.");
    expect(request).toEqual({
      type: "revealReferences",
      references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
      context: {
        reason: "Reveal current paragraph",
        template: "Login with {{0}} now.",
        ranges: [{ index: 0, placeholder: "{{0}}" }]
      }
    });
    expect(JSON.stringify(request)).not.toContain("plaintext");
  });
});
```

- [ ] **Step 2: Implement plugin reveal request builder**

Create `obsidian-plugin/agent-secret-vault/src/reveal/paragraphReveal.ts`:

```typescript
import type { IpcRequest } from "../ipc/protocol";

const referencePattern = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g;

export function buildParagraphRevealRequest(paragraph: string): IpcRequest {
  const references = [...paragraph.matchAll(referencePattern)].map((match) => match[0]);
  let template = paragraph;
  const ranges = references.map((reference, index) => {
    const placeholder = `{{${index}}}`;
    template = template.replace(reference, placeholder);
    return { index, placeholder };
  });

  return {
    type: "revealReferences",
    references,
    context: {
      reason: "Reveal current paragraph",
      template,
      ranges
    }
  };
}
```

- [ ] **Step 3: Write reveal session store tests**

Add `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`:

```swift
import Testing
@testable import AgentSecretVaultApp

@Test func revealSessionStoreStoresResolvedParagraphAndClearsIt() async {
    let store = RevealSessionStore()
    let id = await store.create(resolvedParagraph: "Token: ASV_CANARY_REVEAL")
    #expect(await store.paragraph(id: id) == "Token: ASV_CANARY_REVEAL")
    await store.clear(id: id)
    #expect(await store.paragraph(id: id) == nil)
}
```

- [ ] **Step 4: Implement reveal session store**

Create `Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift`:

```swift
import Foundation

public actor RevealSessionStore {
    private var sessions: [String: String] = [:]

    public init() {}

    public func create(resolvedParagraph: String) -> String {
        let id = "session-\(UUID().uuidString)"
        sessions[id] = resolvedParagraph
        return id
    }

    public func paragraph(id: String) -> String? {
        sessions[id]
    }

    public func clear(id: String) {
        sessions[id] = nil
    }

    public func clearAll() {
        sessions.removeAll()
    }
}
```

- [ ] **Step 5: Add app-owned reveal window**

Create `Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift`:

```swift
import SwiftUI

public struct RevealSessionWindow: View {
    let resolvedParagraph: String
    let close: () -> Void

    public init(resolvedParagraph: String, close: @escaping () -> Void) {
        self.resolvedParagraph = resolvedParagraph
        self.close = close
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Temporary reveal · 临时解密显示")
                .font(.title2.weight(.semibold))
            Text(resolvedParagraph)
                .textSelection(.disabled)
                .padding()
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            Button("Close and clear · 关闭并清除", action: close)
        }
        .padding(22)
    }
}
```

- [ ] **Step 6: Wire app service reveal response**

Modify `VaultAppServices.openRevealSession` to:

1. Validate all references.
2. Resolve records inside the app using `VaultRecordResolver`.
3. Replace placeholders in `RevealContext.template`.
4. Store the resolved paragraph in `RevealSessionStore`.
5. Return only the session ID to IPC.

Do not add any response field containing resolved plaintext.

- [ ] **Step 7: Run reveal tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault && npm test -- paragraphReveal.test.ts && npm run typecheck
cd ../..
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/RevealSessionStoreTests
```

Expected: tests pass.

- [ ] **Step 8: Commit**

```bash
git add Sources/AgentSecretVaultApp/AppServices/RevealSessionStore.swift Sources/AgentSecretVaultApp/Workbench/RevealSessionWindow.swift Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift obsidian-plugin/agent-secret-vault/src/reveal obsidian-plugin/agent-secret-vault/test/paragraphReveal.test.ts Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift obsidian-plugin/agent-secret-vault/src/main.ts project.yml
git commit -m "feat: reveal paragraphs in app-owned sessions"
```

### Task 8: Add deterministic local scanner and context-leak warnings

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/src/scan/detectors.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/scan/contextLeak.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/detectors.test.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/contextLeak.test.ts`

- [ ] **Step 1: Write detector tests**

Add `obsidian-plugin/agent-secret-vault/test/detectors.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { detectSensitiveText } from "../src/scan/detectors";

describe("detectors", () => {
  it("finds high-confidence secrets without remote calls", () => {
    const findings = detectSensitiveText("OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef");
    expect(findings).toEqual([{
      start: 15,
      end: 55,
      ruleId: "openai-api-key",
      confidence: "high",
      redactedPreview: "sk-proj-…cdef"
    }]);
  });
});
```

- [ ] **Step 2: Implement detectors**

Create `obsidian-plugin/agent-secret-vault/src/scan/detectors.ts`:

```typescript
export type Confidence = "high" | "medium" | "low";

export interface Finding {
  start: number;
  end: number;
  ruleId: string;
  confidence: Confidence;
  redactedPreview: string;
}

const rules: Array<{ ruleId: string; confidence: Confidence; pattern: RegExp }> = [
  { ruleId: "openai-api-key", confidence: "high", pattern: /sk-proj-[A-Za-z0-9_-]{20,}/g },
  { ruleId: "private-key", confidence: "high", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { ruleId: "bearer-token", confidence: "high", pattern: /Bearer\s+[A-Za-z0-9._-]{20,}/g },
  { ruleId: "password-assignment", confidence: "medium", pattern: /(password|passwd|pwd)\s*[:=]\s*\S{8,}/gi }
];

export function detectSensitiveText(text: string): Finding[] {
  return rules.flatMap((rule) => {
    const matches = [...text.matchAll(rule.pattern)];
    return matches.map((match) => {
      const value = match[0];
      const start = match.index ?? 0;
      return {
        start,
        end: start + value.length,
        ruleId: rule.ruleId,
        confidence: rule.confidence,
        redactedPreview: redact(value)
      };
    });
  }).sort((a, b) => a.start - b.start);
}

function redact(value: string): string {
  if (value.length <= 10) return "********";
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}
```

- [ ] **Step 3: Write context-leak tests**

Add `obsidian-plugin/agent-secret-vault/test/contextLeak.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { detectContextLeaks } from "../src/scan/contextLeak";

describe("context leak detection", () => {
  it("warns when surrounding text reveals secret type", () => {
    expect(detectContextLeaks("我的 Gmail 密码是 secret://0123456789ABCDEFGHJKMNPQRS")).toEqual([{
      ruleId: "semantic-secret-label",
      message: "Surrounding text reveals the secret type.",
      suggestion: "凭据：secret://0123456789ABCDEFGHJKMNPQRS"
    }]);
  });
});
```

- [ ] **Step 4: Implement context-leak warnings**

Create `obsidian-plugin/agent-secret-vault/src/scan/contextLeak.ts`:

```typescript
const referencePattern = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/;
const riskyWords = /(密码|password|token|api key|root key|银行卡|card number)/i;

export interface ContextLeakWarning {
  ruleId: string;
  message: string;
  suggestion: string;
}

export function detectContextLeaks(line: string): ContextLeakWarning[] {
  const reference = line.match(referencePattern)?.[0];
  if (!reference || !riskyWords.test(line)) {
    return [];
  }
  return [{
    ruleId: "semantic-secret-label",
    message: "Surrounding text reveals the secret type.",
    suggestion: `凭据：${reference}`
  }];
}
```

- [ ] **Step 5: Run scanner tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault
npm test -- detectors.test.ts contextLeak.test.ts
npm run typecheck
```

Expected: tests pass and no network dependency is used.

- [ ] **Step 6: Commit**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan obsidian-plugin/agent-secret-vault/test/detectors.test.ts obsidian-plugin/agent-secret-vault/test/contextLeak.test.ts
git commit -m "feat: detect knowledge-base secrets locally"
```

### Task 9: Implement review queue, scan state, and transactional replacement

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/src/scan/scanState.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/replace/transactionalReplace.ts`
- Create: `obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/transactionalReplace.test.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts`

- [ ] **Step 1: Write scan-state no-plaintext test**

Add `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { serializeScanState } from "../src/scan/scanState";

describe("scan state", () => {
  it("does not persist matched plaintext", () => {
    const serialized = serializeScanState([{
      filePath: "secret.md",
      contentHash: "abc",
      start: 0,
      end: 17,
      ruleId: "password-assignment",
      confidence: "medium",
      redactedPreview: "password…****",
      plaintextForCurrentProcessOnly: "password=hunter2"
    }]);
    expect(serialized).not.toContain("hunter2");
    expect(JSON.parse(serialized)[0].redactedPreview).toBe("password…****");
  });
});
```

- [ ] **Step 2: Implement scan state serialization**

Create `obsidian-plugin/agent-secret-vault/src/scan/scanState.ts`:

```typescript
import type { Confidence } from "./detectors";

export interface ScanFindingState {
  filePath: string;
  contentHash: string;
  start: number;
  end: number;
  ruleId: string;
  confidence: Confidence;
  redactedPreview: string;
  reference?: string;
  plaintextForCurrentProcessOnly?: string;
}

export function serializeScanState(findings: ScanFindingState[]): string {
  return JSON.stringify(findings.map(({ plaintextForCurrentProcessOnly: _omit, ...safe }) => safe));
}
```

- [ ] **Step 3: Write transactional replacement tests**

Add `obsidian-plugin/agent-secret-vault/test/transactionalReplace.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { applyReplacements } from "../src/replace/transactionalReplace";

describe("transactional replacement", () => {
  it("applies replacements from the end to preserve offsets", () => {
    expect(applyReplacements("a SECRET1 b SECRET2 c", [
      { start: 2, end: 9, replacement: "secret://0123456789ABCDEFGHJKMNPQRS" },
      { start: 12, end: 19, replacement: "secret://0123456789ABCDEFGHJKMNPQRT" }
    ])).toBe("a secret://0123456789ABCDEFGHJKMNPQRS b secret://0123456789ABCDEFGHJKMNPQRT c");
  });
});
```

- [ ] **Step 4: Implement transactional replacement**

Create `obsidian-plugin/agent-secret-vault/src/replace/transactionalReplace.ts`:

```typescript
export interface Replacement {
  start: number;
  end: number;
  replacement: string;
}

export function applyReplacements(text: string, replacements: Replacement[]): string {
  return [...replacements]
    .sort((a, b) => b.start - a.start)
    .reduce((current, replacement) => {
      return `${current.slice(0, replacement.start)}${replacement.replacement}${current.slice(replacement.end)}`;
    }, text);
}
```

- [ ] **Step 5: Implement vault scanner orchestration**

Create `obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts`:

```typescript
import { createHash } from "node:crypto";
import { detectSensitiveText } from "./detectors";
import type { ScanFindingState } from "./scanState";

export function scanMarkdownFile(filePath: string, text: string): ScanFindingState[] {
  const contentHash = createHash("sha256").update(text).digest("hex");
  return detectSensitiveText(text).map((finding) => ({
    filePath,
    contentHash,
    start: finding.start,
    end: finding.end,
    ruleId: finding.ruleId,
    confidence: finding.confidence,
    redactedPreview: finding.redactedPreview,
    plaintextForCurrentProcessOnly: text.slice(finding.start, finding.end)
  }));
}
```

Create `obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts`:

```typescript
import { Modal, App } from "obsidian";
import type { ScanFindingState } from "../scan/scanState";

export class ReviewModal extends Modal {
  constructor(app: App, private readonly findings: ScanFindingState[]) {
    super(app);
  }

  onOpen(): void {
    this.contentEl.empty();
    this.contentEl.createEl("h2", { text: "Agent Secret Vault review queue" });
    for (const finding of this.findings) {
      this.contentEl.createEl("div", {
        text: `${finding.filePath}: ${finding.ruleId} (${finding.confidence}) ${finding.redactedPreview}`
      });
    }
  }
}
```

- [ ] **Step 6: Run scan/replacement tests**

Run:

```bash
cd obsidian-plugin/agent-secret-vault
npm test -- scanState.test.ts transactionalReplace.test.ts
npm run typecheck
```

Expected: tests pass.

- [ ] **Step 7: Commit**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan/scanState.ts obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts obsidian-plugin/agent-secret-vault/src/replace obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts obsidian-plugin/agent-secret-vault/test/scanState.test.ts obsidian-plugin/agent-secret-vault/test/transactionalReplace.test.ts obsidian-plugin/agent-secret-vault/src/main.ts
git commit -m "feat: add reviewed vault scan replacement flow"
```

### Task 10: Wire orphan review to real reference scans

**Files:**
- Modify: `Sources/VaultCore/Store/OrphanScanner.swift`
- Create: `Tests/VaultCoreTests/MarkdownReferenceScannerTests.swift`
- Modify: `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift`
- Modify: `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write Markdown reference scanner test**

Add `Tests/VaultCoreTests/MarkdownReferenceScannerTests.swift`:

```swift
import Testing
import VaultCore

@Test func markdownReferenceScannerFindsSecretReferences() {
    let markdown = "A secret://0123456789ABCDEFGHJKMNPQRS and secret://0123456789ABCDEFGHJKMNPQRT."
    #expect(MarkdownReferenceScanner.references(in: markdown) == [
        "secret://0123456789ABCDEFGHJKMNPQRS",
        "secret://0123456789ABCDEFGHJKMNPQRT"
    ])
}
```

- [ ] **Step 2: Implement Markdown reference scanner**

Modify `Sources/VaultCore/Store/OrphanScanner.swift` or add a focused type next to it:

```swift
public enum MarkdownReferenceScanner {
    private static let pattern = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/

    public static func references(in markdown: String) -> [String] {
        markdown.matches(of: pattern).map { String($0.output) }
    }
}
```

- [ ] **Step 3: Wire app orphan response**

Modify `VaultAppServices.scanOrphans` to compare Markdown references from the plugin with record IDs available in the active record store. Return:

```swift
OrphanScanResult(
    missingRecords: markdownReferences.filter { recordStore has no matching latest record },
    unreferencedRecords: storedReferences.filter { !markdownReferenceSet.contains($0) }
)
```

If the record store cannot list all records yet, add a `RecordListing` protocol and implement it in `FileRecordStore`.

- [ ] **Step 4: Update OrphanReviewView**

`OrphanReviewView` should display real `OrphanScanResult` categories:

- missing record referenced in Markdown;
- encrypted record not referenced by Markdown;
- no destructive delete without highest-risk authorization.

Do not show “all clear” unless a scan has run.

- [ ] **Step 5: Run orphan tests**

Run:

```bash
xcodegen generate
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultCoreTests/MarkdownReferenceScannerTests -only-testing:VaultCoreTests/OrphanScannerTests
```

Expected: selected tests pass.

- [ ] **Step 6: Commit**

```bash
git add Sources/VaultCore/Store/OrphanScanner.swift Tests/VaultCoreTests/MarkdownReferenceScannerTests.swift Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift project.yml
git commit -m "feat: wire orphan review to markdown references"
```

### Task 11: Update MCP tools and agent skill for Phase 6 boundary

**Files:**
- Modify: `mcp-server/src/protocol.ts`
- Modify: `mcp-server/src/server.ts`
- Modify: `mcp-server/test/tools.test.ts`
- Modify: `mcp-server/test/security-docs.test.ts`
- Modify: `plugins/agent-secret-vault/skills/agent-secret-vault/SKILL.md`

- [ ] **Step 1: Add MCP canary tests for paragraph reveal**

Modify `mcp-server/test/tools.test.ts`:

```typescript
it("paragraph reveal returns only local display status", async () => {
  const tools = createVaultToolDefinitions({
    request: async () => ({ type: "revealSessionOpened", sessionID: "session-1" })
  });
  const tool = tools.find((candidate) => candidate.name === "paragraph_reveal_request");
  expect(tool).toBeTruthy();

  const result = await tool!.handler({
    references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
    template: "Token {{0}}",
    reason: "show to user"
  });

  expect(JSON.stringify(result)).toContain("DISPLAYED_TO_USER");
  expect(JSON.stringify(result)).not.toContain("ASV_CANARY");
  expect(JSON.stringify(result)).not.toContain("plaintext");
});
```

- [ ] **Step 2: Implement status-only MCP tool**

Modify `mcp-server/src/server.ts` to register `paragraph_reveal_request`:

```typescript
{
  name: "paragraph_reveal_request",
  title: "Request Paragraph Reveal",
  description: "Asks the macOS app to display a paragraph with secret:// references resolved locally. Plaintext is never returned.",
  inputSchema: z.object({
    references: z.array(SecretReference).min(1),
    template: z.string().min(1),
    reason: z.string().min(1)
  }).strict(),
  outputSchema: z.object({ status: z.string().min(1) }).strict(),
  async handler(input) {
    const parsed = ParagraphRevealInput.parse(input);
    const response = await client.request({
      type: "revealReferences",
      references: parsed.references,
      context: {
        reason: parsed.reason,
        template: parsed.template,
        ranges: parsed.references.map((_, index) => ({ index, placeholder: `{{${index}}}` }))
      }
    });
    if (response.type === "revealSessionOpened") {
      return structuredResult({ status: "DISPLAYED_TO_USER" });
    }
    return structuredResult(statusOnly(response));
  }
}
```

- [ ] **Step 3: Update agent skill rules**

Modify `plugins/agent-secret-vault/skills/agent-secret-vault/SKILL.md` to include:

```markdown
## Knowledge-base rules

- Treat `secret://` references as opaque handles.
- Do not infer, classify, summarize, or transform the hidden value.
- It is acceptable to discuss visible surrounding context, but state when context may leak meaning.
- For paragraph reveal, use `paragraph_reveal_request`; never ask for plaintext in chat.
- If surrounding text says “password”, “token”, “API key”, or similar, warn that the context leaks secret type even though the value remains encrypted.
```

- [ ] **Step 4: Run MCP tests**

Run:

```bash
cd mcp-server
npm test
npm run typecheck
npm run build
```

Expected: all MCP tests pass.

- [ ] **Step 5: Commit**

```bash
git add mcp-server/src/protocol.ts mcp-server/src/server.ts mcp-server/test/tools.test.ts mcp-server/test/security-docs.test.ts plugins/agent-secret-vault/skills/agent-secret-vault/SKILL.md
git commit -m "feat: add status-only paragraph reveal mcp flow"
```

### Task 12: Update docs, release checklist, and full release gate

**Files:**
- Modify: `README.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/security/release-checklist.md`
- Modify: `scripts/scan-plaintext.sh` only if plugin output directories need inclusion.

- [ ] **Step 1: Update docs with actual usage**

Update `README.md` with:

```markdown
## Obsidian workflow

1. Open Agent Secret Vault.
2. Install the Obsidian plugin from `obsidian-plugin/agent-secret-vault`.
3. Pair the plugin with the local app.
4. Use “Agent Secret Vault: Encrypt selection” to replace selected sensitive text with a `secret://` reference.
5. Use “Scan current note” or “Scan vault” to review candidates before replacement.
6. Use “Reveal current paragraph” to open an app-owned temporary reveal window. The plugin receives only a status response, not decrypted values.
```

Update `docs/security/threat-model.md`:

- remove “automatic sensitive-information detection” and “Claude and Hermes integrations” from first-release exclusions only when implemented;
- keep excluded local attacker classes unchanged;
- add “Obsidian plugin does not receive decrypted values from app-to-plugin responses.”

Update `docs/security/release-checklist.md` with:

```markdown
- Verify Obsidian plugin scan state does not persist full plaintext.
- Verify paragraph reveal returns only status to plugin and MCP.
- Verify Obsidian search does not index revealed plaintext.
- Verify context-leak warnings trigger for labels such as password, token, API key, and 银行卡.
```

- [ ] **Step 2: Run full release gate**

Run:

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/agent-secret-vault && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/dist
git diff --check
git status --short
```

Expected:

- Xcode reports `** TEST SUCCEEDED **`.
- MCP tests pass.
- Obsidian plugin tests pass.
- Canary scanner prints no plaintext leak.
- `git diff --check` prints nothing.
- `git status --short` shows only intended tracked changes or known ignored generated files.

- [ ] **Step 3: Commit docs and release gate fixes**

```bash
git add README.md docs/security/threat-model.md docs/security/release-checklist.md scripts/scan-plaintext.sh
git commit -m "docs: document knowledge-base workbench workflow"
```

### Task 13: Final verification and branch completion

**Files:**
- No required source edits.

- [ ] **Step 1: Run final release gate fresh**

Run the full gate again from Task 12 Step 2 after the final commit.

Expected: all commands pass with the same evidence.

- [ ] **Step 2: Inspect final diff**

Run:

```bash
git status --short --branch
git log --oneline -10
```

Expected: clean tracked worktree except generated local files that are intentionally ignored or left untracked.

- [ ] **Step 3: Request code review**

Use `superpowers:requesting-code-review` before claiming the implementation is complete.

- [ ] **Step 4: Finish branch**

Use `superpowers:finishing-a-development-branch` after review and final verification pass.

---

## Plan self-review

Spec coverage:

- Real app control plane: Tasks 2, 3, 5, 7, and 10.
- Obsidian plugin: Tasks 4 through 9.
- Encrypt selection and current paragraph: Task 6.
- Paragraph reveal without plugin plaintext response: Task 7 and Task 11.
- Large-vault scan/review/batch replacement: Tasks 8 and 9.
- MCP opaque-reference boundary: Task 11.
- Semantic leakage warnings: Task 8 and docs in Task 12.
- Orphan review: Task 10.
- Release gates and canary checks: Task 12 and Task 13.

Known scope cut:

- Claude and Hermes get skill/protocol-compatible behavior through the same MCP boundary in Phase 6. Dedicated marketplace packaging for those clients should be planned only after the Obsidian plugin and app-owned reveal flow pass the release gate.

Placeholder scan:

- The plan contains no unresolved placeholder markers or deferred implementation steps.
- Each code-producing task includes file paths, test commands, expected failures, and expected passes.

Type consistency:

- Swift IPC uses `WorkbenchStatus`, `RevealContext`, `ReferenceRange`, and `OrphanScanResult` consistently across protocol, handler, and app services.
- TypeScript plugin uses `IpcRequest` / `IpcResponse` schemas consistently across client, pairing, encrypt, reveal, and tests.
