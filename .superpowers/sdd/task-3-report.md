# Task 3 Report: Shared Menu-Bar Runtime and Termination Control

## Status

Completed and committed as `4209107 feat: keep vault running from menu bar`.

## Scope

Changed only the required application entry point, a new lifecycle test, and the Xcode project metadata needed to compile that test. Existing untracked task documents and review artifacts were not staged or modified.

## Implementation

- The main workbench scene now uses `WindowGroup(id: MenuBarPresentation.mainWindowID)`, matching the compact panel's existing `openWindow(id:)` call for reliable reopening.
- Added `MenuBarExtra("Agent Secret Vault", systemImage: MenuBarPresentation.statusItemSymbol)` with `.menuBarExtraStyle(.window)`.
- The menu panel receives the same `AgentSecretVaultRuntime` published state and restore/refresh closures as the main workbench. It also receives runtime session clearing and the delegate's menu-only termination request.
- Both scene entry points call the existing idempotent `runtime.start()`, so they share one runtime instead of creating separate IPC or vault-service state.
- Main-window focus, sleep, lock, and application-termination cleanup behavior is unchanged.

## Termination Behavior

- `applicationShouldTerminateAfterLastWindowClosed` always returns `false`; closing the main window leaves the process alive for the menu-bar extra.
- The default `.appTermination` command group is empty, removing the advertised Command-Q path while preserving the existing Navigation menu and its Command-1 through Command-6 shortcuts.
- `requestMenuBarTermination()` is the only assignment site for `permitsTermination`. It clears reveal sessions, grants the permit, then requests termination.
- `applicationShouldTerminate` cancels every unpermitted termination request and allows only the request made after the compact panel's Quit action.

## Tests and Review

- TDD red phase: the file selector compiled but executed zero Swift Testing cases, so the required target-level run was used. It ran 96 tests and failed the two new lifecycle tests with 11 expected missing-source assertions.
- Green phase: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test` passed all 96 Swift Testing cases.
- The final staged diff passed `git diff --cached --check`. Self-review confirmed the staged file list was limited to the app file, lifecycle test, and project metadata; `permitsTermination = true` has exactly one assignment in the app source.

## Concerns

No known implementation concerns. The focused Xcode selector is ineffective for these Swift Testing cases in this project, so target-level testing is the reliable verification path. No interactive GUI session was run; the app and lifecycle scene compile as part of the successful target-level test build.

---

# Task 3 Lifecycle Remediation

## Status

Completed on 2026-07-12. The lifecycle boundary now belongs to the shared runtime, authoritative reveal-session storage is awaited before menu-bar termination is permitted, and the main workbench uses a singleton `Window` scene.

## Diagnosis

- Commit `4209107` left application and workspace observers attached to the main `WindowGroup` content. Closing that window removed the only observers while the menu-bar process and IPC runtime remained alive.
- `AgentSecretVaultRuntime.clearRevealSessions()` only closed registered reveal windows. It did not clear sessions that lacked a registered window and did not await `RevealSessionStore.clearAll()`.
- `requestMenuBarTermination()` permitted termination immediately after requesting window closure, so delayed window-driven store cleanup could lose the race with process exit.
- `WindowGroup(id:)` allowed repeated main-window open requests to create multiple workbench windows.

## TDD Evidence

### RED

Command:

```sh
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS' test
```

Result: exit 65, `TEST FAILED`. Compilation stopped at `MenuBarLifecycleTests.swift` with `cannot find 'VaultLifecycleMonitor' in scope`, proving the new runtime-owned lifecycle behavior was absent before production edits.

### GREEN

The first production run compiled and executed all 100 tests. The injected lifecycle monitor test and awaited service/store clearing test passed, while one source-wiring test failed only because it assumed a one-line delegate function declaration. The assertion was made formatting-independent without weakening the required async cleanup contract.

The same target-level command was rerun. Result: exit 0, `TEST SUCCEEDED`; 100 Swift Testing tests passed with 0 failures.

### Full Scheme

Command:

```sh
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' test
```

Result: exit 0, `TEST SUCCEEDED`. The result bundle reported 142 total tests, 0 failures, 0 skipped, and no runtime warnings.

Additional verification: `git diff --cached --check` passed before the implementation commit.

## Implementation

- Added `VaultLifecycleMonitor`, with injectable application/workspace notification centers and idempotent startup, covering application resign-active, screen sleep, workspace sleep, session resign-active, and application will-terminate.
- `AgentSecretVaultRuntime` owns and starts the monitor after its IPC/service runtime starts. Monitor callbacks use the same async runtime clear path as retained view observers.
- Added `VaultAppServices.clearRevealSessions()`, which awaits the authoritative store's `clearAll()`.
- Runtime clearing synchronously requests `RevealSessionLifecycle.clearAll()` on the main actor, then awaits service/store clearing.
- Menu-panel sensitive-state and Quit closures are async. The panel still receives the single shared runtime and does not construct IPC state.
- `AgentSecretVaultAppDelegate.requestMenuBarTermination(cleanup:)` rejects duplicate pending requests, awaits cleanup, then grants the one termination permit and calls `NSApp.terminate(nil)`. Ordinary termination remains denied and no alternate Quit item was added.
- Replaced `WindowGroup(id:)` with singleton `Window("Agent Secret Vault", id:)`. Main workbench visual layout and copy were not changed.

## Changed Paths

- `AgentSecretVault.xcodeproj/project.pbxproj`
- `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
- `Sources/AgentSecretVaultApp/AppServices/VaultAppServices.swift`
- `Sources/AgentSecretVaultApp/AppServices/VaultLifecycleMonitor.swift`
- `Sources/AgentSecretVaultApp/MenuBar/MenuBarVaultPanel.swift`
- `Tests/VaultAuthorizationTests/MenuBarLifecycleTests.swift`
- `Tests/VaultAuthorizationTests/RevealSessionStoreTests.swift`
- `.superpowers/sdd/task-3-report.md`

## Commits

- Baseline under remediation: `4209107 feat: keep vault running from menu bar`
- Lifecycle remediation: `3c77867 fix: remediate vault lifecycle cleanup`
- This appended report is committed separately as `docs: record task 3 lifecycle remediation`.

## Remaining Concerns

- No interactive GUI automation was run to visually exercise repeated Open Main Window and menu-bar Quit. The singleton scene and async termination wiring compile in the full app scheme and are covered by deterministic source/behavior tests.
- Xcode beta emitted its existing IDE launch-session diagnostic warning during command-line tests; the xcresult summary contained no runtime warnings and all tests passed.
