# Agent Secret Vault Phase 5: Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete recovery, encrypted audit logs, migrations, orphan cleanup, and end-to-end plaintext-leak verification.

**Architecture:** Recovery is a separate wrapping layer and never weakens device-local authorization. Audit records contain fixed metadata only and are encrypted through `VaultCore`. Release verification seeds unique canary plaintext and scans every persisted and returned artifact.

**Tech Stack:** Security/iCloud Keychain, CryptoKit, Swift Testing, shell scanning, Node/Vitest.

---

### Task 1: Implement recovery wrapping

**Files:**
- Create: `Sources/VaultAuthorization/RecoveryKeyStore.swift`
- Create: `Sources/VaultAuthorization/MasterKeyCoordinator.swift`
- Create: `Tests/VaultAuthorizationTests/MasterKeyCoordinatorTests.swift`

- [ ] **Step 1: Write recovery state tests**

Cover new vault, normal local unlock, recovery item unavailable, recovered Mac
creating a new local wrapper, malformed recovery data, and the fail-closed case
where required Keychain controls are unsupported.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement coordinator**

Store a synchronizable recovery wrapping key in an application-specific
Keychain item and store the master key only as AES-GCM wrapped bytes. After
recovery, generate a fresh non-synchronizable device key and local wrapped
copy. Expose:

```swift
public enum VaultUnlockState: Equatable {
    case ready
    case authenticationRequired
    case recoveryRequired
    case recoveryUnavailable
}
```

Never silently fall back to weaker Keychain access control.

- [ ] **Step 4: Run tests plus a signed manual Keychain matrix**

Run unit tests, then verify create/unlock/recover on two test macOS user
profiles signed into the designated test Apple account. Record supported OS
versions in `docs/security/keychain-matrix.md`.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultAuthorization Tests/VaultAuthorizationTests docs/security/keychain-matrix.md
git commit -m "feat: add fail-closed icloud key recovery"
```

### Task 2: Add encrypted audit logging and retention

**Files:**
- Create: `Sources/VaultCore/Models/AuditEvent.swift`
- Create: `Sources/VaultCore/Store/EncryptedAuditLog.swift`
- Create: `Tests/VaultCoreTests/EncryptedAuditLogTests.swift`

- [ ] **Step 1: Write field allowlist tests**

Encode every event and recursively assert it contains only timestamp,
integration, reference ID, operation, risk, authorization outcome, declared
target, status, and exit code. Verify 31-day-old records are removed while
30-day records remain.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement encrypted events**

Use a dedicated audit data key wrapped by the master key. Store one encrypted
event per file, never accept arbitrary metadata dictionaries, and export only
the fixed redacted `AuditEvent` schema.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultCore Tests/VaultCoreTests
git commit -m "feat: add encrypted bounded audit log"
```

### Task 3: Add migrations and orphan review

**Files:**
- Create: `Sources/VaultCore/Store/RecordMigrator.swift`
- Create: `Sources/VaultCore/Store/OrphanScanner.swift`
- Create: `Sources/AgentSecretVaultApp/Orphans/OrphanReviewView.swift`
- Create: `Tests/VaultCoreTests/RecordMigratorTests.swift`
- Create: `Tests/VaultCoreTests/OrphanScannerTests.swift`

- [ ] **Step 1: Write failure-preservation tests**

Inject failures before write, after temporary write, and before final rename;
assert the old record remains decryptable. Test that orphan detection scans
Markdown for exact `secret://` references and never deletes automatically.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement migration and review**

Migrate to a new version file, decode and decrypt it, then mark it current.
Orphan scanning returns candidates only. Permanent deletion is exposed through
the app's highest-risk authorization path and deletes all versions only after
explicit confirmation.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultCore Sources/AgentSecretVaultApp/Orphans Tests/VaultCoreTests
git commit -m "feat: add safe migrations and orphan review"
```

### Task 4: Add end-to-end plaintext leak gates

**Files:**
- Create: `scripts/scan-plaintext.sh`
- Create: `Tests/LeakTests/LeakFixtureTests.swift`
- Create: `mcp-server/test/leak-e2e.test.ts`
- Modify: `project.yml`
- Modify: `mcp-server/package.json`

- [ ] **Step 1: Write a deliberately failing canary test**

Use a unique fixture such as
`ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST`. Persist a temporary plaintext file and
assert the scanner exits non-zero and prints only the file path, not the
canary.

- [ ] **Step 2: Run and verify failure**

```bash
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts
```

Expected: non-zero while the deliberate leak exists.

- [ ] **Step 3: Implement and wire the scanner**

The script accepts the canary through an environment variable, searches app
containers, test sidecars, logs, MCP captures, generated crash fixtures, and
Codex fixture transcripts with `rg -l --fixed-strings`, and never echoes the
matched value. Remove the deliberate leak after proving detection.

- [ ] **Step 4: Run the release gate**

```bash
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts
git diff --check
```

Expected: all tests PASS, scanner exits zero, and no formatting errors.

- [ ] **Step 5: Commit**

```bash
git add scripts Tests/LeakTests mcp-server project.yml
git commit -m "test: add end-to-end plaintext leak gate"
```

### Task 5: Complete security documentation and release checklist

**Files:**
- Create: `README.md`
- Create: `docs/security/threat-model.md`
- Create: `docs/security/release-checklist.md`

- [ ] **Step 1: Write documentation assertions**

Add a Vitest that checks all excluded threats from the approved specification
appear in `threat-model.md`, and that the release checklist includes every
acceptance criterion numbered 1 through 12.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because documents are absent.

- [ ] **Step 3: Write documentation**

Document setup, opaque-reference behavior, authorization classes, recovery
limitations, same-user/root exclusions, clipboard best-effort behavior, no
bulk export, and the exact release-gate commands from Task 4.

- [ ] **Step 4: Run final verification**

Run the complete release gate from Task 4 and `git status --short`.
Expected: all checks PASS and only intended documentation changes remain.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/security mcp-server/test
git commit -m "docs: add security and release guidance"
```

