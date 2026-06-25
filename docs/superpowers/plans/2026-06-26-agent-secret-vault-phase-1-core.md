# Agent Secret Vault Phase 1: Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and test opaque references, AES-GCM envelope encryption, and the conflict-safe sidecar record store.

**Architecture:** `VaultCore` is a UI-independent Swift framework. Every secret has a random ID and data key; the data key is wrapped by a supplied master key. Versioned JSON record files are the synchronized source of truth.

**Tech Stack:** Swift 6, CryptoKit, Foundation, XCTest/Swift Testing, XcodeGen.

---

### Task 1: Create the build skeleton

**Files:**
- Create: `project.yml`
- Create: `Sources/VaultCore/VaultCore.swift`
- Create: `Tests/VaultCoreTests/SmokeTests.swift`

- [ ] **Step 1: Write the failing smoke test**

```swift
import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 1)
}
```

- [ ] **Step 2: Generate and run to verify failure**

Run:

```bash
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme VaultCore -destination 'platform=macOS'
```

Expected: FAIL because `VaultFormat` does not exist.

- [ ] **Step 3: Add the minimal module and project definition**

```swift
public enum VaultFormat {
    public static let current = 1
}
```

`project.yml` must define a macOS 14 framework target `VaultCore` from
`Sources/VaultCore` and a test target `VaultCoreTests` from
`Tests/VaultCoreTests` depending on it.

- [ ] **Step 4: Run the test**

Run the command from Step 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add project.yml Sources/VaultCore Tests/VaultCoreTests
git commit -m "build: add vault core target"
```

### Task 2: Define references and encrypted record schema

**Files:**
- Create: `Sources/VaultCore/Models/SecretReference.swift`
- Create: `Sources/VaultCore/Models/EncryptedRecord.swift`
- Create: `Tests/VaultCoreTests/SecretReferenceTests.swift`

- [ ] **Step 1: Write parsing and round-trip tests**

```swift
import Testing
@testable import VaultCore

@Test func parsesCanonicalReference() throws {
    let ref = try SecretReference("secret://01JABCDEF0123456789ABCDEFG")
    #expect(ref.description == "secret://01JABCDEF0123456789ABCDEFG")
}

@Test func rejectsMetadataInReference() {
    #expect(throws: SecretReference.Error.self) {
        try SecretReference("secret://password@example.com")
    }
}
```

- [ ] **Step 2: Run the focused tests**

```bash
xcodebuild test -project AgentSecretVault.xcodeproj -scheme VaultCore -destination 'platform=macOS' -only-testing:VaultCoreTests/SecretReferenceTests
```

Expected: FAIL because the types do not exist.

- [ ] **Step 3: Implement the models**

`SecretReference` must be `Codable`, `Hashable`, `Sendable`, and
`CustomStringConvertible`. Accept exactly `secret://` plus 26 uppercase
Crockford Base32 characters. `EncryptedRecord` must contain:

```swift
public struct EncryptedRecord: Codable, Sendable, Equatable {
    public let formatVersion: Int
    public let id: String
    public let recordVersion: Int
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let wrappedDataKey: Data
    public let wrappedDataKeyNonce: Data
    public let wrappedDataKeyTag: Data
    public let label: String?
    public let policy: SecretPolicy
    public let createdAt: Date
    public let updatedAt: Date
}

public enum SecretPolicy: String, Codable, Sendable {
    case read
    case externalSend
    case credential
}
```

- [ ] **Step 4: Run all core tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultCore/Models Tests/VaultCoreTests
git commit -m "feat: define secret reference record format"
```

### Task 3: Implement envelope encryption

**Files:**
- Create: `Sources/VaultCore/Crypto/VaultCipher.swift`
- Create: `Sources/VaultCore/Crypto/RandomBytes.swift`
- Create: `Tests/VaultCoreTests/VaultCipherTests.swift`

- [ ] **Step 1: Write encryption, tamper, and uniqueness tests**

```swift
@Test func encryptDecryptRoundTrip() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let record = try cipher.encrypt(
        Data("sensitive".utf8), id: "01JABCDEF0123456789ABCDEFG",
        version: 1, label: "test", policy: .credential, masterKey: master
    )
    #expect(try cipher.decrypt(record, masterKey: master) == Data("sensitive".utf8))
}

@Test func tamperedCiphertextFails() throws {
    // Flip one ciphertext byte and expect VaultCryptoError.integrityFailed.
}

@Test func samePlaintextProducesDifferentCiphertext() throws {
    // Encrypt twice and assert ciphertext and wrapped key differ.
}
```

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because `VaultCipher` does not exist.

- [ ] **Step 3: Implement encryption**

Use `AES.GCM.seal` twice: once with a fresh per-record 256-bit key for the
plaintext, and once with the master key for the raw data-key bytes. Use
`Data("\(id):\(VaultFormat.current)".utf8)` as authenticated data in both
operations. Map all authentication failures to
`VaultCryptoError.integrityFailed`; never return partial bytes.

- [ ] **Step 4: Run all core tests**

Expected: all three tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultCore/Crypto Tests/VaultCoreTests/VaultCipherTests.swift
git commit -m "feat: add envelope encryption"
```

### Task 4: Implement atomic sidecar storage

**Files:**
- Create: `Sources/VaultCore/Store/RecordStore.swift`
- Create: `Sources/VaultCore/Store/FileRecordStore.swift`
- Create: `Tests/VaultCoreTests/FileRecordStoreTests.swift`

- [ ] **Step 1: Write storage tests**

Test that saving creates
`.agent-secret-vault/records/<id>/00000001.json`, loading returns the latest
valid version, a failed replacement leaves the prior version readable, and
path traversal IDs are rejected.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because `FileRecordStore` does not exist.

- [ ] **Step 3: Implement the store**

Define:

```swift
public protocol RecordStore: Sendable {
    func save(_ record: EncryptedRecord) async throws
    func latest(id: String) async throws -> EncryptedRecord
    func versions(id: String) async throws -> [Int]
}
```

Write JSON to a same-directory temporary file with `.atomic`, decode it back,
then rename it to the zero-padded version filename. Reject symlinks and IDs
that do not pass `SecretReference` validation.

- [ ] **Step 4: Run core tests and inspect artifacts**

```bash
xcodebuild test -project AgentSecretVault.xcodeproj -scheme VaultCore -destination 'platform=macOS'
git diff --check
```

Expected: PASS and no formatting errors.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultCore/Store Tests/VaultCoreTests/FileRecordStoreTests.swift
git commit -m "feat: add atomic sidecar record store"
```

