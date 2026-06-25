# Agent Secret Vault Phase 3: Execution Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute user-approved, allowlisted command templates with local secret injection and guaranteed output quarantine on uncertainty.

**Architecture:** Requests are typed data, never shell text. Validation occurs before authorization or secret resolution. A process runner launches an executable with argument arrays and bounded I/O; a sanitizer removes exact secret matches or quarantines the result.

**Tech Stack:** Swift Foundation Process, XCTest/Swift Testing.

---

### Task 1: Define and validate execution templates

**Files:**
- Create: `Sources/VaultExecution/ExecutionTemplate.swift`
- Create: `Sources/VaultExecution/ExecutionRequest.swift`
- Create: `Sources/VaultExecution/TemplateValidator.swift`
- Create: `Tests/VaultExecutionTests/TemplateValidatorTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write rejection tests**

Cover undeclared executable, extra parameter, secret in a non-secret field,
destination mismatch, risk escalation, shell metacharacters, and relative
executable paths.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because `VaultExecution` is absent.

- [ ] **Step 3: Implement typed validation**

```swift
public struct ExecutionTemplate: Codable, Sendable {
    public let id: String
    public let executable: String
    public let arguments: [ArgumentSlot]
    public let risk: RiskClass
    public let allowedHosts: Set<String>
    public let allowedPaths: Set<String>
}

public enum ArgumentSlot: Codable, Sendable {
    case literal(String)
    case value(name: String)
    case secret(name: String)
}
```

Validation returns a sealed `ValidatedExecution` containing the exact
executable and argument slots. It rejects any input not represented by the
template and never concatenates a command string.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add project.yml Sources/VaultExecution Tests/VaultExecutionTests
git commit -m "feat: validate allowlisted execution templates"
```

### Task 2: Implement bounded process execution

**Files:**
- Create: `Sources/VaultExecution/ProcessRunning.swift`
- Create: `Sources/VaultExecution/FoundationProcessRunner.swift`
- Create: `Tests/VaultExecutionTests/FoundationProcessRunnerTests.swift`

- [ ] **Step 1: Write process tests**

Use `/usr/bin/printf` and `/usr/bin/env` fixtures. Assert no shell is invoked,
timeout terminates the process, output exceeding 1 MiB is rejected, and stdin
is closed after supplied bytes.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement runner**

Launch `Process.executableURL` directly, assign `arguments`, use pipes for
stdin/stdout/stderr, enforce a default 30-second timeout and 1 MiB combined
output limit, and return:

```swift
public struct ProcessResult: Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data
}
```

- [ ] **Step 4: Run tests**

Expected: PASS and no child processes remain.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultExecution Tests/VaultExecutionTests
git commit -m "feat: add bounded direct process runner"
```

### Task 3: Sanitize or quarantine output

**Files:**
- Create: `Sources/VaultExecution/OutputSanitizer.swift`
- Create: `Tests/VaultExecutionTests/OutputSanitizerTests.swift`

- [ ] **Step 1: Write leak tests**

Test exact UTF-8 matches in stdout and stderr, repeated and overlapping
secrets, secrets split across read chunks after reassembly, binary output,
invalid UTF-8, encoded variants not declared safe, and empty secrets.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement fail-closed sanitizer**

Return `.sanitized(ProcessResult)` only for bounded valid UTF-8 output after
replacing every non-empty exact secret with `[REDACTED_SECRET]`. Return
`.quarantined(reason:)` for binary data, invalid UTF-8, empty secret material,
or any configured uncertainty rule.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultExecution/OutputSanitizer.swift Tests/VaultExecutionTests/OutputSanitizerTests.swift
git commit -m "feat: sanitize execution output fail closed"
```

### Task 4: Orchestrate authorization, resolution, and execution

**Files:**
- Create: `Sources/VaultExecution/ExecutionBroker.swift`
- Create: `Tests/VaultExecutionTests/ExecutionBrokerTests.swift`

- [ ] **Step 1: Write ordering and side-effect tests**

Assert validation precedes authorization, authorization precedes secret
resolution, cancellation prevents process launch, read authorization cannot
run an external-send template, and quarantined output never becomes an MCP
result.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement the broker**

The broker accepts only `ValidatedExecution`, requests authorization for the
template's fixed risk, resolves secrets into mutable byte buffers immediately
before launch, wipes those buffers in `defer`, sanitizes output, and returns
only a `SanitizedExecutionResult`.

- [ ] **Step 4: Run phase tests**

```bash
xcodebuild test -project AgentSecretVault.xcodeproj -scheme VaultExecution -destination 'platform=macOS'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultExecution Tests/VaultExecutionTests
git commit -m "feat: orchestrate secure local execution"
```

