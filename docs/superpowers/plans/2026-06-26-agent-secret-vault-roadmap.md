# Agent Secret Vault Implementation Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved Agent Secret Vault design as five independently testable implementation phases.

**Architecture:** A Swift 6 macOS application owns cryptography, authorization, secure display, storage, and execution. A local Node MCP adapter and Codex plugin communicate with the app over authenticated local IPC and never receive plaintext.

**Tech Stack:** Swift 6, SwiftUI, CryptoKit, Security, LocalAuthentication, XCTest/Swift Testing, Node.js 24, TypeScript, MCP SDK, Vitest, XcodeGen.

---

## Required environment

- Xcode beta is installed at `/Applications/Xcode-beta.app` and was verified as
  Xcode 27.0 build `27A5209h` with Swift 6.4.
- The global active developer directory currently points to Command Line Tools.
  Keep that global setting unchanged and scope build commands through
  `DEVELOPER_DIR`.
- Before Task 1, run:

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodebuild -version
swift --version
```

Expected: `xcodebuild` prints Xcode 27.0 and Swift prints 6.4.

- Install XcodeGen only after Xcode is active:

```bash
brew install xcodegen
xcodegen --version
```

Keep `DEVELOPER_DIR` exported for every `xcodegen` and `xcodebuild` step in the
phase plans.

## Locked file structure

```text
project.yml
Config/
  AgentSecretVault.entitlements
Sources/
  VaultCore/
    Models/
    Crypto/
    Store/
  VaultAuthorization/
  VaultExecution/
  VaultIPC/
  AgentSecretVaultApp/
Tests/
  VaultCoreTests/
  VaultAuthorizationTests/
  VaultExecutionTests/
  VaultIPCTests/
mcp-server/
  package.json
  tsconfig.json
  src/
  test/
.agents/plugins/
  marketplace.json
plugins/agent-secret-vault/
  .codex-plugin/plugin.json
  .mcp.json
  skills/agent-secret-vault/SKILL.md
  hooks/hooks.json
scripts/
  scan-plaintext.sh
```

## Phase order

1. [Core crypto and sidecar store](2026-06-26-agent-secret-vault-phase-1-core.md)
2. [Authorization and secure macOS UI](2026-06-26-agent-secret-vault-phase-2-app.md)
3. [Allowlisted execution broker](2026-06-26-agent-secret-vault-phase-3-execution.md)
4. [Authenticated IPC, MCP server, and Codex plugin](2026-06-26-agent-secret-vault-phase-4-integration.md)
5. [Recovery, audit, migration, and release hardening](2026-06-26-agent-secret-vault-phase-5-hardening.md)

Do not begin a later phase until the prior phase's full verification command
passes and its commit is present.
