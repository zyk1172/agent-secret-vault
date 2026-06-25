# Agent Secret Vault Phase 4: Codex Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect Codex to the app through authenticated local IPC, an MCP server, and a packaged Codex plugin without exposing plaintext.

**Architecture:** The app owns a per-user Unix-domain socket and rotating capability token stored with mode `0600`. The TypeScript MCP process validates and forwards typed requests, then validates responses against schemas that contain no plaintext fields.

**Tech Stack:** Swift Darwin sockets, Node.js 24, TypeScript, `@modelcontextprotocol/sdk`, Zod, Vitest, Codex plugins.

---

### Task 1: Define the IPC protocol and Swift server

**Files:**
- Create: `Sources/VaultIPC/IPCMessage.swift`
- Create: `Sources/VaultIPC/UnixSocketServer.swift`
- Create: `Tests/VaultIPCTests/IPCMessageTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write protocol tests**

Test JSON round trips for `status`, `reveal`, `encrypt`, and `execute`.
Recursively inspect encoded responses and reject keys matching
`plaintext|secretValue|resolvedArguments|masterKey`.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement messages**

```swift
public enum IPCRequest: Codable, Sendable {
    case status
    case reveal(reference: String, reason: String)
    case encrypt(label: String?, policy: SecretPolicy)
    case execute(ExecutionRequest)
}

public enum IPCResponse: Codable, Sendable {
    case status(locked: Bool)
    case displayedToUser
    case created(reference: String)
    case execution(SanitizedExecutionResult)
    case failure(code: String)
}
```

Frame messages as four-byte big-endian length plus JSON, cap frames at 1 MiB,
bind under the user's application-support directory, set socket permissions to
`0600`, and require a 256-bit capability token in the first request.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add project.yml Sources/VaultIPC Tests/VaultIPCTests
git commit -m "feat: add authenticated local ipc protocol"
```

### Task 2: Scaffold and test the MCP adapter

**Files:**
- Create: `mcp-server/package.json`
- Create: `mcp-server/tsconfig.json`
- Create: `mcp-server/src/protocol.ts`
- Create: `mcp-server/src/client.ts`
- Create: `mcp-server/test/protocol.test.ts`

- [ ] **Step 1: Write response-schema leak tests**

```typescript
it("rejects plaintext-shaped fields", () => {
  expect(() => IpcResponse.parse({ plaintext: "leak" })).toThrow();
});
```

Add valid fixtures for every Swift `IPCResponse` case.

- [ ] **Step 2: Install and run**

```bash
cd mcp-server
npm install
npm test
```

Expected: FAIL because schemas do not exist.

- [ ] **Step 3: Implement schemas and client**

Use strict Zod objects with `.strict()`. The client reads socket and token paths
from fixed app-support locations, rejects non-owner token-file permissions,
applies the same 1 MiB frame cap, and maps connection failures to
`APP_UNAVAILABLE`.

- [ ] **Step 4: Run tests and typecheck**

```bash
npm test
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcp-server
git commit -m "feat: add typed local mcp adapter"
```

### Task 3: Expose safe MCP tools

**Files:**
- Create: `mcp-server/src/server.ts`
- Create: `mcp-server/test/tools.test.ts`
- Modify: `mcp-server/package.json`

- [ ] **Step 1: Write tool contract tests**

Cover `vault_status`, `secret_reveal_request`, `secret_create_request`, and
`secure_execute`. Assert tool results contain only references, status codes,
sanitized output, and non-sensitive metadata.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because tools are unregistered.

- [ ] **Step 3: Implement tools**

Register tools with explicit descriptions that state plaintext is never
returned. `secret_reveal_request` returns
`{"status":"DISPLAYED_TO_USER"}`. `secure_execute` accepts a template ID,
typed values, and reference strings; reject raw values in secret slots.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcp-server/src/server.ts mcp-server/test/tools.test.ts mcp-server/package.json
git commit -m "feat: expose non-plaintext mcp tools"
```

### Task 4: Package the Codex plugin

**Files:**
- Create: `.agents/plugins/marketplace.json`
- Create: `plugins/agent-secret-vault/.codex-plugin/plugin.json`
- Create: `plugins/agent-secret-vault/.mcp.json`
- Create: `plugins/agent-secret-vault/skills/agent-secret-vault/SKILL.md`
- Create: `plugins/agent-secret-vault/hooks/hooks.json`
- Create: `plugins/agent-secret-vault/hooks/validate_secret_output.js`
- Create: `mcp-server/test/plugin.test.ts`

- [ ] **Step 1: Write manifest tests**

Parse the manifest, verify all referenced paths remain under
`plugins/agent-secret-vault/`, and
scan skill/hook text to require the rules “never request plaintext from MCP,”
“never echo resolved credentials,” and “use `secret://` references.”

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because plugin files are missing.

- [ ] **Step 3: Create plugin**

The marketplace entry uses local source path
`./plugins/agent-secret-vault`. The plugin manifest points to the bundled
skill, `.mcp.json`, and hook definition. The MCP command invokes the compiled
adapter through `${PLUGIN_ROOT}`. The hook scans candidate tool output for
forbidden response keys and blocks it with a generic non-sensitive error.

- [ ] **Step 4: Validate and perform local smoke test**

```bash
cd mcp-server && npm test && npm run build
cd ..
codex plugin marketplace add .
codex plugin marketplace list
codex
# In the Codex TUI: open /plugins, select the local marketplace,
# install Agent Secret Vault, then open /mcp verbose.
codex mcp list
```

Expected: the local marketplace is listed, the plugin installs through
`/plugins`, the MCP server appears through `/mcp verbose`, and no plaintext is
printed.

- [ ] **Step 5: Commit**

```bash
git add .agents/plugins/marketplace.json plugins/agent-secret-vault mcp-server
git commit -m "feat: package codex secret vault plugin"
```
