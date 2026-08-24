# SVLT

![SVLT app icon](AppAssets/AppIcon-source.png)

SVLT is a macOS UI app plus a separate launchd-managed local Agent and MCP
adapter. The UI can quit while the Agent continues serving Vault, MCP, and
Obsidian IPC requests without loading SwiftUI or creating a window.

`SVLT.app` owns UI, settings, file selection, service registration, and local
reveal presentation. `SVLTAgent` owns encryption, decryption, authorization,
Unix-socket IPC, recovery, audit logging, migration, and controlled local
execution. Agents receive only opaque references such as:

```text
secret://0123456789ABCDEFGHJKMNPQRS
```

## Normal installation

For people who only use the app, do not run Xcode. Use the release zip:

1. Unzip `SVLT-release.zip`.
2. Double-click `install.command`. If macOS blocks it, right-click it and choose
   Open. Terminal users can run `install.sh`.
3. Open SVLT.
4. Copy the generated MCP config from:

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```
5. For Codex, Hermes, OpenClaw, or another MCP agent, paste the required
   [Agent sensitive-information policy](docs/svlt-agent-policy-zh-CN.md)
   into its system prompt, project rule, or workspace instruction.

The installer places:

- App and embedded Agent: `/Applications/SVLT.app` or `~/Applications/SVLT.app`
- LaunchAgent plist: `SVLT.app/Contents/Library/LaunchAgents/com.agent-secret-vault.SVLT.agent.plist`
- MCP server: `~/Library/Application Support/AgentSecretVault/MCP`
- MCP config: `~/Library/Application Support/AgentSecretVault/svlt.mcp.json`

On first launch the App registers the embedded plist with `SMAppService.agent`.
The plist uses `BundleProgram` and points to `Contents/MacOS/SVLTAgent`. If
macOS requests approval, use System Settings → General → Login Items. Do not
copy the plist to `~/Library/LaunchAgents`; registration and lifecycle are
owned by `SMAppService`.

The user only needs Node.js 24 or newer for the MCP server. Xcode is not needed
for normal use.

## Developer build

Required local tooling for development only:

- macOS 14 or newer.
- Xcode or Xcode beta.
- XcodeGen.
- Node.js 24 or newer.

Build, package, and test:

```bash
xcodegen generate
xcodebuild test -project SVLT.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/svlt && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/svlt/main.js obsidian-plugin/svlt/dist
git diff --check
```

Create a distributable zip:

```bash
./scripts/package-release.sh
```

To inspect the idle background process after installation:

```bash
./scripts/check-agent-resources.sh
# or: ps -axo pid,ppid,%cpu,%mem,rss,etime,command | grep '[S]VLTAgent'
```

The Agent blocks on its Unix socket and uses no heartbeat, Timer, periodic
status refresh, network ping, or full-vault scan. `SVLT.app` termination does
not stop it; only an explicit service unregister/disable, uninstall, or
intentional development stop should do so.

## Agent installation

For Codex, Claude, Hermes, or another MCP-capable agent, follow
[docs/universal-agent-usage.md](docs/universal-agent-usage.md).

中文使用教程见 [docs/zh-CN.md](docs/zh-CN.md).

Short version:

1. Open SVLT and select the `敏感信息.md` that will be the active
   SVLT-managed Catalog v2 document. It contains Index/Entry metadata and
   opaque `secret://` references; encrypted records remain in the local vault.
2. Use the generated MCP config:

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

3. Paste the required [Agent sensitive-information policy](docs/svlt-agent-policy-zh-CN.md)
   into the agent's system prompt, project rule, or workspace instruction.
   This makes the App-selected index and its `secret://` references the
   mandatory path for sensitive data; agents must not read the index directly
   or fall back to notes, logs, environment variables, or memory.

For Codex skill installation:

```bash
./scripts/install-codex-skill.sh
```

When a task names a service, device, host, account, or purpose but the Agent
does not yet know a `secret://` reference, it should call the query-scoped MCP
tool `secret_search` first. The tool returns Entry-centric results containing
the Index, Entry, endpoint, allowed visible metadata, and opaque `secretRef`
values; it never returns plaintext, catalog paths, or the full `敏感信息.md`.
Managed catalog writes must use the Catalog MCP tools and an App-issued lease;
Obsidian and agents must not directly edit the Markdown/JSON representation.

## Obsidian workflow

1. Open SVLT.
2. Install the Obsidian plugin from `obsidian-plugin/svlt`.
3. Pair the plugin with the local SVLT app.
4. Select sensitive text in Obsidian and encrypt it into an opaque `secret://`
   reference.
5. Use the App's local scan to review replacement candidates before converting
   them to references.
6. Use reveal for the current paragraph only when local display is needed. The
   app opens an app-owned temporary reveal window; the plugin receives status
   only, not decrypted values.

MCP `secret_create_request` remains a local app/plugin compatibility endpoint
for creating opaque references. MCP does not expose a generic execution
endpoint: operations must use a purpose-built tool and pass the local policy
engine before execution.

## Agent local-use tools

For Codex, Claude, Hermes, or another MCP-capable agent, keep `secret://`
references in the conversation and use narrow MCP tools when plaintext must be
used locally:

- `ssh_command_with_secret` for restricted local/private-network SSH.
- `local_http_request_with_secret` for restricted local/private HTTP(S)
  GET/HEAD checks with Basic Auth.
- `api_request_with_token` for restricted allowlisted API requests with a token.
- `database_query_with_secret` for restricted read-only database queries through
  a purpose-built runner.
- `sftp_transfer_with_secret` for restricted SFTP/SCP list/download/upload
  through a purpose-built runner.
- `browser_web_login_with_secret` for specific local/private browser login form
  fills.
- `local_app_form_fill_with_secret` for specific macOS app form fills.

`secret_search` is metadata-only discovery and does not grant reveal/export
permission. Plaintext reveal, local export, writes, and external operations
still go through the local `SecretOperationPolicyEngine`; an export to the
Desktop remains approval-required.

These tools resolve `secret://` values only inside the SVLTAgent process or a
purpose-built local runner. Results are status/metadata/sanitized previews only;
plaintext credentials, Authorization headers, cookies, and filled field values
must never be returned to the agent.

## Security model

- Plaintext is encrypted locally and replaced in Markdown with opaque
  `secret://` references.
- MCP tools never return decrypted values. Reveal requests display plaintext
  only in the macOS app, and Obsidian plugin reveal responses contain status
  only.
- Each secret operation is independently evaluated as `silent`,
  `approvalRequired`, or `denied` by `SecretOperationPolicyEngine`.
- `effectiveRisk = max(agentRisk, localRisk)`: the Agent hint may raise risk but
  never lowers a local approval or denial.
- Bound read-only SSH/HTTP/database/SFTP operations can run silently. New or
  public destinations, writes, plaintext reveal/copy/export, deletes, and
  security-setting changes require a short-lived one-shot `ApprovalTicket` or
  are denied.
- `locked` remains a compatibility field only. Agent gating uses
  `available`/`ready`/`approvalPending`; quitting the GUI does not stop the
  launchd Agent, while screen lock or session changes still clear protected
  runtime state.
- The Agent uses a `WhenUnlockedThisDeviceOnly` Keychain item for normal
  low-risk cryptographic access. Dangerous data flows use macOS
  `deviceOwnerAuthentication`, rather than prompting for every low-risk
  decryption.
- Audit writes use an independent Keychain audit key and never unlock the Vault
  merely to record status or connection activity.
- Clipboard use is explicit and best-effort: the app clears only the
  app-owned clipboard value if nothing else has replaced it.
- Bulk plaintext export is intentionally unsupported.

See [docs/security/threat-model.md](docs/security/threat-model.md),
[docs/security/crypto-hardening.md](docs/security/crypto-hardening.md),
[docs/security/operation-authorization.md](docs/security/operation-authorization.md),
and [docs/security/release-checklist.md](docs/security/release-checklist.md).

## Recovery

Recovery uses a synchronizable iCloud Keychain wrapping key plus wrapped master
key bytes. Recovery never weakens normal device-local authorization. If the
required Keychain controls are unavailable, recovery fails closed. The
cross-user iCloud Keychain matrix remains a manual release requirement in
[docs/security/keychain-matrix.md](docs/security/keychain-matrix.md).
