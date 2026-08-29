# SVLT

![SVLT app icon](AppAssets/AppIcon-source.png)

SVLT is a macOS UI app plus a separate launchd-managed local Agent and MCP
adapter. SVLT is opt-in: it protects secrets the user chooses to manage with
SVLT and does not claim ownership of every credential available to an Agent.
The UI can quit while the Agent continues serving Vault, MCP, and Obsidian IPC
requests without loading SwiftUI or creating a window.

`SVLT.app` owns UI, settings, file selection, service registration, and local
reveal presentation. `SVLTAgent` owns encryption, decryption, authorization,
Unix-socket IPC, transaction rollback, audit logging, migration, and controlled
local execution. For SVLT-managed operations, Agents receive only opaque references
such as:

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
   into its system prompt, project rule, or workspace instruction. The policy is
   opt-in: a user-supplied plaintext credential explicitly selected for the
   current operation is not automatically imported or replaced by SVLT.

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
SVLT_SIGNING_IDENTITY='Developer ID Application: ...' ./scripts/package-release.sh
```

Release signing deliberately requires `SVLT_SIGNING_IDENTITY` from the local
keychain; the project does not embed an individual developer certificate.

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

1. Open SVLT and select an existing `敏感信息.md` as the active
   SVLT Catalog v3 document. It is ordinary Obsidian Markdown with real `##`
   group headings, `###` entry headings, stable SVLT markers, and opaque
   `secret://` references; encrypted records remain in the local vault.
   Only credentials the user chooses to manage with SVLT belong in this path.
   A blank packaged template is available from the Security Boundary page;
   copying it into a vault remains an explicit user action.
2. Use the generated MCP config:

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

3. Paste the required [Agent sensitive-information policy](docs/svlt-agent-policy-zh-CN.md)
   into the agent's system prompt, project rule, or workspace instruction.
   The policy explains the accepted semantic model and approval boundary;
   agents may use Catalog MCP, while users, Obsidian, scripts, and other
   writers may also edit valid v3 Markdown. The coordinator validates and
   reconciles those edits instead of treating the writer transport as risk.
   The App can inspect the selected document's format and apply only a
   semantic-preserving formatting repair after a fresh hash check.
   It does not override a user-selected QNAP MCP, external provider, logged-in
   CLI, environment variable, third-party password manager, or explicitly
   supplied plaintext for the current operation.

For Codex skill installation:

```bash
./scripts/install-codex-skill.sh
```

When a task names a service, device, host, account, or purpose but the Agent
does not yet know a credential source, it may call the query-scoped MCP tool
`secret_search` for automatic discovery. It must first honor an explicit user
source: current plaintext and explicitly selected external providers take
precedence over SVLT search. The tool returns Entry-centric results containing
the Index, Entry, endpoint, allowed visible metadata, and opaque `secretRef`
values; it never returns plaintext, catalog paths, or the full `敏感信息.md`.
Catalog writes are evaluated by semantic diff. Creating groups/entries, ordinary
metadata, empty password placeholders, and validation are safe by default;
binding/replacing/deleting existing secrets or changing their targets requires
local approval. v3 writers must preserve unrelated Markdown, whitespace, notes,
and WikiLinks; the coordinator applies source-range patches and never
canonicalizes the whole document for a single edit. Use `secret_catalog_batch`
for one-lock, one-revision multi-operation changes.

SVLT-generated and controlled insertions use three logical zones in the managed Markdown:
preamble, a contiguous Catalog body, and trailing unmanaged Markdown. Notes, callouts,
ordinary paragraphs, comments, and WikiLinks remain unmanaged and stay in place even when a
user has put them between existing Indexes; format repair does not move them merely to make
the body contiguous. New Indexes are inserted after the last managed Index and before trailing
user content (or after the preamble when there is no Index), never blindly appended to EOF.
The renderer uses `\n\n---\n\n` between newly generated Indexes and a consistent double-blank
visual gap between Entries; source-range minimal patches preserve unrelated bytes and existing
user horizontal rules.

## Obsidian workflow

1. Open SVLT.
2. Install the Obsidian plugin from `obsidian-plugin/svlt`.
3. Pair the plugin with the local SVLT app.
4. Open the v3 `敏感信息.md` in Obsidian and edit headings, notes, and
   `[[WikiLinks]]` normally. The plugin validates changes after a short debounce
   and reports precise diagnostics with line locations in Chinese.
5. Keep credential management in the App: create groups and entries, fill or
   replace passwords, and view plaintext by clicking "解密" on the exact field
   after device-owner authentication.
6. Agent Catalog mutations each create their own operation-bound request; the
   App authenticates the user and the approved ticket is consumed once.
7. The plugin is read-only. It never encrypts, decrypts, repairs, or writes a
   managed catalog, and it never returns plaintext.

MCP `secret_create_request` remains a local app/plugin compatibility endpoint
for creating opaque references. MCP does not expose a generic execution
endpoint: operations must use a purpose-built tool and pass the local policy
engine before execution.

## Agent local-use tools

For Codex, Claude, Hermes, or another MCP-capable agent, keep SVLT-managed
`secret://` references in the conversation and use narrow MCP tools when an
SVLT-managed value must be used locally. A user may explicitly select a
different provider or provide plaintext for the current operation; SVLT does
not force conversion or substitution in that case.

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

- SVLT-managed plaintext is encrypted locally and represented in Markdown by
  opaque `secret://` references. This is not a claim over credentials the user
  keeps in another provider or explicitly supplies for one operation.
- MCP tools never return decrypted values. Reveal requests display plaintext
  only in the macOS app, and Obsidian plugin reveal responses contain status
  only.
- Each secret operation is independently evaluated as `silent`,
  `approvalRequired`, or `denied` by `SecretOperationPolicyEngine`.
- `effectiveRisk = max(agentRisk, localRisk)`: the Agent hint may raise risk but
  never lowers a local approval or denial.
- Bound read-only SSH/HTTP/database/SFTP operations can run silently. An
  eligible purpose-built Agent execution whose policy result is
  `approvalRequired` may use one fresh device-owner approval to open a fixed,
  non-sliding 300-second in-memory execution window. Every request still
  re-evaluates the current local policy; destinations that remain denied stay
  denied.
- Plaintext reveal/copy/export, deletes, security-setting changes, and Catalog
  Agent writes never use the execution window. They retain their own exact,
  one-shot `ApprovalTicket` authorization boundary.
- Execution authorization is cleared on screen lock, sleep, session changes,
  explicit lock, and Agent restart. Audit records distinguish fresh local
  approval from execution-window reuse without storing plaintext or headers.
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

## Opt-in scope and plaintext override

The four non-secret scope labels are `SVLT_MANAGED_OPERATION`,
`USER_EXPLICIT_PLAINTEXT`, `EXTERNAL_PROVIDER_OPERATION`, and
`UNMANAGED_CREDENTIAL`. If the user says “use this password/token directly” or
“do not use SVLT” for the current operation, the selected external tool may use
that user-provided value without SVLT lookup, comparison, replacement, import,
or approval. SVLT must not compare it with an existing `secret://` value.
The decision is per operation: a current user choice replaces an earlier SVLT
or external-provider choice and is never inherited as sticky state.

This does not permit unsafe persistence: repository `AGENTS.md`, tool, logging,
network, and workspace rules still decide whether the value may be written or
printed. Conversely, plaintext obtained by decrypting an SVLT-managed
`secret://` must remain inside the approved SVLT operation and must not be
passed to ordinary shell, curl, URL, header, environment variable, log, audit,
or chat.

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
