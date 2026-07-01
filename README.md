# Agent Secret Vault

![Agent Secret Vault app icon](AppAssets/AppIcon-source.png)

Agent Secret Vault is a macOS app plus local MCP adapter for letting agents such
as Codex work with sensitive knowledge-base material without receiving
plaintext secrets.

The app owns encryption, decryption, authorization, secure display, recovery,
audit logging, migration, and controlled local execution. Agents receive only
opaque references such as:

```text
secret://0123456789ABCDEFGHJKMNPQRS
```

## Normal installation

For people who only use the app, do not run Xcode. Use the release zip:

1. Unzip `AgentSecretVault-release.zip`.
2. Double-click `install.command`. If macOS blocks it, right-click it and choose
   Open. Terminal users can run `install.sh`.
3. Open Agent Secret Vault.
4. Copy the generated MCP config from:

```text
~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json
```

The installer places:

- App: `/Applications/AgentSecretVault.app` or `~/Applications/AgentSecretVault.app`
- MCP server: `~/Library/Application Support/AgentSecretVault/MCP`
- MCP config: `~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json`

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
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/agent-secret-vault && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/main.js obsidian-plugin/agent-secret-vault/dist
git diff --check
```

Create a distributable zip:

```bash
./scripts/package-release.sh
```

## Agent installation

For Codex, Claude, Hermes, or another MCP-capable agent, follow
[docs/universal-agent-usage.md](docs/universal-agent-usage.md).

中文使用教程见 [docs/zh-CN.md](docs/zh-CN.md).

Short version:

Use the generated MCP config:

```text
~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json
```

For Codex skill installation:

```bash
./scripts/install-codex-skill.sh
```

## Obsidian workflow

1. Open Agent Secret Vault.
2. Install the Obsidian plugin from `obsidian-plugin/agent-secret-vault`.
3. Pair the plugin with the local Agent Secret Vault app.
4. Select sensitive text in Obsidian and encrypt it into an opaque `secret://`
   reference.
5. Scan the current note or vault to review replacement candidates before
   converting them to references.
6. Use reveal for the current paragraph only when local display is needed. The
   app opens an app-owned temporary reveal window; the plugin receives status
   only, not decrypted values.

MCP `secret_create_request` and `secure_execute` are first-release compatibility
endpoints. They return non-sensitive unavailable statuses until the app-side
selection and execution bridges are enabled.

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

These tools restore `secret://` values only inside the local MCP process or a
purpose-built local runner. Results are status/metadata/sanitized previews only;
plaintext credentials, Authorization headers, cookies, and filled field values
must never be returned to the agent.

## Security model

- Plaintext is encrypted locally and replaced in Markdown with opaque
  `secret://` references.
- MCP tools never return decrypted values. Reveal requests display plaintext
  only in the macOS app, and Obsidian plugin reveal responses contain status
  only.
- Authorization has separate risk classes for read, external-send/write, and
  delete or credential-change operations.
- Read authorization is short-lived. Higher-risk operations require fresh
  per-operation authorization.
- Clipboard use is explicit and best-effort: the app clears only the
  app-owned clipboard value if nothing else has replaced it.
- Bulk plaintext export is intentionally unsupported.

See [docs/security/threat-model.md](docs/security/threat-model.md),
[docs/security/crypto-hardening.md](docs/security/crypto-hardening.md), and
[docs/security/release-checklist.md](docs/security/release-checklist.md).

## Recovery

Recovery uses a synchronizable iCloud Keychain wrapping key plus wrapped master
key bytes. Recovery never weakens normal device-local authorization. If the
required Keychain controls are unavailable, recovery fails closed. The
cross-user iCloud Keychain matrix remains a manual release requirement in
[docs/security/keychain-matrix.md](docs/security/keychain-matrix.md).
