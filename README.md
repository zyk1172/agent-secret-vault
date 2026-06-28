# Agent Secret Vault

Agent Secret Vault is a macOS app plus local MCP adapter for letting agents such
as Codex work with sensitive knowledge-base material without receiving
plaintext secrets.

The app owns encryption, decryption, authorization, secure display, recovery,
audit logging, migration, and controlled local execution. Agents receive only
opaque references such as:

```text
secret://0123456789ABCDEFGHJKMNPQRS
```

## Setup

Required local tooling:

- macOS 14 or newer.
- Xcode beta at `/Applications/Xcode-beta.app`.
- XcodeGen.
- Node.js 24 or newer for `mcp-server`.

Build and test:

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/agent-secret-vault && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/main.js obsidian-plugin/agent-secret-vault/dist
git diff --check
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

See [docs/security/threat-model.md](docs/security/threat-model.md) and
[docs/security/release-checklist.md](docs/security/release-checklist.md).

## Recovery

Recovery uses a synchronizable iCloud Keychain wrapping key plus wrapped master
key bytes. Recovery never weakens normal device-local authorization. If the
required Keychain controls are unavailable, recovery fails closed. The
cross-user iCloud Keychain matrix remains a manual release requirement in
[docs/security/keychain-matrix.md](docs/security/keychain-matrix.md).
