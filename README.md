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
cd ..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts
git diff --check
```

## Security model

- Plaintext is encrypted locally and replaced in Markdown with opaque
  `secret://` references.
- MCP tools never return decrypted values. Reveal requests display plaintext
  only in the macOS app.
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
