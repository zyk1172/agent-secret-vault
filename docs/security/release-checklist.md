# Agent Secret Vault release checklist

Run this checklist for every release candidate.

## Release gate commands

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/agent-secret-vault && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/main.js obsidian-plugin/agent-secret-vault/dist
git diff --check
git status --short
```

## Acceptance criteria

1. Test plaintext cannot be found in the knowledge base, search index, audit logs, Codex transcript, application logs, notifications, or crash reports.
2. Copying the knowledge base and encrypted sidecar store to an unauthorized Mac does not permit decryption.
3. Cancelling Touch ID, locking the application, or modifying ciphertext exposes no full or partial plaintext.
4. Simulated credential echoes in stdout and stderr are removed before results reach Codex.
5. Ambiguous or unsafe output is quarantined instead of returned.
6. Write, external-send, delete, and credential-change operations cannot reuse a read authorization.
7. Lock, sleep, user switch, application exit, and timeout invalidate active authorization.
8. A new Mac signed into the same Apple account can recover access only after successful platform authentication and installation of the correctly signed application.
9. Every MCP success and error response passes automated plaintext-leak tests.
10. Knowledge-base replacement failures preserve the source plaintext and the newly encrypted record for manual recovery.
11. Template validation rejects undeclared executables, destinations, parameters, and side-effect escalation.
12. Cryptographic migration tests prove that failed migrations preserve the last valid record.
13. Scan state does not persist full plaintext.
14. Paragraph reveal returns only status to the Obsidian plugin and MCP callers.
15. Obsidian search does not index revealed plaintext.
16. Context-leak warnings trigger for password, token, API key, and 银行卡 candidates.
17. Plaintext canary scans include the shipped Obsidian plugin bundle at `obsidian-plugin/agent-secret-vault/main.js`.

## Manual checks

- Complete `docs/security/keychain-matrix.md` on real macOS user profiles before
  marking iCloud Keychain recovery as release-ready.
- Verify no UI, README, plugin skill, or MCP description claims protection
  against same-user malware, root/admin compromise, screen recording, physical
  observation, compromised signed binaries, or compromised developer signing
  identity.
- Verify no feature exposes bulk plaintext export.
