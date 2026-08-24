# SVLT release checklist

Run this checklist for every release candidate.

## Release gate commands

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodegen generate
xcodebuild test -project SVLT.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/svlt && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/svlt/main.js obsidian-plugin/svlt/dist
git diff --check
git status --short
./scripts/check-agent-resources.sh # after installing/running the release
```

## Acceptance criteria

1. For SVLT-managed test secrets, test plaintext cannot be found in the knowledge base, search index, audit logs, Codex transcript, application logs, notifications, or crash reports. This criterion does not claim to erase user plaintext explicitly selected for an external current operation.
2. Copying the knowledge base and encrypted sidecar store to an unauthorized Mac does not permit decryption.
3. Cancelling Touch ID, locking the application, or modifying ciphertext exposes no full or partial plaintext.
4. Simulated credential echoes in stdout and stderr are removed before results reach Codex.
5. Ambiguous or unsafe output is quarantined instead of returned.
6. Write, external-send, delete, and credential-change operations cannot reuse a read authorization; credential windows are reused only within their configured scope and external-send is destination-bound.
7. `locked` is compatibility-only; operation readiness is reported by `available`/`ready`/`approvalPending`. Sleep, user switch, and explicit lock invalidate active runtime authorization. Quitting the GUI App does not stop the Agent or create a global Agent gate.
8. A new Mac signed into the same Apple account can recover access only after successful platform authentication and installation of the correctly signed application.
9. Every MCP success and error response passes automated plaintext-leak tests.
10. Knowledge-base replacement failures preserve the source plaintext and the newly encrypted record for manual recovery.
11. Template validation rejects undeclared executables, destinations, parameters, and side-effect escalation.
12. Cryptographic migration tests prove that failed migrations preserve the last valid record.
13. Scan state does not persist full plaintext.
14. Paragraph reveal returns only status to the Obsidian plugin and MCP callers; a native App-owned reveal is delivered through the explicit Agent → App UI bridge.
15. `SVLTAgent` contains no SwiftUI/AppKit/UI framework dependency and the embedded LaunchAgent plist uses `BundleProgram` under `Contents/Library/LaunchAgents`.
16. Obsidian search does not index revealed plaintext.
17. Context-leak warnings trigger for password, token, API key, and 银行卡 candidates.
18. Plaintext canary scans include the shipped Obsidian plugin bundle at `obsidian-plugin/svlt/main.js`.

## Manual checks

- Complete `docs/security/keychain-matrix.md` on real macOS user profiles before
  marking iCloud Keychain recovery as release-ready.
- Verify no UI, README, plugin skill, or MCP description claims protection
  against same-user malware, root/admin compromise, screen recording, physical
  observation, compromised signed binaries, or compromised developer signing
  identity.
- Verify no feature exposes bulk plaintext export.
