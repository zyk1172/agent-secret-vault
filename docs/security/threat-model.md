# SVLT threat model

## Assets

- Selected plaintext secrets and sensitive text.
- Vault master key and wrapped record data keys.
- Encrypted record versions and audit log records.
- Codex/MCP responses and local execution results.
- Knowledge-base Markdown and search indexes that contain opaque references.

## Security goals

For SVLT-managed secrets, SVLT is designed to prevent plaintext exposure to
Codex, cloud models, the Obsidian knowledge base and search index, file-sync
providers, copied encrypted sidecar stores, audit logs, system logs,
notifications, and crash reports. This is an opt-in boundary, not a global DLP
claim: user-selected external credentials and explicitly supplied plaintext for
the current operation remain outside SVLT scope.

The expected safe data shape outside the macOS app is an opaque reference such
as `secret://0123456789ABCDEFGHJKMNPQRS`, fixed redacted metadata, encrypted
record bytes, or sanitized execution output.

## Trust boundary

The signed native SVLT components (SVLT.app and the launchd-managed SVLTAgent)
form the local decryption boundary. SVLTAgent owns the master-key session and
Vault access; SVLT.app is a UI client for settings and App-owned reveal windows.
The MCP server and Codex/Obsidian clients are untrusted for SVLT-managed
plaintext handling: they may request actions, but they must not receive
SVLT-decrypted plaintext, unwrapped keys, resolved command arguments, or bulk
export data.

The Obsidian plugin follows the same boundary. App-to-plugin responses for
selection encryption, scan, and paragraph reveal must return opaque references,
candidate metadata, or operation status only; paragraph reveal opens an
app-owned temporary display window and does not send decrypted values back to
the plugin.

## Excluded threats

The product does not claim to resist:

- malicious software running as the same macOS user;
- screen recording or physical observation while plaintext is visible;
- an attacker with administrator or root control of the Mac;
- compromise of the signed application binary;
- compromise of the developer signing identity.

These are release-blocking only if documentation or UI implies protection
against them. The correct claim is that SVLT reduces accidental
agent/cloud/log exposure, not that it defeats local same-user compromise.

## First-release scope exclusions

The first release also excludes:

- Claude and Hermes integrations as dedicated packaged integrations;
- full-note encryption;
- plaintext rendering inside the original Codex App;
- iPhone or iPad clients;
- team sharing and multi-user access control;
- arbitrary shell execution;
- bulk plaintext export;
- defense against same-user malware or root compromise.

## Authorization model

Every protected request is represented by a `SecretOperationDescriptor` and
evaluated by the local `SecretOperationPolicyEngine`. The engine computes the
local requirement (`none`, `reusableApproval`, or
`freshApprovalRequired`) from the descriptor and current metadata. The
Agent's `AgentRiskAssessment` is display/audit metadata only; it cannot
promote, downgrade, or deny that result. Exact opaque reference sets are
checked before any record is resolved.

Secret-bearing execution uses one fixed, non-sliding 300-second owner lease per
exact scope. The ordinary path covers SSH/HTTP/database/SFTP and other
technically supported operations, including shell syntax and new destinations;
only the small fixed destructive registries, plaintext/security controls, and
arbitrary local secret release require fresh approval. Cross-origin HTTP
redirects stop transport and require a newly submitted request rather than a
special inherited authorization. Malformed, contradictory, stale, or
unverifiable requests fail technically; the device owner decides all other
technically executable requests. The lease binds operation hash, Secret
references, destination, command/method/path/database/file details, expiry,
and security generation.

`locked` in `WorkbenchStatus` is compatibility-only; it is not an Agent gate.
`available`, `ready`, and `approvalPending` describe the current operation
channel. LocalAuthentication uses macOS `deviceOwnerAuthentication` for the
approval step. Normal low-risk Keychain access uses the device-local
`WhenUnlockedThisDeviceOnly` item without a per-decryption user-presence
prompt. Audit records use a separate non-userPresence Keychain key and status
recording never unlocks the Vault.

## Recovery limitations

iCloud Keychain recovery is a wrapped-key recovery path, not a weaker password
fallback. A recovered Mac must authenticate locally, unwrap the recovery copy,
and create a new non-synchronizable local wrapper. If macOS cannot enforce the
required Keychain controls safely, recovery remains unavailable.

## Clipboard behavior

Clipboard clearing is best-effort. The app clears only the app-owned clipboard
entry when the pasteboard change count still matches the copy operation. It
does not erase user or third-party clipboard changes.
