# SVLT threat model

## Assets

- Selected plaintext secrets and sensitive text.
- Vault master key and wrapped record data keys.
- Encrypted record versions and audit log records.
- Codex/MCP responses and local execution results.
- Knowledge-base Markdown and search indexes that contain opaque references.

## Security goals

SVLT is designed to prevent plaintext exposure to Codex, cloud
models, the Obsidian knowledge base and search index, file-sync providers,
copied encrypted sidecar stores, audit logs, system logs, notifications, and
crash reports.

The expected safe data shape outside the macOS app is an opaque reference such
as `secret://0123456789ABCDEFGHJKMNPQRS`, fixed redacted metadata, encrypted
record bytes, or sanitized execution output.

## Trust boundary

The native macOS app is the only component with decryption authority. The MCP
server and Codex plugin are untrusted for plaintext handling: they may request
actions, but they must not receive plaintext, unwrapped keys, resolved command
arguments, or bulk export data.

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

Risk classes are separated:

- Read: short-lived local display authorization.
- Write or external-send: fresh single-use authorization.
- Delete or credential-change: highest-risk fresh single-use authorization.

Write, external-send, delete, and credential-change operations cannot reuse a
read authorization.

## Recovery limitations

iCloud Keychain recovery is a wrapped-key recovery path, not a weaker password
fallback. A recovered Mac must authenticate locally, unwrap the recovery copy,
and create a new non-synchronizable local wrapper. If macOS cannot enforce the
required Keychain controls safely, recovery remains unavailable.

## Clipboard behavior

Clipboard clearing is best-effort. The app clears only the app-owned clipboard
entry when the pasteboard change count still matches the copy operation. It
does not erase user or third-party clipboard changes.
