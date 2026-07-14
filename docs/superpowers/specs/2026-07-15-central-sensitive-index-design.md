# Central Sensitive Index Design

## Status

This specification supersedes the scan-review design in
`2026-07-15-obsidian-paragraph-scan-design.md`. Scanning remains available,
but it no longer automatically encrypts or writes candidates.

## Goal

Use one user-selected `敏感信息.md` file as the authoritative, portable source
of encrypted secret records. The macOS App manages that file and provides the
primary review workflow. Obsidian remains available for manual encryption,
temporary reveal, and explicit restoration.

## Source Of Truth

`敏感信息.md` is a visible Markdown index. Each entry has a human display ID,
category, title, source file and position, timestamps, the opaque
`secret://` reference, and one independently encrypted record payload. The
payload contains the current encrypted-record envelope and never plaintext.

The cryptographic reference ID remains the existing 26-character ID used by
`secret://`. The display ID is stable and sequential (`S-001`, `S-002`, and
so on), and exists only for user-readable labels and links.

The file format is App-owned and canonical:

```markdown
<!-- agent-secret-vault-index: 1 -->
# 敏感信息索引

## S-001 · OpenAI API Key
- 类别：API Key
- 策略：credential
- 来源：AI/工具与服务.md:23
- 引用：`secret://0123456789ABCDEFGHJKMNPQRS`
- 创建：2026-07-15T00:00:00Z
- 更新：2026-07-15T00:00:00Z

```asv-record
{canonical encrypted-record envelope only}
```
```

The App parses, validates, and writes this structure atomically. It rejects
duplicate display IDs, duplicate references, invalid references, malformed or
unverifiable encrypted envelopes, path traversal, and symbolic-link targets.
It never silently repairs or overwrites an externally modified invalid file.

## File Selection And Migration

The user selects an existing index or creates a new one at any writable path.
The App persists a security-scoped bookmark for that selection and requires a
new selection if it cannot resolve the bookmark.

The App reads only this selected file for record resolution. Existing
Application Support records are offered as a one-time migration after the
index path is selected and the vault is unlocked. Migration writes and verifies
all indexed entries before switching the record source. Legacy files remain
unchanged as a recovery backup until the user explicitly removes them in a
later maintenance action.

## macOS App Workflow

The App owns the scanning and review experience:

1. Choose one or more Markdown files or folders to scan.
2. Apply local, deterministic rules to identify candidates, categories, and
   risk scores. No source text leaves the device.
3. Present candidates in descending risk order. Scanning itself never writes
   records or modifies notes.
4. The user selects a candidate, reviews its complete source paragraph,
   chooses a category and title, and explicitly chooses `写入敏感信息.md` or
   `忽略`.
5. On confirmation, the App writes and verifies the encrypted index entry,
   then replaces only the selected source span with a readable Markdown link:
   `[S-001 OpenAI API Key](secret://...)`.
6. The App shows the resulting display ID, source location, and a preview of
   the replacement. A source write failure leaves an unreferenced index entry
   visible for repair; no record is silently discarded.

The primary screen follows the supplied design: scan scope and file counts on
the left, risk-ranked candidates in the center, the current candidate's
classification and explicit decision controls beside it, and write result plus
source-reference preview on the right. The selected index path, a compact
record list, search, manual entry, and maintenance actions are part of the
same macOS App surface.

## Local Rule Policy

Rules are a local candidate generator, not an authority. Password assignments,
API keys, bearer tokens, private keys, JWTs, secret URL parameters, and common
credential-key assignments have high risk. Email, phone, identity-card, and
bank-card patterns have lower, review-only risk. Existing valid `secret://`
references and placeholders are never candidates.

No candidate is auto-selected for storage. The user must explicitly choose the
entry and write action. Manual App entry is always available for values rules
do not recognise.

## Obsidian Fallback

Obsidian keeps manual commands for encrypting selected text, temporary local
reveal, and explicit restore. Manual encryption asks the App to create an
indexed encrypted record in the selected `敏感信息.md`, then replaces only the
selection with the readable Markdown reference link. Reveal and restore resolve
the underlying `secret://` reference through the selected index.

The Obsidian plugin no longer owns all-vault scan review or automatic scan
replacement. It may offer a command to open the macOS App for central scanning
and maintenance.

## Security And Consistency

- Plaintext exists only during a confirmed App or Obsidian action, and is
  cleared from transient UI state when the operation finishes, is cancelled,
  or the App locks.
- The index is written through a verified temporary file and atomic rename,
  after rejecting symbolic links.
- Source-note writes retain their snapshot/hash validation. Cross-file writes
  cannot be globally atomic, so the index is committed first and an orphaned
  entry is recoverable through the App's maintenance view.
- `secret://` remains the sole agent-facing secret representation. Neither the
  index payload nor decrypted data is returned through MCP, Obsidian IPC,
  notices, logs, or settings.

## Verification

- Swift tests for Markdown index parsing, canonical serialisation, round-trip
  encryption records, corrupt-file rejection, duplicate rejection, and atomic
  write verification.
- Swift tests for migration from the legacy record store without deleting the
  legacy files on failure.
- SwiftUI source and model tests for explicit review actions, candidate sorting,
  source preview, manual entry, and index-path selection failure states.
- Obsidian tests for manual encryption writing a readable reference link and
  resolving it through the selected index.
- Full macOS, MCP, Obsidian, whitespace, and plaintext-canary verification
  before release.
