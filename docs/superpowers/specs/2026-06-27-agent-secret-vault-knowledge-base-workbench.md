# Agent Secret Vault Phase 6: Knowledge-base workbench

## Status

Draft approved for planning. This spec turns Agent Secret Vault from a
security-core prototype into an operable knowledge-base encryption workflow.
It intentionally does not weaken the existing rule that the macOS app is the
only component allowed to decrypt plaintext.

## Problem

The current app exposes a readable dashboard but not a usable workflow:

- The Encrypt Text, Agent Send, and Orphan Review sections are explanatory
  pages, not connected tools.
- The MCP adapter defines safe request shapes, but the app side does not yet
  expose a complete IPC handler for status, encrypt, reveal, and execute
  requests.
- A large Obsidian knowledge base cannot be protected one selection at a time.
- Users need temporary paragraph-level reveal because useful notes often mix
  normal text with multiple encrypted references.
- Agents must be able to carry opaque references without receiving plaintext or
  being encouraged to infer hidden values from surrounding context.

## Goals

1. Make the macOS app a real local control plane for the vault.
2. Add an Obsidian plugin for scanning, reviewing, encrypting, and temporarily
   revealing sensitive text inside the knowledge base.
3. Support paragraph reveal: a paragraph containing multiple `secret://`
   references can be displayed temporarily with all references resolved locally.
4. Support large-vault workflows through scan results, review queues, and
   batch replacement with explicit user confirmation.
5. Preserve the agent security boundary: MCP, Codex, Claude, Hermes, and the
   Obsidian plugin do not receive decrypted values through normal tool calls or
   paragraph reveal responses.
6. Reduce semantic leakage around encrypted references by detecting and warning
   about risky context such as “password is secret://...”.

## Non-goals

- Bulk plaintext export.
- Full-note encryption.
- Multi-user sharing.
- Mobile clients.
- Protection against same-user malware, root/admin compromise, screen
  recording, physical observation, compromised app binaries, or compromised
  developer signing identity.
- Automatic rewriting without preview for medium- or low-confidence findings.
- Sending decrypted values through the LLM conversation.

## User-facing product shape

Phase 6 has two visible surfaces.

### macOS app: Vault Workbench

The app becomes the local authority and status surface:

- Shows vault lock state, IPC status, current knowledge-base root, and Obsidian
  plugin connection state.
- Provides setup guidance for installing and pairing the Obsidian plugin.
- Shows recent non-sensitive audit events.
- Handles local authorization prompts for read, write, external-send, and
  delete-risk operations.
- Displays temporary plaintext only in app-controlled reveal surfaces.
- Shows orphan records and failed replacement recovery records after a scan.

The macOS app should stop presenting placeholder workflow pages as if they are
working tools. A section that is not connected must be visibly marked as not
ready, or omitted until it is connected.

### Obsidian plugin: Knowledge-base guard

The plugin provides direct operations where the user edits notes:

- Encrypt selection.
- Encrypt current paragraph.
- Scan current note.
- Scan entire vault.
- Review scan candidates with confidence, matched rule, file path, and diff.
- Apply selected replacements.
- Request temporary reveal for current paragraph.
- Request temporary reveal for selected text.
- Show unresolved or orphaned `secret://` references.
- Warn when surrounding context leaks semantics.

The plugin must not receive decrypted values from the app, and must not store
decrypted plaintext in Markdown, Obsidian metadata, workspace state, logs,
localStorage, IndexedDB, or search indexes.

## Core workflows

### 1. First-run setup

1. User opens Agent Secret Vault.
2. App creates or unlocks the local vault.
3. App starts local IPC and writes a user-only capability token.
4. User installs the Obsidian plugin.
5. Plugin pairs with the app by reading the app-published endpoint metadata and
   completing a local authorization step.
6. App dashboard shows plugin connected.

Acceptance criteria:

- Pairing succeeds without copying plaintext secrets.
- IPC socket and token files remain user-only.
- Plugin cannot operate if the app is locked or unreachable.
- The app clearly explains where encrypted records live and which knowledge-base
  root is active.

### 2. Encrypt selected text

1. User selects text in Obsidian.
2. User runs “Agent Secret Vault: Encrypt selection”.
3. Plugin sends selected plaintext to the local app over authenticated local IPC.
4. App asks for write authorization if needed.
5. App encrypts the plaintext and stores the encrypted record.
6. App returns only a `secret://` reference.
7. Plugin replaces the selected text with the reference.
8. Plugin records a non-sensitive local operation result.

Acceptance criteria:

- If replacement fails, the original note remains unchanged and the app marks
  the encrypted record as unlinked for recovery.
- Labels and metadata must not include the plaintext.
- The reference is random and contains no semantic hints.
- This workflow may send currently selected plaintext from Obsidian to the local
  app for encryption, but app-to-plugin responses still contain only references
  or non-sensitive status.

### 3. Scan current note or entire vault

1. User chooses scan scope: current selection, current note, folder, or entire
   vault.
2. Plugin reads Markdown files locally and applies detection rules.
3. Findings are grouped by file and confidence.
4. User reviews a diff for each candidate.
5. User confirms selected candidates.
6. Plugin sends each selected plaintext span to the app for encryption.
7. Plugin applies replacements transactionally per file.

Detection rule categories:

- High confidence: private keys, API keys with known prefixes, bearer tokens,
  obvious password assignments, `.env`-style secrets.
- Medium confidence: cookies, session tokens, connection strings, long random
  credentials, structured personal identifiers.
- Low confidence: custom dictionary terms, project-specific labels, ambiguous
  numbers, surrounding-language heuristics.

Acceptance criteria:

- Whole-vault scan is review-first, not auto-replace.
- High-confidence findings may be preselected, but user confirmation is still
  required before note modification.
- The scanner never sends Markdown content to an LLM or remote service.
- The scanner can resume after interruption without duplicating replacements.
- Scan results do not include full plaintext in persistent logs.

### 4. Paragraph temporary reveal

1. User places the cursor in a paragraph or selects a text block.
2. Plugin extracts all `secret://` references in that scope.
3. Plugin sends a reveal request containing references, non-secret surrounding
   paragraph text, reference ranges, and reason text.
4. App requests read authorization.
5. App resolves all references locally.
6. The app displays a temporary floating panel or app-owned reveal window with
   the resolved paragraph.
7. Plaintext is cleared on timeout, blur, lock, app disconnect, note switch, or
   explicit close.

Acceptance criteria:

- The Markdown file is not modified.
- Plaintext is not copied automatically.
- The reveal surface is visually distinct from the editor and is owned by the
  macOS app, not by persistent Obsidian editor state.
- Multiple references in one paragraph are resolved in a single authorization
  window.
- Missing or unauthorized references appear as redacted placeholders, not as
  partial plaintext.
- The app does not return decrypted values to the plugin; it returns only a
  reveal-session status.

### 5. Agent use through MCP

Agents interact with references, not plaintext:

- `vault_status` reports non-sensitive availability and lock state.
- `secret_create_request` asks the app/plugin to encrypt a local selection.
- `secret_reveal_request` displays plaintext to the user locally and returns
  only `DISPLAYED_TO_USER`.
- `secure_execute` resolves references only inside the app boundary and returns
  sanitized output.
- A future `paragraph_reveal_request` may ask the app to display a locally
  resolved paragraph to the user, but it must not return plaintext to MCP.

Acceptance criteria:

- MCP schemas reject raw secret values in secret slots.
- MCP tool descriptions explicitly say plaintext is never returned.
- Tool tests include canary secrets and verify they do not appear in structured
  content, text content, stdout, stderr, errors, or logs.
- Agent-facing skills tell Codex, Claude, and Hermes to treat `secret://` as an
  opaque handle and never ask the user to paste plaintext.

## Data model

### Markdown reference

Markdown stores only opaque references:

```text
secret://0123456789ABCDEFGHJKMNPQRS
```

The reference must not encode:

- service name;
- user name;
- secret type;
- length;
- creation timestamp;
- hash prefix;
- policy;
- label.

### Optional display wrapper

The plugin may support an optional Markdown wrapper for readability:

```md
{{secret:secret://0123456789ABCDEFGHJKMNPQRS}}
```

The raw `secret://` reference remains canonical. The wrapper is only an editor
affordance and must not include sensitive labels.

### Encrypted records

Encrypted record storage remains app-owned sidecar data. Each record stores:

- random record ID;
- ciphertext;
- nonce;
- encrypted metadata needed for policy enforcement;
- non-sensitive policy class;
- version;
- creation and migration data that do not reveal plaintext.

Labels are allowed only if they pass plaintext and semantic-leak checks.

### Scan index

Scan state may persist only non-sensitive operational data:

- file path;
- content hash or mtime;
- byte or character ranges;
- rule ID;
- confidence;
- redacted preview;
- replacement status;
- reference ID after successful encryption.

It must not persist full matched plaintext.

## IPC/API additions

The app needs a real request handler behind the existing IPC transport.

Required requests:

- `status`: app lock, vault availability, active knowledge-base root, plugin
  pairing state.
- `encryptText`: encrypt explicit local text from the paired local Obsidian
  plugin and return a reference.
- `encryptSelection`: encrypt app-accessible current selection where supported.
- `revealReferences`: resolve one or more references inside an app-controlled
  temporary reveal session and return only session status to the caller.
- `openRevealSession`: create a short-lived display session for paragraph
  reveal.
- `scanOrphans`: compare Markdown references and sidecar records.
- `secureExecute`: execute allowlisted templates with secrets resolved inside
  the app boundary.

The existing MCP `secret_create_request` can remain selection-based, but the
Obsidian plugin needs `encryptText` because it owns editor selection access.

## Semantic leakage controls

Encryption hides values, not all meaning. Phase 6 must make this explicit and
provide tools to reduce surrounding-context leakage.

Examples of risky context:

```md
我的 Gmail 密码是 secret://...
AWS root key: secret://...
银行卡号：secret://...
```

The plugin should warn and optionally suggest neutral rewrites:

```md
凭据：secret://...
账户信息：secret://...
敏感引用：secret://...
```

Acceptance criteria:

- The app and plugin never claim that opaque references hide all surrounding
  meaning.
- Scanner includes a context-leak rule category.
- Agent instructions require references to be treated as opaque handles, not as
  values to infer, transform, summarize, or classify beyond user-visible
  context.

## Error handling

- App unavailable: plugin shows reconnect instructions and does not modify
  notes.
- Vault locked: plugin offers “Unlock in Agent Secret Vault”.
- Authorization cancelled: no note modification occurs.
- Encryption succeeds but replacement fails: app records an unlinked encrypted
  record and plugin shows recovery instructions.
- Replacement partially fails in a file: plugin restores from a per-file backup
  or leaves a clear recovery diff.
- Reference missing: reveal shows a redacted missing-reference placeholder.
- Output sanitizer quarantines result: MCP receives only `QUARANTINED` and a
  non-sensitive reason.

## Testing strategy

### macOS app tests

- IPC request routing for status, encrypt, reveal, and failure responses.
- Authorization risk separation.
- Multi-reference reveal session clears plaintext on timeout, blur, lock, sleep,
  note switch, and explicit close.
- Unlinked encrypted record recovery.
- Orphan scan comparison between Markdown references and sidecar records.

### Obsidian plugin tests

- Scanner finds high-confidence secrets without remote calls.
- Replacement is transactional per file.
- Scan state never persists full plaintext.
- Paragraph reveal does not return plaintext to the plugin and does not write
  plaintext to Markdown or persistent plugin state.
- Context-leak warnings trigger on risky surrounding language.

### MCP tests

- Plaintext canaries do not appear in MCP structured content, text content,
  stdout, stderr, exceptions, logs, or snapshots.
- Raw secret inputs are rejected where a `secret://` reference is required.
- Reveal requests return only status codes.

### Manual QA

- Pair a real Obsidian vault with the app.
- Scan a copy of a large vault.
- Review and replace high-confidence findings.
- Reveal a paragraph containing at least three references.
- Confirm Obsidian search does not index revealed plaintext.
- Confirm app UI and docs do not claim protection against excluded local
  attacker classes.

## Release gates

Phase 6 is not complete until:

1. A user can encrypt selected Obsidian text and see the Markdown replaced with
   a `secret://` reference.
2. A user can scan a large vault, review candidates, and batch-confirm
   replacements.
3. A user can temporarily reveal a paragraph with multiple references without
   writing plaintext back to disk.
4. Codex can carry a reference through MCP without receiving plaintext.
5. The app shows real connection and workflow state, not placeholder pages.
6. Automated canary tests prove plaintext does not leak through MCP, logs,
   scan state, persistent plugin storage, or generated artifacts.

## Implementation order recommendation

1. App-side IPC request handler and real status surface.
2. Obsidian plugin skeleton and pairing flow.
3. Encrypt selection from Obsidian.
4. Paragraph reveal session.
5. Current-note scanner with preview and transactional replacement.
6. Whole-vault scanner with resumable review queue.
7. Context-leak warnings and neutral rewrite suggestions.
8. Orphan review wired to real Markdown/reference scans.
9. MCP schema and skill updates for the expanded workflow.

This order makes the smallest useful product appear early: encrypt selection
and paragraph reveal. Whole-vault automation comes after the safety boundary is
working in a real editor.
