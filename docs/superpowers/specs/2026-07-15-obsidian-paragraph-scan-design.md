# Obsidian Paragraph Scan Design

> **Superseded:** Replaced by `2026-07-15-central-sensitive-index-design.md`.
> The new workflow uses an App-managed central encrypted index and explicit
> user decisions instead of an Obsidian-owned scan-review flow.

## Goal

Make scan review useful for deciding what to encrypt. Present each finding in
its readable Markdown context, prioritise credentials for encryption, and
exclude data that is already protected.

## Review Unit

The review modal groups findings by a local Markdown content block rather than
by detector result. A content block is the contiguous non-empty body lines
around a finding, plus the closest preceding Markdown heading when it is
separated only by blank lines. This keeps a service title and its labelled
fields together in one review card.

Each card displays:

- The source file path.
- The complete in-memory content block.
- Every detected value in that block, highlighted in red.
- A checkbox for every detected value, so one block can encrypt one or many
  values without encrypting its labels or unrelated fields.

The modal starts with credential candidates selected and all manual candidates
unselected. It provides a `Select all` / `Clear selection` control and an
action button whose count reflects the current selection.

## Candidate Policy

Credential rules are automatic candidates: password assignments, Chinese
password/token/key assignments, API keys, GitHub tokens, bearer tokens, JWTs,
private keys, and secret URL parameters. They are highlighted and initially
selected.

Personal identifiers such as email addresses, phone numbers, identity-card
numbers, and bank-card numbers remain manual candidates. They are highlighted
but initially unselected.

Existing valid `secret://` references are never candidates. The detector must
also reject values overlapping an existing reference, Markdown decoration that
precedes a reference, and explicit placeholders such as `[to fill]` or
`[pending]`. A block containing both an existing reference and a separate raw
credential still shows the raw credential only.

## Data Boundaries

Full content blocks, block offsets, and exact matched values are process-local
scan state only. They are omitted from serialised state, settings, notices,
logs, and IPC payloads. Closing, cancelling, or applying the review clears all
process-local scan text.

The encryption transaction continues to receive only the selected match ranges
and must retain its existing content-hash check before replacing text.

## Error Handling

If a process-local block is unavailable, the modal falls back to the existing
redacted candidate presentation without reconstructing plaintext. If no
candidates remain after filtering references and placeholders, the existing
empty-state guidance is shown.

## Verification

- Detector tests cover valid references, Markdown-wrapped references,
  placeholders, and raw credentials next to protected references.
- Scanner tests cover complete content-block extraction and non-persistence.
- Modal tests cover grouping, red highlighting, credential-only default
  selection, and select-all controls.
- Obsidian typecheck, tests, bundle validation, whitespace validation, and the
  plaintext canary scan remain required before release.
