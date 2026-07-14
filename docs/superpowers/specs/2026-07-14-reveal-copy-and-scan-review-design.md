# Reveal Copy and Scan Review Design

## Goal

Make a multi-reference temporary reveal practical to use without manually selecting text, and make Obsidian scan findings reviewable before encryption.

## User Experience

- A temporary reveal opened by an agent shows the resolved paragraph and one copy button for every `secret://` reference in source order: `复制密文 1`, `复制密文 2`, and so on.
- Each per-reference button copies only that reference's resolved plaintext. The existing whole-paragraph copy action remains available in App and menu-bar paragraph restore views.
- The App's paragraph restore view and compact menu-bar restore view expose the same ordered per-reference copy buttons after a successful restore.
- Obsidian's scan review modal shows the actual matched value and a bounded excerpt of its source line, next to file, rule, confidence, and selection state. Users decide case by case whether to encrypt.

## Architecture

- Replace the string-only paragraph restore result inside the macOS App with a local, non-Codable `RestoredParagraph` value containing the resolved paragraph plus an ordered list of per-reference plaintext values.
- Build the result from the existing reference list and resolved values in `VaultAppServices`; the values never cross the IPC protocol, disk, audit log, or record metadata boundaries.
- Store the result only in `RevealSessionStore` while the temporary reveal is open. The existing close, session-clear, sleep, lock, and app-deactivation paths discard the whole result.
- Give the main App and menu-bar paragraph-restore views the same local result type so they can render the same numbered copy controls.
- Keep scan source text only in `ScanFindingState.plaintextForCurrentProcessOnly`. Derive the visible line excerpt from the in-memory file snapshot during scanning; do not serialize it, put it in settings, or include it in notices.

## Safety Boundary

- A numbered copy button copies only the associated resolved plaintext, never the opaque `secret://` handle and never unrelated values from the paragraph.
- Copy continues to use the macOS system clipboard and therefore requires the existing explicit confirmation for temporary agent reveal windows. App workbench copy follows its current direct-copy behaviour.
- Closing a temporary reveal, clearing restore output, hiding the menu panel, losing active session, sleeping, or quitting invalidates all resolved values and makes its copy buttons unavailable.
- The scan review modal may show plaintext only while it is open. `onClose` clears references to the findings and their in-memory plaintext. Applying or cancelling never persists scan plaintext except when an explicitly selected finding is encrypted by the existing authenticated IPC path.
- Existing detector output remains redacted-only. Exact text is introduced only by the scanner's process-local state after a user initiates a scan.

## Error Handling

- A restore with no references, an invalid reference, or authorization/decryption failure keeps per-reference controls hidden and follows the existing error copy.
- A scan finding without process-local plaintext or an excerpt falls back to its redacted preview and remains selectable; it must not reconstruct or persist the original value.
- Duplicate references in a paragraph are retained as separate ordered entries because each occurrence is an actionable copy target.

## Testing and Verification

- Add Swift unit tests for ordered restored values, duplicate references, clearing sensitive output, and per-reference clipboard selection.
- Add Swift source/UI tests to ensure all three reveal surfaces render numbered controls and continue clearing their state at existing lifecycle boundaries.
- Add Obsidian modal tests proving the exact value and context are shown only from process-local scan data and that close clears it.
- Run the macOS test suite, Obsidian test/typecheck/build sequence, `git diff --check`, and the plaintext canary scan.
