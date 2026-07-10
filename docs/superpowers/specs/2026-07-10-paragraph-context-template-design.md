# Paragraph Context Template Design

## Goal

Make each saved secret usable as a paragraph-level context template so the Vault can show and copy the surrounding operational context with the correct `secret://` reference.

## User Experience

- Encrypting a selection or a scanner finding creates a record whose label is a sanitized version of its containing paragraph.
- The selected secret is replaced with a fixed reference marker before the record is created.
- The Vault replaces that marker with the record's actual `secret://` reference when displaying and copying the card.
- The default copy action copies the complete usable paragraph template; users can still select the displayed reference directly when they need only the opaque handle.

## Safety Boundary

- Do not store the original paragraph as record metadata.
- Replace the selected secret with the reference marker and replace every other detector-recognized sensitive match with `已隐藏` before the label is sent to the Mac app.
- Preserve paragraph structure and non-sensitive context only. Do not infer a secret's meaning beyond the source paragraph.
- The resulting label is authenticated record metadata, not ciphertext. This intentionally preserves operational semantics in the local Vault and copied snippet, as explicitly requested.
- Existing labels and records remain valid: if a label does not contain the marker, display and copy it with its reference as a separate line.

## Implementation

- Add a plugin-local context-template builder that uses `extractCurrentParagraph`, `detectSensitiveText`, and the existing reverse-order replacement utility.
- Use it for selected encryption and scanning before calling `encryptText`.
- Update the macOS saved-reference card to render a multiline template and replace the marker with the record reference at copy time.
- Add focused plugin tests for selected and scanned paragraph templates plus a workbench source test for marker replacement and full-snippet copy.

## Verification

- TDD: new tests must fail before the builder and card rendering are changed.
- Run the full Obsidian plugin test, typecheck, and build sequence.
- Run the full macOS test suite, whitespace check, and plaintext canary scan.
