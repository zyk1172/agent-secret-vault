# Agent Secret Vault UI redesign

## Confirmed brief

Redesign the Agent Secret Vault macOS app so it is clearly usable by a person, not only technically correct for tests. The confirmed direction is **A+B**:

- a native macOS security console structure for long-term use;
- a first-run / empty-state guide that explains exactly how to use the product;
- restrained but polished security-product visual treatment;
- native-quality bilingual copy in Simplified Chinese and English.

The UI must explain the core promise immediately:

> Agents can carry `secret://` references, but plaintext stays inside the Mac app.

Chinese UI copy must read naturally for a Chinese-speaking user. English UI copy must read naturally for an English-speaking user. Do not ship literal machine-translation phrasing.

## Current problem

The current app opens directly into `SecureViewerView`. When no secret is loaded it says only “No plaintext loaded” and gives little practical instruction. The user cannot tell:

- what Agent Secret Vault does;
- how to encrypt a secret from a knowledge base;
- how Codex / Claude / Hermes should use `secret://` references;
- what the security boundary is;
- what to do next when the window is empty.

The current visual design is functional but sparse. It does not look like a trustworthy macOS security product.

## Goals

1. Make first launch self-explanatory.
2. Keep the security model honest and visible.
3. Make routine use efficient after the user understands the product.
4. Preserve existing fail-closed security behavior.
5. Add bilingual UI copy without weakening clarity.
6. Improve visual hierarchy, spacing, and polish using native SwiftUI patterns.

## Non-goals

- Do not implement Claude or Hermes integrations in this UI pass.
- Do not add bulk plaintext export.
- Do not claim protection against same-user malware, root/admin compromise, screen recording, physical observation, compromised signed binaries, or compromised developer signing identity.
- Do not implement full-note encryption or automatic sensitive-information detection.
- Do not put plaintext examples, real secrets, passwords, tokens, or keys in docs, tests, previews, or fixtures.

## Information architecture

Use a native macOS window with a clear control-console layout.

Primary sections:

1. Overview
   - product promise;
   - vault status;
   - four-step usage guide;
   - key safety boundaries.
2. Encrypt Text
   - explain how selected sensitive text becomes a `secret://` reference;
   - show expected input/output shape without real secrets.
3. Reveal Secret
   - host the improved secure viewer empty and loaded states.
4. Agent Send
   - explain that higher-risk external-send requires fresh authorization and sanitized outputs.
5. Orphan Review
   - present orphan candidates using the same visual language as the rest of the app.
6. Security Model
   - summarize what the app protects and explicitly what it does not protect.

If full navigation is too much for the current code shape, implement the same content as a single-window dashboard with cards and sections. The first implementation may use static navigation labels until deeper flows are wired.

## Main window design

The main window should feel like a native macOS utility:

- minimum window size around 820 × 560;
- sidebar or left rail for product identity and sections;
- content cards with clear rounded rectangles and system materials;
- strong title hierarchy;
- restrained accent color suitable for security software;
- SF Symbols for status and actions where appropriate;
- no decorative fake assets, no emoji-based security badges, no marketing-heavy hero art.

Overview content should include:

- title: “Let agents work with secrets without seeing plaintext.”
- Chinese equivalent: “让 Agent 使用敏感信息，但不接触明文。”
- compact explanation of `secret://` references;
- four-step guide:
  1. Select sensitive text in your knowledge base.
  2. Encrypt it into a `secret://` reference.
  3. Let the agent use the reference in conversation or tools.
  4. Reveal or send through this app after local authorization.
- visible safety boundaries:
  - agents never receive decrypted values;
  - clipboard use is explicit and temporary;
  - higher-risk send/delete operations require fresh authorization;
  - local same-user malware/root compromise is out of scope.

## Secure Viewer design

Empty state must be instructive, not passive.

When no plaintext is loaded:

- show a lock/status illustration using native symbols;
- explain what this screen is for;
- show “How to open a secret” steps;
- show one example reference shape: `secret://0123456789ABCDEFGHJKMNPQRS`;
- provide safe actions such as “Open reference” or “Learn how it works” if the current app architecture supports them.

When plaintext is loaded:

- show a clear “Plaintext visible” risk banner;
- render plaintext in a protected monospaced card with text selection disabled;
- keep “Copy for 60 seconds” behind explicit confirmation;
- show copy countdown or copy-clear explanation;
- keep “Close and clear plaintext” prominent;
- clear plaintext on close, focus loss, sleep, timeout, and app exit as already tested.

## Orphan Review design

Use the same card and status language as Overview and Secure Viewer.

Requirements:

- explain that scanning never deletes anything by itself;
- show candidate count;
- show each candidate as a structured card or table row;
- keep destructive action visually separated;
- keep the confirmation copy explicit that deletion requires highest-risk authorization.

## Bilingual copy model

The first implementation should support bilingual copy in code with clear keys or constants, even if a full `.strings` localization pass is deferred.

Required behavior:

- Chinese and English text must both be authored intentionally.
- UI labels should not mix languages in the same sentence unless naming a protocol, product, or literal such as `secret://`.
- The implementation should be ready to move copy into localization files later.
- Tests should verify that core instructional copy remains present in at least English, and preferably also Chinese for the main user-facing guide.

Preferred copy examples:

| Context | English | Chinese |
| --- | --- | --- |
| Product promise | Let agents work with secrets without seeing plaintext. | 让 Agent 使用敏感信息，但不接触明文。 |
| Reference explanation | Agents receive only opaque `secret://` references. | Agent 只会收到不透明的 `secret://` 引用。 |
| Empty viewer | No plaintext is currently loaded. Open a secret reference to reveal it temporarily. | 当前没有载入明文。打开一个密文引用后，可在此临时查看。 |
| Clipboard warning | Copy only when you are ready to paste immediately. | 只在准备立即粘贴时复制。 |
| Boundary | This does not protect against malware running as the same macOS user. | 这不能防御以同一 macOS 用户身份运行的恶意软件。 |

## Component boundaries

Add small SwiftUI components instead of growing `SecureViewerView` into a large mixed-purpose file.

Suggested components:

- `VaultDashboardView`
  - owns the main window layout and selected section state.
- `OverviewGuideView`
  - renders the product promise, four-step guide, and safety boundaries.
- `SecureViewerView`
  - remains focused on reveal / copy / close behavior.
- `InstructionStepCard`
  - reusable numbered guide card.
- `SecurityBoundaryCard`
  - reusable security claim / limitation card.
- `OrphanReviewView`
  - reuse shared styling helpers where possible.
- `VaultUICopy`
  - central place for bilingual strings or copy constants.

Keep model logic separate from view presentation. Existing security models should not be weakened or bypassed for UI convenience.

## Data flow and interaction

Initial window:

1. App launches.
2. Dashboard opens on Overview.
3. User sees usage steps and current safe status.
4. Reveal Secret section hosts `SecureViewerView`.
5. When the model has plaintext, Secure Viewer shows protected loaded state.
6. When plaintext is cleared, Secure Viewer returns to guided empty state.

Copy flow:

1. User clicks Copy for 60 seconds.
2. Confirmation dialog explains clipboard risk.
3. App copies only after confirmation.
4. App clears only its own clipboard value if unchanged.

Deletion / orphan flow:

1. Scanner identifies orphan candidates.
2. UI labels them as candidates only.
3. User requests deletion.
4. Highest-risk authorization path remains required outside the view.

## Error handling and safety messaging

Errors should use plain-language messages with next steps:

- authorization cancelled: say no plaintext was revealed and how to try again;
- biometric unavailable: explain platform authentication is required;
- malformed reference: show the expected `secret://...` shape;
- unsafe/quarantined agent output: explain it was not returned because it may contain secret material;
- recovery unavailable: say recovery fails closed when required Keychain controls are unavailable.

Do not show raw sensitive values in errors.

## Testing plan

Add or update tests for:

1. Overview guide contains the core product promise.
2. Overview guide contains all four usage steps.
3. Security boundaries include the same-user malware / root limitation.
4. Secure Viewer empty state contains actionable “open a reference” guidance.
5. Secure Viewer loaded state still disables text selection and keeps explicit copy confirmation.
6. Bilingual copy constants include the core Chinese and English promise.
7. Orphan Review copy still states scanning does not delete automatically.

Run the normal release gate after implementation:

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts
git diff --check
```

## Acceptance criteria

- First launch explains what the app does and how to use it.
- A user can understand the `secret://` workflow without reading README first.
- Secure Viewer empty state gives concrete next steps.
- Loaded plaintext state looks intentionally protected and easy to clear.
- Orphan Review matches the new visual system.
- Core UI copy exists in native-quality English and Simplified Chinese.
- Security boundary language remains honest and does not overclaim.
- Existing security tests continue to pass.
