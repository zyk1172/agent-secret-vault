# Obsidian Paragraph Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Review scan results as complete Markdown content blocks, automatically prioritise credentials, and never offer already encrypted values for replacement.

**Architecture:** Extend detector output with a non-sensitive selection policy and reject matches that overlap valid secret references or placeholders. The scanner adds an in-memory content-block snapshot and absolute block offset to every finding. The review modal groups findings using those transient fields, renders value spans in red, and manages selection per finding; the existing replacement code retains selected absolute ranges and content-hash validation.

**Tech Stack:** TypeScript 5.9, Obsidian API, Vitest 4, esbuild.

## Global Constraints

- A valid `secret://` reference, any overlap with one, Markdown decoration around it, and explicit placeholders are never encryptable candidates.
- Credential rules are selected by default; personal-identifier rules are visible manual candidates and start unselected.
- Content blocks, offsets, and exact values are process-local only and are omitted from serialised scan state, settings, notices, logs, and IPC payloads.
- A review card must preserve the complete local content block and only replace individually selected sensitive values.
- Closing, cancelling, or applying the review clears every process-local plaintext field.
- Replacement operations retain their existing content-hash validation and descending-offset transaction.

---

### Task 1: Classify default selection and reject protected text

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/scan/detectors.ts`
- Test: `obsidian-plugin/agent-secret-vault/test/detectors.test.ts`

**Interfaces:**
- Produces `SensitiveSelectionPolicy = "automatic" | "manual"`.
- Adds `selectionPolicy: SensitiveSelectionPolicy` to `SensitiveFinding`.
- Produces `isDefaultSelected(finding: SensitiveFinding): boolean`.

- [ ] **Step 1: Write failing detector tests**

```ts
it("marks credentials automatic and identifiers manual", () => {
  const findings = detectSensitiveText("password = example-password\nuser@example.com");
  expect(findings.map((finding) => finding.selectionPolicy)).toEqual(["automatic", "manual"]);
  expect(findings.map(isDefaultSelected)).toEqual([true, false]);
});

it("ignores Markdown-wrapped references and placeholders", () => {
  const reference = "secret://0123456789ABCDEFGHJKMNPQRS";
  expect(detectSensitiveText(`**密码：** ${reference}\nAPI Key：[待填]`)).toEqual([]);
});

it("keeps a raw password next to a protected reference", () => {
  const reference = "secret://0123456789ABCDEFGHJKMNPQRS";
  const findings = detectSensitiveText(`用户名：${reference}\n密码：example-password`);
  expect(findings).toHaveLength(1);
  expect(findings[0]).toMatchObject({ ruleId: "chinese-secret-assignment", selectionPolicy: "automatic" });
});
```

- [ ] **Step 2: Run the focused detector test and verify it fails**

Run: `npm test -- --run test/detectors.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: FAIL because `selectionPolicy` and `isDefaultSelected` do not exist and wrapped references can still produce false candidates.

- [ ] **Step 3: Add the minimal detector policy and protected-range filter**

```ts
export type SensitiveSelectionPolicy = "automatic" | "manual";

export interface SensitiveFinding {
  start: number;
  end: number;
  ruleId: SensitiveRuleId;
  confidence: SensitiveConfidence;
  selectionPolicy: SensitiveSelectionPolicy;
  redactedPreview: string;
}

const manualRules = new Set<SensitiveRuleId>([
  "email-address", "phone-number", "china-id-card", "bank-card"
]);

export function isDefaultSelected(finding: SensitiveFinding): boolean {
  return finding.selectionPolicy === "automatic";
}
```

Collect valid `secret://` ranges before running rule matches. Reject a match when its range intersects a reference range, its trimmed value begins with `secret://`, or its trimmed value is a Markdown decoration or recognised placeholder. Assign `manual` only to `manualRules`; assign `automatic` to every other rule.

- [ ] **Step 4: Run the focused detector test and verify it passes**

Run: `npm test -- --run test/detectors.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: PASS, including all existing redaction and overlap-priority tests.

- [ ] **Step 5: Commit the detector behaviour**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan/detectors.ts \
  obsidian-plugin/agent-secret-vault/test/detectors.test.ts
git commit -m "fix: filter protected scan references"
```

### Task 2: Capture complete process-local content blocks

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/scan/scanState.ts`
- Modify: `obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts`
- Test: `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`

**Interfaces:**
- Adds `contentBlockForCurrentProcessOnly?: string` to `ScanFindingState`.
- Adds `contentBlockStartForCurrentProcessOnly?: number` to `ScanFindingState`.
- Produces `contentBlock(text: string, start: number, end: number): { text: string; start: number }` in `vaultScanner.ts`.

- [ ] **Step 1: Write failing content-block tests**

```ts
it("keeps a heading and all local field lines in one content block", () => {
  const text = "# NewAPI\n\n服务：NewAPI\n地址：https://example.test/v1\nAPI：example-api-key\n\n# Other";
  const [finding] = scanMarkdownFile("Secrets.md", text);
  expect(finding.contentBlockForCurrentProcessOnly).toBe(
    "# NewAPI\n\n服务：NewAPI\n地址：https://example.test/v1\nAPI：example-api-key"
  );
  expect(finding.contentBlockStartForCurrentProcessOnly).toBe(0);
});

it("does not serialise content blocks or block offsets", () => {
  const serialized = serializeScanState(scanMarkdownFile("Secrets.md", "密码：example-password"));
  expect(serialized).not.toContain("密码：example-password");
  expect(serialized).not.toContain("contentBlock");
});
```

- [ ] **Step 2: Run the focused scanner test and verify it fails**

Run: `npm test -- --run test/scanState.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: FAIL because the state has only the bounded source-line excerpt.

- [ ] **Step 3: Replace line excerpts with content-block snapshots**

```ts
export interface ScanFindingState extends SensitiveFinding {
  filePath: string;
  contentHash: string;
  reference?: string;
  plaintextForCurrentProcessOnly?: string;
  contentBlockForCurrentProcessOnly?: string;
  contentBlockStartForCurrentProcessOnly?: number;
}
```

Implement `contentBlock` by locating the nearest blank-line boundaries around the matching line. When the preceding non-empty block is a Markdown heading, prepend it and the intervening blank lines. In `scanMarkdownFile`, calculate one block per finding and store its text and absolute start. Update `omitPlaintext` to remove all three process-local fields.

- [ ] **Step 4: Run the focused scanner test and verify it passes**

Run: `npm test -- --run test/scanState.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: PASS; serialised state contains only detector metadata and file metadata.

- [ ] **Step 5: Commit transient content-block state**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan/scanState.ts \
  obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts \
  obsidian-plugin/agent-secret-vault/test/scanState.test.ts
git commit -m "feat: retain scan content blocks in memory"
```

### Task 3: Render grouped review cards with controlled selection

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts`
- Test: `obsidian-plugin/agent-secret-vault/test/reviewModal.test.ts`

**Interfaces:**
- Produces `groupFindingsByContentBlock(findings: ScanFindingState[]): ScanFindingState[][]`.
- Uses `isDefaultSelected` from `detectors.ts` to initialise selection.
- Produces `renderContentBlock(parent: HTMLElement, findings: ScanFindingState[]): void`.

- [ ] **Step 1: Write failing modal tests**

```ts
it("groups matches into one paragraph card with red sensitive values", () => {
  const first = finding({
    start: 12, end: 28, selectionPolicy: "automatic",
    contentBlockStartForCurrentProcessOnly: 0,
    contentBlockForCurrentProcessOnly: "服务：NAS\n密码：example-password"
  });
  const modal = new ReviewModal({} as never, [first]);
  modal.onOpen();
  expect(modalMock.latestContentEl?.findByClass("asv-scan-card")).toHaveLength(1);
  expect(modalMock.latestContentEl?.findByClass("asv-scan-sensitive").map((node) => node.textContent)).toEqual(["example-password"]);
});

it("selects credentials by default but leaves manual candidates unchecked", () => {
  const modal = new ReviewModal({} as never, [
    finding({ selectionPolicy: "automatic" }),
    finding({ start: 20, end: 35, ruleId: "email-address", selectionPolicy: "manual" })
  ]);
  modal.onOpen();
  expect(modalMock.latestContentEl?.checkboxes().map((checkbox) => checkbox.checked)).toEqual([true, false]);
});

it("select all selects every candidate and clear selection deselects every candidate", () => {
  const modal = new ReviewModal({} as never, [finding({ selectionPolicy: "automatic" }), finding({ start: 20, end: 35, selectionPolicy: "manual" })]);
  modal.onOpen();
  modalMock.latestContentEl?.findButton("全选")?.listeners.get("click")?.();
  expect(modalMock.latestContentEl?.checkboxes().every((checkbox) => checkbox.checked)).toBe(true);
  modalMock.latestContentEl?.findButton("取消全选")?.listeners.get("click")?.();
  expect(modalMock.latestContentEl?.checkboxes().every((checkbox) => !checkbox.checked)).toBe(true);
});

it("applies only default-selected credential findings", async () => {
  const automatic = finding({ selectionPolicy: "automatic" });
  const manual = finding({ start: 20, end: 35, ruleId: "email-address", selectionPolicy: "manual" });
  const apply = vi.fn(async () => undefined);
  const modal = new ReviewModal({} as never, [automatic, manual], apply);
  modal.onOpen();
  await modalMock.latestContentEl?.findButton("加密选中项（1）")?.listeners.get("click")?.();
  expect(apply).toHaveBeenCalledWith([automatic]);
});
```

Extend `FakeElement` with `addClass`, `classes`, `findByClass`, `checkboxes`, and `findButton` so the tests inspect rendered semantics rather than implementation strings.

- [ ] **Step 2: Run the focused modal test and verify it fails**

Run: `npm test -- --run test/reviewModal.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: FAIL because the modal renders one list item per finding, selects all values, and has no grouped spans or selection controls.

- [ ] **Step 3: Implement cards, red spans, and selection controls**

```ts
const selected = new Set(this.findings.filter(isDefaultSelected));
const refreshSelection = (): void => {
  for (const checkbox of checkboxes) checkbox.checked = selected.has(checkbox.finding);
  actionButton.textContent = `加密选中项（${selected.size}）`;
};

selectAllButton.addEventListener("click", () => {
  for (const finding of this.findings) selected.add(finding);
  refreshSelection();
});

clearButton.addEventListener("click", () => {
  selected.clear();
  refreshSelection();
});
```

Group with `filePath`, `contentHash`, and `contentBlockStartForCurrentProcessOnly`. Render each block as DOM text nodes split at every finding range relative to the block start; give value spans the `asv-scan-sensitive` class and set their color to Obsidian's `var(--text-error)`. Give each value a checkbox and concise rule label beneath the block. Do not use `innerHTML`. Keep the empty state and the existing apply callback.

- [ ] **Step 4: Run the focused modal test and verify it passes**

Run: `npm test -- --run test/reviewModal.test.ts`

Working directory: `obsidian-plugin/agent-secret-vault`

Expected: PASS; existing close cleanup tests are updated to assert block text and offsets are cleared.

- [ ] **Step 5: Commit the review UI**

```bash
git add obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts \
  obsidian-plugin/agent-secret-vault/test/reviewModal.test.ts
git commit -m "feat: review scans by content block"
```

### Task 4: Preserve selected-only replacement and run plugin verification

**Files:**
- Verify: `obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts`
- Verify: `obsidian-plugin/agent-secret-vault/src/main.ts`
- Verify: `obsidian-plugin/agent-secret-vault/src/replace/transactionalReplace.ts`

**Interfaces:**
- Consumes `ScanFindingState[]` selected by `ReviewModal` without changing `encryptFindingsInText` or `applyReplacements` signatures.
- Preserves descending absolute offset replacements and existing snapshot/hash checks.

- [ ] **Step 1: Inspect replacement-boundary coverage before the final suite**

Read `test/scanCommands.test.ts`, `src/main.ts`, and `src/replace/transactionalReplace.ts` together. Confirm that `ReviewModal` passes only the selected `ScanFindingState[]`, `encryptFindingsInText` only loops over that array, and `applyReplacements` validates non-overlapping absolute ranges before replacing them from the end of the document.

- [ ] **Step 2: Run the complete Obsidian and repository verification suite**

```bash
cd obsidian-plugin/agent-secret-vault
npm test
npm run typecheck
npm run build
npm run check:build-artifact
cd ../..
git diff --check
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/agent-secret-vault/main.js obsidian-plugin/agent-secret-vault/dist
```

Expected: every command exits `0`; the canary scan reports no persisted plaintext canary.

- [ ] **Step 3: Commit the built Obsidian artifact and final source changes**

```bash
git add obsidian-plugin/agent-secret-vault/src/scan/detectors.ts \
  obsidian-plugin/agent-secret-vault/src/scan/scanState.ts \
  obsidian-plugin/agent-secret-vault/src/scan/vaultScanner.ts \
  obsidian-plugin/agent-secret-vault/src/ui/reviewModal.ts \
  obsidian-plugin/agent-secret-vault/test/detectors.test.ts \
  obsidian-plugin/agent-secret-vault/test/scanState.test.ts \
  obsidian-plugin/agent-secret-vault/test/reviewModal.test.ts \
  obsidian-plugin/agent-secret-vault/main.js
git commit -m "feat: review scans by paragraph"
```
