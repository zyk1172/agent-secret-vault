import { MarkdownView, Menu, Notice, Plugin, type Editor, type EditorPosition, type TFile } from "obsidian";
import { buildParagraphContextTemplate } from "./encrypt/paragraphContextTemplate";
import { encryptTextRange, inferReferenceTitle } from "./encrypt/encryptSelection";
import { extractCurrentParagraph, type TextRange } from "./editor/selection";
import { LocalVaultClient } from "./ipc/client";
import type { IpcRequest } from "./ipc/protocol";
import { interpretWorkbenchStatus } from "./pairing/pairing";
import { applyReplacements, type PlannedReplacement } from "./replace/transactionalReplace";
import { buildParagraphRestoreRequest, buildParagraphRevealRequest } from "./reveal/paragraphReveal";
import type { ScanFindingState } from "./scan/scanState";
import { scanMarkdownFile } from "./scan/vaultScanner";
import { ReviewModal } from "./ui/reviewModal";
import { updateStatusBar } from "./ui/statusBar";

const DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;

function clonePosition(position: EditorPosition): EditorPosition {
  return { line: position.line, ch: position.ch };
}

export const commandDefinitions = [
  { id: "encrypt-selection", name: "加密选中文本" },
  { id: "reveal-selection", name: "在 SVLT 中临时解密选中文本" },
  { id: "reveal-current-paragraph", name: "在 SVLT 中临时解密当前段落" },
  { id: "restore-selection", name: "还原选中文本中的密文引用" },
  { id: "restore-current-paragraph", name: "还原当前段落中的密文引用" }
] as const;

export default class AgentSecretVaultPlugin extends Plugin {
  private createVaultClient(): LocalVaultClient {
    return new LocalVaultClient(DEFAULT_SOCKET_PATH);
  }

  async onload(): Promise<void> {
    const pairing = interpretWorkbenchStatus({ reachable: false });
    const status = this.addStatusBarItem();
    updateStatusBar(status, { connected: pairing.canOperate, locked: !pairing.canOperate });
    await this.refreshStatus(status);

    for (const definition of commandDefinitions) {
      const command = {
        id: definition.id,
        name: definition.name,
        callback: () => {
          new Notice(`SVLT: ${definition.id} is not connected yet.`);
        }
      };

      if (definition.id === "encrypt-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptSelection(editor);
          }
        });
      } else if (definition.id === "reveal-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.revealCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "reveal-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.revealSelection(editor);
          }
        });
      } else if (definition.id === "restore-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.restoreSelection(editor);
          }
        });
      } else if (definition.id === "restore-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.restoreCurrentParagraph(editor);
          }
        });
      } else {
        this.addCommand(command);
      }
    }

    this.registerEditorMenu();
    this.registerJumpProtocol();
  }

  private registerJumpProtocol(): void {
    const registerProtocolHandler = (this as unknown as {
      registerObsidianProtocolHandler?: (action: string, handler: (params: Record<string, string>) => Promise<void>) => void;
    }).registerObsidianProtocolHandler;
    if (typeof registerProtocolHandler !== "function") {
      return;
    }

    registerProtocolHandler.call(this, "svlt", async (params) => {
      const fullPath = typeof params.file === "string" ? params.file : "";
      const requestedLine = Number.parseInt(typeof params.line === "string" ? params.line : "1", 10);
      if (fullPath.length === 0 || !Number.isFinite(requestedLine) || requestedLine < 1) {
        new Notice("SVLT: invalid local jump request.");
        return;
      }

      const adapter = this.app.vault.adapter as unknown as { getFullPath?: (path: string) => string };
      const file = this.app.vault.getMarkdownFiles().find((candidate) => adapter.getFullPath?.(candidate.path) === fullPath);
      if (!file) {
        new Notice("SVLT: the requested file is not in this vault.");
        return;
      }

      const leaf = this.app.workspace.getLeaf(false);
      await leaf.openFile(file);
      if (leaf.view instanceof MarkdownView) {
        const line = Math.max(0, requestedLine - 1);
        leaf.view.editor.setCursor({ line, ch: 0 });
        leaf.view.editor.scrollIntoView({ from: { line, ch: 0 }, to: { line, ch: 0 } }, true);
      }
    });
  }

  private registerEditorMenu(): void {
    this.registerEvent(this.app.workspace.on("editor-menu", (menu: Menu, editor: Editor) => {
      menu.addItem((item) => {
        item.setTitle("SVLT").setIcon("shield-check");
        const submenu = this.tryCreateSubmenu(item);
        if (submenu) {
          this.populateEditorActionMenu(submenu, editor);
          return;
        }

        item.onClick((event) => {
          this.showEditorActionMenu(event, editor);
        });
      });
    }));
  }

  private tryCreateSubmenu(item: unknown): Menu | null {
    const maybeItem = item as { setSubmenu?: () => Menu };
    if (typeof maybeItem.setSubmenu !== "function") {
      return null;
    }
    return maybeItem.setSubmenu();
  }

  private showEditorActionMenu(event: MouseEvent | KeyboardEvent, editor: Editor): void {
    const actionMenu = new Menu();
    actionMenu.setUseNativeMenu(false);
    this.populateEditorActionMenu(actionMenu, editor);

    if ("clientX" in event && "clientY" in event) {
      actionMenu.showAtMouseEvent(event as MouseEvent);
      return;
    }

    actionMenu.showAtPosition({ x: 0, y: 0 });
  }

  private populateEditorActionMenu(menu: Menu, editor: Editor): void {
    menu.addItem((item) => {
      item
        .setTitle("加密选中文本")
        .setIcon("lock")
        .onClick(async () => {
          await this.encryptSelection(editor);
        });
    });

    menu.addSeparator();

    menu.addItem((item) => {
      item
        .setTitle("临时解密选中文本")
        .setIcon("eye")
        .onClick(async () => {
          await this.revealSelection(editor);
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("还原选中文本")
        .setIcon("rotate-ccw")
        .onClick(async () => {
          await this.restoreSelection(editor);
        });
    });

  }

  private async refreshStatus(status: HTMLElement): Promise<void> {
    try {
      const response = await this.createVaultClient().request({ type: "workbenchStatus" });
      if (response.type === "workbenchStatus") {
        const pairing = interpretWorkbenchStatus({ reachable: true, status: response });
        updateStatusBar(status, {
          connected: pairing.canOperate && response.status.pluginConnected,
          locked: response.status.locked
        });
      }
    } catch {
      updateStatusBar(status, { connected: false, locked: true });
    }
  }

  private async encryptSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (text.length === 0) {
      new Notice("SVLT: select text to encrypt.");
      return;
    }

    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    await this.encryptRange(editor, {
      start: editor.posToOffset(from),
      end: editor.posToOffset(to),
      text
    }, clonePosition(from), clonePosition(to));
  }

  private async encryptCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new Notice("SVLT: current paragraph is empty.");
      return;
    }

    const findings = scanMarkdownFile(this.app.workspace?.getActiveFile()?.path ?? "current-paragraph.md", range.text);
    if (findings.length === 0) {
      new Notice("SVLT: current paragraph has no detected sensitive text; select exact text to encrypt manually.");
      return;
    }

    try {
      const updatedText = await this.encryptFindingsInText(range.text, findings);
      const fromPos = editor.offsetToPos(range.start);
      const toPos = editor.offsetToPos(range.end);
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("SVLT: note changed before encryption completed; leaving text unchanged.");
        return;
      }
      editor.replaceRange(updatedText, fromPos, toPos, "svlt");
      new Notice(`SVLT: encrypted ${findings.length} sensitive finding${findings.length === 1 ? "" : "s"} in current paragraph.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT: paragraph encryption failed (${message}).`);
    }
  }

  private async encryptRange(
    editor: Editor,
    range: TextRange,
    fromPos: EditorPosition,
    toPos: EditorPosition
  ): Promise<void> {
    try {
      const documentText = editor.getValue();
      const result = await encryptTextRange({
        documentText,
        range,
        label: buildParagraphContextTemplate(documentText, range),
        referenceTitle: inferReferenceTitle(documentText, range),
        policy: "credential",
        client: this.createVaultClient()
      });

      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("SVLT: note changed before encryption completed; leaving text unchanged.");
        return;
      }

      editor.replaceRange(result.replacementText, fromPos, toPos, "svlt");
      new Notice("SVLT: encrypted text into a secret reference.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT: encryption failed (${message}).`);
    }
  }

  private async revealCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.revealText(range.text, "SVLT: current paragraph has no secret reference.");
  }

  private async revealSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new Notice("SVLT: select text containing a secret reference to reveal.");
      return;
    }

    await this.revealText(text, "SVLT: selected text has no secret reference.");
  }

  private async revealText(text: string, noReferenceMessage: string): Promise<void> {
    let request: IpcRequest;

    try {
      request = buildParagraphRevealRequest(text);
    } catch {
      new Notice(noReferenceMessage);
      return;
    }

    try {
      const response = await this.createVaultClient().request(request);
      if (response.type !== "revealSessionOpened") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }

      new Notice("SVLT: reveal session opened in the Mac app.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT: reveal failed (${message}).`);
    }
  }

  private async restoreCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.restoreRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end), "SVLT: current paragraph has no secret reference.");
  }

  private async restoreSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new Notice("SVLT: select text containing a secret reference to restore.");
      return;
    }
    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    await this.restoreRange(editor, {
      start: editor.posToOffset(from),
      end: editor.posToOffset(to),
      text
    }, clonePosition(from), clonePosition(to), "SVLT: selected text has no secret reference.");
  }

  private async restoreRange(
    editor: Editor,
    range: TextRange,
    fromPos: EditorPosition,
    toPos: EditorPosition,
    noReferenceMessage: string
  ): Promise<void> {
    let request: IpcRequest;
    try {
      request = buildParagraphRestoreRequest(range.text);
    } catch {
      new Notice(noReferenceMessage);
      return;
    }

    try {
      const response = await this.createVaultClient().request(request);
      if (response.type !== "restoredText") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("SVLT: note changed before restore completed; leaving text unchanged.");
        return;
      }
      editor.replaceRange(response.text, fromPos, toPos, "svlt-restore");
      new Notice("SVLT: restored secret references into plaintext.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT: restore failed (${message}).`);
    }
  }

  private async scanCurrentNote(editor: Editor): Promise<void> {
    const originalText = editor.getValue();
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new Notice("SVLT: note changed after scan; leaving text unchanged.");
          return;
        }

        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings);
        editor.setValue(updatedText);
        new Notice(`SVLT: encrypted ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}.`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`SVLT: scan replacement failed (${message}).`);
      }
    }).open();
  }

  private async scanVault(): Promise<void> {
    const files = this.app.vault.getMarkdownFiles();
    const filesByPath = new Map(files.map((file) => [file.path, file]));
    const snapshots = new Map<string, string>();
    const allFindings: ScanFindingState[] = [];

    for (const file of files) {
      const text = await this.app.vault.cachedRead(file);
      snapshots.set(file.path, text);
      allFindings.push(...scanMarkdownFile(file.path, text));
    }

    new ReviewModal(this.app, allFindings, async (selectedFindings) => {
      try {
        const result = await this.applyVaultFindings(selectedFindings, filesByPath, snapshots);
        new Notice(this.replacementSummary(result.appliedCount, result.skippedCount));
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`SVLT: scan replacement failed (${message}).`);
      }
    }).open();
  }

  private async scanOrphans(): Promise<void> {
    const references = new Set<string>();
    for (const file of this.app.vault.getMarkdownFiles()) {
      const text = await this.app.vault.cachedRead(file);
      for (const reference of extractSecretReferences(text)) {
        references.add(reference);
      }
    }

    try {
      const response = await this.createVaultClient().request({
        type: "scanOrphans",
        markdownReferences: [...references].sort()
      });
      if (response.type !== "orphanScan") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      new Notice("SVLT: orphan scan sent to the Mac app.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT: orphan scan failed (${message}).`);
    }
  }

  private async applyVaultFindings(
    selectedFindings: ScanFindingState[],
    filesByPath: Map<string, TFile>,
    snapshots: Map<string, string>
  ): Promise<{ appliedCount: number; skippedCount: number }> {
    const findingsByPath = new Map<string, ScanFindingState[]>();
    let appliedCount = 0;
    let skippedCount = 0;
    for (const finding of selectedFindings) {
      const existing = findingsByPath.get(finding.filePath) ?? [];
      existing.push(finding);
      findingsByPath.set(finding.filePath, existing);
    }

    for (const [filePath, findings] of findingsByPath) {
      const file = filesByPath.get(filePath);
      const originalText = snapshots.get(filePath);
      if (!file || originalText === undefined) {
        skippedCount += findings.length;
        continue;
      }

      const currentText = await this.app.vault.cachedRead(file);
      if (currentText !== originalText) {
        new Notice(`SVLT: ${filePath} changed after scan; leaving it unchanged.`);
        skippedCount += findings.length;
        continue;
      }

      const updatedText = await this.encryptFindingsInText(originalText, findings);
      await this.app.vault.modify(file, updatedText);
      appliedCount += findings.length;
    }

    return { appliedCount, skippedCount };
  }

  private replacementSummary(appliedCount: number, skippedCount: number): string {
    const applied = `encrypted ${appliedCount} finding${appliedCount === 1 ? "" : "s"}`;
    if (skippedCount === 0) {
      return `SVLT: ${applied}.`;
    }
    return `SVLT: ${applied}; skipped ${skippedCount} changed finding${skippedCount === 1 ? "" : "s"}.`;
  }

  private async encryptFindingsInText(
    text: string,
    findings: ScanFindingState[]
  ): Promise<string> {
    const client = this.createVaultClient();
    const replacements: PlannedReplacement[] = [];

    for (const finding of findings) {
      const plaintext = finding.plaintextForCurrentProcessOnly ?? text.slice(finding.start, finding.end);
      const response = await client.request({
        type: "encryptText",
        plaintext,
        label: buildParagraphContextTemplate(text, {
          start: finding.start,
          end: finding.end,
          text: plaintext
        }),
        policy: "credential"
      });

      if (response.type !== "created") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }

      replacements.push({
        start: finding.start,
        end: finding.end,
        replacementText: response.reference
      });
      finding.plaintextForCurrentProcessOnly = undefined;
    }

    return applyReplacements(text, replacements);
  }
}

const SECRET_SCHEME = "secret://";
const SECRET_ID_LENGTH = 26;
const SECRET_REFERENCE_REGEX = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g;
const SECRET_TOKEN_CHARACTERS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/-".split(""));

function extractSecretReferences(text: string): string[] {
  return [...text.matchAll(SECRET_REFERENCE_REGEX)]
    .filter((match) => {
      const start = match.index ?? 0;
      const end = start + SECRET_SCHEME.length + SECRET_ID_LENGTH;
      return isReferenceBoundary(text, start - 1) && isReferenceBoundary(text, end);
    })
    .map((match) => match[0]);
}

function isReferenceBoundary(text: string, index: number): boolean {
  if (index < 0 || index >= text.length) {
    return true;
  }
  return !SECRET_TOKEN_CHARACTERS.has(text[index] ?? "");
}
