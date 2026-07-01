import { Menu, Notice, Plugin, type Editor, type EditorPosition, type TFile } from "obsidian";
import { encryptTextRange } from "./encrypt/encryptSelection";
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
type SecretPolicyName = "credential" | "externalSend" | "read";

function clonePosition(position: EditorPosition): EditorPosition {
  return { line: position.line, ch: position.ch };
}

export const commandDefinitions = [
  { id: "encrypt-selection", name: "加密选中文本" },
  { id: "encrypt-selection-low-protection", name: "低保护加密选中文本" },
  { id: "encrypt-current-paragraph", name: "加密当前段落敏感信息" },
  { id: "encrypt-current-paragraph-low-protection", name: "低保护加密当前段落敏感信息" },
  { id: "scan-current-note", name: "扫描当前笔记中的敏感信息" },
  { id: "scan-current-note-low-protection", name: "低保护扫描当前笔记中的敏感信息" },
  { id: "scan-vault", name: "扫描整个知识库中的敏感信息" },
  { id: "scan-vault-low-protection", name: "低保护扫描整个知识库中的敏感信息" },
  { id: "scan-orphans", name: "扫描孤立密文引用" },
  { id: "reveal-selection", name: "在 Agent Secret Vault 中临时解密选中文本" },
  { id: "reveal-current-paragraph", name: "在 Agent Secret Vault 中临时解密当前段落" },
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
          new Notice(`Agent Secret Vault: ${definition.id} is not connected yet.`);
        }
      };

      if (definition.id === "encrypt-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptSelection(editor);
          }
        });
      } else if (definition.id === "encrypt-selection-low-protection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptSelection(editor, "read");
          }
        });
      } else if (definition.id === "encrypt-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "encrypt-current-paragraph-low-protection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptCurrentParagraph(editor, "read");
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
      } else if (definition.id === "scan-current-note") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.scanCurrentNote(editor);
          }
        });
      } else if (definition.id === "scan-current-note-low-protection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.scanCurrentNote(editor, "read");
          }
        });
      } else if (definition.id === "scan-vault") {
        this.addCommand({
          ...command,
          callback: async () => {
            await this.scanVault();
          }
        });
      } else if (definition.id === "scan-vault-low-protection") {
        this.addCommand({
          ...command,
          callback: async () => {
            await this.scanVault("read");
          }
        });
      } else if (definition.id === "scan-orphans") {
        this.addCommand({
          ...command,
          callback: async () => {
            await this.scanOrphans();
          }
        });
      } else {
        this.addCommand(command);
      }
    }

    this.registerEditorMenu();
  }

  private registerEditorMenu(): void {
    this.registerEvent(this.app.workspace.on("editor-menu", (menu: Menu, editor: Editor) => {
      let hasNativeSubmenu = false;
      menu.addItem((item) => {
        item.setTitle("Agent Secret Vault").setIcon("shield-check");
        const submenu = this.tryCreateSubmenu(item);
        if (submenu) {
          hasNativeSubmenu = true;
          this.populateEditorActionMenu(submenu, editor);
          return;
        }

        item.setTitle("Agent Secret Vault：加密选中文本").setIcon("lock").onClick(async () => {
          await this.encryptSelection(editor);
        });
      });

      if (!hasNativeSubmenu) {
        menu.addItem((item) => item.setTitle("Agent Secret Vault：加密当前段落敏感信息").setIcon("lock-keyhole").onClick(async () => {
          await this.encryptCurrentParagraph(editor);
        }));
        menu.addItem((item) => item.setTitle("Agent Secret Vault：低保护加密当前段落").setIcon("shield").onClick(async () => {
          await this.encryptCurrentParagraph(editor, "read");
        }));
        menu.addItem((item) => item.setTitle("Agent Secret Vault：临时解密当前段落").setIcon("eye").onClick(async () => {
          await this.revealCurrentParagraph(editor);
        }));
        menu.addItem((item) => item.setTitle("Agent Secret Vault：还原当前段落").setIcon("rotate-ccw").onClick(async () => {
          await this.restoreCurrentParagraph(editor);
        }));
      }
    }));
  }

  private tryCreateSubmenu(item: unknown): Menu | null {
    const maybeItem = item as { setSubmenu?: () => Menu };
    if (typeof maybeItem.setSubmenu !== "function") {
      return null;
    }
    return maybeItem.setSubmenu();
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

    menu.addItem((item) => {
      item
        .setTitle("低保护加密选中文本")
        .setIcon("shield")
        .onClick(async () => {
          await this.encryptSelection(editor, "read");
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("加密当前段落敏感信息")
        .setIcon("lock-keyhole")
        .onClick(async () => {
          await this.encryptCurrentParagraph(editor);
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("低保护加密当前段落敏感信息")
        .setIcon("shield")
        .onClick(async () => {
          await this.encryptCurrentParagraph(editor, "read");
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("扫描当前笔记并加密")
        .setIcon("scan-search")
        .onClick(async () => {
          await this.scanCurrentNote(editor);
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("低保护扫描当前笔记并加密")
        .setIcon("shield")
        .onClick(async () => {
          await this.scanCurrentNote(editor, "read");
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
        .setTitle("临时解密当前段落")
        .setIcon("eye")
        .onClick(async () => {
          await this.revealCurrentParagraph(editor);
        });
    });

    menu.addSeparator();

    menu.addItem((item) => {
      item
        .setTitle("还原选中文本")
        .setIcon("rotate-ccw")
        .onClick(async () => {
          await this.restoreSelection(editor);
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("还原当前段落")
        .setIcon("rotate-ccw")
        .onClick(async () => {
          await this.restoreCurrentParagraph(editor);
        });
    });

    menu.addSeparator();

    menu.addItem((item) => {
      item
        .setTitle("扫描整个知识库")
        .setIcon("folder-search")
        .onClick(async () => {
          await this.scanVault();
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("低保护扫描整个知识库")
        .setIcon("shield")
        .onClick(async () => {
          await this.scanVault("read");
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("扫描孤立密文引用")
        .setIcon("unlink")
        .onClick(async () => {
          await this.scanOrphans();
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

  private async encryptSelection(editor: Editor, policy: SecretPolicyName = "credential"): Promise<void> {
    const text = editor.getSelection();
    if (text.length === 0) {
      new Notice("Agent Secret Vault: select text to encrypt.");
      return;
    }

    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    await this.encryptRange(editor, {
      start: editor.posToOffset(from),
      end: editor.posToOffset(to),
      text
    }, clonePosition(from), clonePosition(to), policy);
  }

  private async encryptCurrentParagraph(editor: Editor, policy: SecretPolicyName = "credential"): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new Notice("Agent Secret Vault: current paragraph is empty.");
      return;
    }

    const findings = scanMarkdownFile(this.app.workspace?.getActiveFile()?.path ?? "current-paragraph.md", range.text);
    if (findings.length === 0) {
      new Notice("Agent Secret Vault: current paragraph has no detected sensitive text; select exact text to encrypt manually.");
      return;
    }

    try {
      const updatedText = await this.encryptFindingsInText(range.text, findings, policy);
      const fromPos = editor.offsetToPos(range.start);
      const toPos = editor.offsetToPos(range.end);
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("Agent Secret Vault: note changed before encryption completed; leaving text unchanged.");
        return;
      }
      editor.replaceRange(updatedText, fromPos, toPos, "agent-secret-vault");
      new Notice(`Agent Secret Vault: encrypted ${findings.length} sensitive finding${findings.length === 1 ? "" : "s"} in current paragraph.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: paragraph encryption failed (${message}).`);
    }
  }

  private async encryptRange(
    editor: Editor,
    range: TextRange,
    fromPos: EditorPosition,
    toPos: EditorPosition,
    policy: SecretPolicyName = "credential"
  ): Promise<void> {
    try {
      const result = await encryptTextRange({
        documentText: editor.getValue(),
        range,
        label: null,
        policy,
        client: this.createVaultClient()
      });

      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("Agent Secret Vault: note changed before encryption completed; leaving text unchanged.");
        return;
      }

      editor.replaceRange(result.reference, fromPos, toPos, "agent-secret-vault");
      new Notice("Agent Secret Vault: encrypted text into a secret reference.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: encryption failed (${message}).`);
    }
  }

  private async revealCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.revealText(range.text, "Agent Secret Vault: current paragraph has no secret reference.");
  }

  private async revealSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new Notice("Agent Secret Vault: select text containing a secret reference to reveal.");
      return;
    }

    await this.revealText(text, "Agent Secret Vault: selected text has no secret reference.");
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

      new Notice("Agent Secret Vault: reveal session opened in the Mac app.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: reveal failed (${message}).`);
    }
  }

  private async restoreCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.restoreRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end), "Agent Secret Vault: current paragraph has no secret reference.");
  }

  private async restoreSelection(editor: Editor): Promise<void> {
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new Notice("Agent Secret Vault: select text containing a secret reference to restore.");
      return;
    }
    const from = editor.getCursor("from");
    const to = editor.getCursor("to");
    await this.restoreRange(editor, {
      start: editor.posToOffset(from),
      end: editor.posToOffset(to),
      text
    }, clonePosition(from), clonePosition(to), "Agent Secret Vault: selected text has no secret reference.");
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
        new Notice("Agent Secret Vault: note changed before restore completed; leaving text unchanged.");
        return;
      }
      editor.replaceRange(response.text, fromPos, toPos, "agent-secret-vault-restore");
      new Notice("Agent Secret Vault: restored secret references into plaintext.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: restore failed (${message}).`);
    }
  }

  private async scanCurrentNote(editor: Editor, policy: SecretPolicyName = "credential"): Promise<void> {
    const originalText = editor.getValue();
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new Notice("Agent Secret Vault: note changed after scan; leaving text unchanged.");
          return;
        }

        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings, policy);
        editor.setValue(updatedText);
        new Notice(`Agent Secret Vault: encrypted ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}.`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`Agent Secret Vault: scan replacement failed (${message}).`);
      }
    }).open();
  }

  private async scanVault(policy: SecretPolicyName = "credential"): Promise<void> {
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
        const result = await this.applyVaultFindings(selectedFindings, filesByPath, snapshots, policy);
        new Notice(this.replacementSummary(result.appliedCount, result.skippedCount));
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`Agent Secret Vault: scan replacement failed (${message}).`);
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
      new Notice("Agent Secret Vault: orphan scan sent to the Mac app.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: orphan scan failed (${message}).`);
    }
  }

  private async applyVaultFindings(
    selectedFindings: ScanFindingState[],
    filesByPath: Map<string, TFile>,
    snapshots: Map<string, string>,
    policy: SecretPolicyName = "credential"
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
        new Notice(`Agent Secret Vault: ${filePath} changed after scan; leaving it unchanged.`);
        skippedCount += findings.length;
        continue;
      }

      const updatedText = await this.encryptFindingsInText(originalText, findings, policy);
      await this.app.vault.modify(file, updatedText);
      appliedCount += findings.length;
    }

    return { appliedCount, skippedCount };
  }

  private replacementSummary(appliedCount: number, skippedCount: number): string {
    const applied = `encrypted ${appliedCount} finding${appliedCount === 1 ? "" : "s"}`;
    if (skippedCount === 0) {
      return `Agent Secret Vault: ${applied}.`;
    }
    return `Agent Secret Vault: ${applied}; skipped ${skippedCount} changed finding${skippedCount === 1 ? "" : "s"}.`;
  }

  private async encryptFindingsInText(
    text: string,
    findings: ScanFindingState[],
    policy: SecretPolicyName = "credential"
  ): Promise<string> {
    const client = this.createVaultClient();
    const replacements: PlannedReplacement[] = [];

    for (const finding of findings) {
      const plaintext = finding.plaintextForCurrentProcessOnly ?? text.slice(finding.start, finding.end);
      const response = await client.request({
        type: "encryptText",
        plaintext,
        label: `${finding.filePath}:${finding.ruleId}`,
        policy
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
