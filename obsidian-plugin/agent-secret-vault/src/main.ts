import { Notice, Plugin, type Editor, type EditorPosition, type TFile } from "obsidian";
import { encryptTextRange } from "./encrypt/encryptSelection";
import { extractCurrentParagraph, type TextRange } from "./editor/selection";
import { LocalVaultClient } from "./ipc/client";
import type { IpcRequest } from "./ipc/protocol";
import { interpretWorkbenchStatus } from "./pairing/pairing";
import { applyReplacements, type PlannedReplacement } from "./replace/transactionalReplace";
import { buildParagraphRevealRequest } from "./reveal/paragraphReveal";
import type { ScanFindingState } from "./scan/scanState";
import { scanMarkdownFile } from "./scan/vaultScanner";
import { ReviewModal } from "./ui/reviewModal";
import { updateStatusBar } from "./ui/statusBar";

const DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;

function clonePosition(position: EditorPosition): EditorPosition {
  return { line: position.line, ch: position.ch };
}

export const commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "scan-orphans", name: "Scan vault for orphaned secret references" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
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
      } else if (definition.id === "encrypt-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.encryptCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "reveal-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.revealCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "scan-current-note") {
        this.addCommand({
          ...command,
          editorCallback: async (editor: Editor) => {
            await this.scanCurrentNote(editor);
          }
        });
      } else if (definition.id === "scan-vault") {
        this.addCommand({
          ...command,
          callback: async () => {
            await this.scanVault();
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
      new Notice("Agent Secret Vault: select text to encrypt.");
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
      new Notice("Agent Secret Vault: current paragraph is empty.");
      return;
    }

    await this.encryptRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end));
  }

  private async encryptRange(
    editor: Editor,
    range: TextRange,
    fromPos: EditorPosition,
    toPos: EditorPosition
  ): Promise<void> {
    try {
      const result = await encryptTextRange({
        documentText: editor.getValue(),
        range,
        label: null,
        policy: "credential",
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
    let request: IpcRequest;

    try {
      request = buildParagraphRevealRequest(range.text);
    } catch {
      new Notice("Agent Secret Vault: current paragraph has no secret reference.");
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

  private async scanCurrentNote(editor: Editor): Promise<void> {
    const originalText = editor.getValue();
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new Notice("Agent Secret Vault: note changed after scan; leaving text unchanged.");
          return;
        }

        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings);
        editor.setValue(updatedText);
        new Notice(`Agent Secret Vault: encrypted ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}.`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`Agent Secret Vault: scan replacement failed (${message}).`);
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
        new Notice(`Agent Secret Vault: ${filePath} changed after scan; leaving it unchanged.`);
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
      return `Agent Secret Vault: ${applied}.`;
    }
    return `Agent Secret Vault: ${applied}; skipped ${skippedCount} changed finding${skippedCount === 1 ? "" : "s"}.`;
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
        label: `${finding.filePath}:${finding.ruleId}`,
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
