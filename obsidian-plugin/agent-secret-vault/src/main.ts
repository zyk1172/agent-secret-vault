import { Notice, Plugin, type Editor, type EditorPosition } from "obsidian";
import { encryptTextRange } from "./encrypt/encryptSelection";
import { extractCurrentParagraph, type TextRange } from "./editor/selection";
import { LocalVaultClient } from "./ipc/client";
import type { IpcRequest } from "./ipc/protocol";
import { interpretWorkbenchStatus } from "./pairing/pairing";
import { buildParagraphRevealRequest } from "./reveal/paragraphReveal";
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
      } else {
        this.addCommand(command);
      }
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
}
