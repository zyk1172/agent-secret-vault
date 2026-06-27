import { Notice, Plugin, type Editor } from "obsidian";
import { encryptTextRange } from "./encrypt/encryptSelection";
import { extractCurrentParagraph, type TextRange } from "./editor/selection";
import type { IpcRequest, IpcResponse } from "./ipc/protocol";
import { interpretWorkbenchStatus } from "./pairing/pairing";
import { updateStatusBar } from "./ui/statusBar";

const DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;
const MAX_FRAME_BYTES = 1_048_576;
const SECRET_REFERENCE_PATTERN = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;

function parseEncryptResponse(json: string): IpcResponse {
  const parsed = JSON.parse(json) as unknown;
  if (typeof parsed !== "object" || parsed === null || !("type" in parsed)) {
    throw new Error("Invalid IPC response.");
  }

  if (parsed.type === "created" && "reference" in parsed && typeof parsed.reference === "string") {
    if (!SECRET_REFERENCE_PATTERN.test(parsed.reference)) {
      throw new Error("Invalid secret reference.");
    }

    return { type: "created", reference: parsed.reference };
  }

  if (parsed.type === "failure" && "code" in parsed && typeof parsed.code === "string" && parsed.code.length > 0) {
    return { type: "failure", code: parsed.code };
  }

  throw new Error("Unexpected IPC response.");
}

class RuntimeVaultClient {
  constructor(private readonly socketPath: string) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    const nodeRequire = Function("return require")() as NodeRequire;
    const net = nodeRequire("node:net") as typeof import("node:net");
    const payload = Buffer.from(JSON.stringify(request), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = Buffer.alloc(0);
      let settled = false;

      const settle = (callback: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        callback();
        socket.destroy();
      };

      const rejectWith = (error: unknown): void => {
        settle(() => reject(error instanceof Error ? error : new Error(String(error))));
      };

      const parseAvailableFrame = (): void => {
        if (buffer.length < 4) {
          return;
        }

        const length = buffer.readUInt32BE(0);
        if (length > MAX_FRAME_BYTES) {
          rejectWith(new Error("IPC frame exceeds maximum size."));
          return;
        }

        const frameLength = 4 + length;
        if (buffer.length < frameLength) {
          return;
        }

        try {
          const json = buffer.subarray(4, frameLength).toString("utf8");
          const response = parseEncryptResponse(json);
          settle(() => resolve(response));
        } catch (error) {
          rejectWith(error);
        }
      };

      socket.on("connect", () => socket.write(frame));
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        parseAvailableFrame();
      });
      socket.on("error", rejectWith);
      socket.on("end", () => {
        if (!settled) {
          rejectWith(new Error("Incomplete IPC frame."));
        }
      });
    });
  }
}

export const commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
] as const;

export default class AgentSecretVaultPlugin extends Plugin {
  private createVaultClient(): RuntimeVaultClient {
    return new RuntimeVaultClient(DEFAULT_SOCKET_PATH);
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
    });
  }

  private async encryptCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new Notice("Agent Secret Vault: current paragraph is empty.");
      return;
    }

    await this.encryptRange(editor, range);
  }

  private async encryptRange(editor: Editor, range: TextRange): Promise<void> {
    try {
      const result = await encryptTextRange({
        documentText: editor.getValue(),
        range,
        label: null,
        policy: "credential",
        client: this.createVaultClient()
      });

      editor.setValue(result.updatedText);
      new Notice("Agent Secret Vault: encrypted text into a secret reference.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`Agent Secret Vault: encryption failed (${message}).`);
    }
  }
}
