"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  commandDefinitions: () => commandDefinitions,
  default: () => AgentSecretVaultPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");

// src/editor/selection.ts
function extractCurrentParagraph(documentText, cursorOffset) {
  const before = documentText.lastIndexOf("\n\n", Math.max(0, cursorOffset - 1));
  const after = documentText.indexOf("\n\n", cursorOffset);
  const start = before === -1 ? 0 : before + 2;
  const end = after === -1 ? documentText.length : after;
  return { start, end, text: documentText.slice(start, end) };
}
function replaceRange(documentText, range, replacement) {
  return `${documentText.slice(0, range.start)}${replacement}${documentText.slice(range.end)}`;
}

// src/encrypt/encryptSelection.ts
async function encryptTextRange(input) {
  const response = await input.client.request({
    type: "encryptText",
    plaintext: input.range.text,
    label: input.label,
    policy: input.policy
  });
  if (response.type !== "created") {
    throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
  }
  return {
    updatedText: replaceRange(input.documentText, input.range, response.reference),
    reference: response.reference
  };
}

// src/pairing/pairing.ts
function interpretWorkbenchStatus(input) {
  if (!input.reachable) {
    return { canOperate: false, message: "Agent Secret Vault is unavailable." };
  }
  if (input.status.status.locked) {
    return { canOperate: false, message: "Unlock Agent Secret Vault to continue." };
  }
  if (!input.status.status.ipcAvailable) {
    return { canOperate: false, message: "Agent Secret Vault IPC is unavailable." };
  }
  return { canOperate: true, message: "Agent Secret Vault is ready." };
}

// src/ui/statusBar.ts
function updateStatusBar(element, state) {
  const connection = state.connected ? "connected" : "not connected";
  const lock = state.locked ? "locked" : "unlocked";
  element.textContent = `ASV: ${connection}, ${lock}`;
}

// src/main.ts
var DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;
var MAX_FRAME_BYTES = 1048576;
var SECRET_REFERENCE_PATTERN = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
function parseEncryptResponse(json) {
  const parsed = JSON.parse(json);
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
var RuntimeVaultClient = class {
  constructor(socketPath) {
    this.socketPath = socketPath;
  }
  socketPath;
  async request(request) {
    const nodeRequire = Function("return require")();
    const net = nodeRequire("node:net");
    const payload = Buffer.from(JSON.stringify(request), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);
    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = Buffer.alloc(0);
      let settled = false;
      const settle = (callback) => {
        if (settled) {
          return;
        }
        settled = true;
        callback();
        socket.destroy();
      };
      const rejectWith = (error) => {
        settle(() => reject(error instanceof Error ? error : new Error(String(error))));
      };
      const parseAvailableFrame = () => {
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
};
var commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
];
var AgentSecretVaultPlugin = class extends import_obsidian.Plugin {
  createVaultClient() {
    return new RuntimeVaultClient(DEFAULT_SOCKET_PATH);
  }
  async onload() {
    const pairing = interpretWorkbenchStatus({ reachable: false });
    const status = this.addStatusBarItem();
    updateStatusBar(status, { connected: pairing.canOperate, locked: !pairing.canOperate });
    for (const definition of commandDefinitions) {
      const command = {
        id: definition.id,
        name: definition.name,
        callback: () => {
          new import_obsidian.Notice(`Agent Secret Vault: ${definition.id} is not connected yet.`);
        }
      };
      if (definition.id === "encrypt-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.encryptSelection(editor);
          }
        });
      } else if (definition.id === "encrypt-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.encryptCurrentParagraph(editor);
          }
        });
      } else {
        this.addCommand(command);
      }
    }
  }
  async encryptSelection(editor) {
    const text = editor.getSelection();
    if (text.length === 0) {
      new import_obsidian.Notice("Agent Secret Vault: select text to encrypt.");
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
  async encryptCurrentParagraph(editor) {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new import_obsidian.Notice("Agent Secret Vault: current paragraph is empty.");
      return;
    }
    await this.encryptRange(editor, range);
  }
  async encryptRange(editor, range) {
    try {
      const result = await encryptTextRange({
        documentText: editor.getValue(),
        range,
        label: null,
        policy: "credential",
        client: this.createVaultClient()
      });
      editor.setValue(result.updatedText);
      new import_obsidian.Notice("Agent Secret Vault: encrypted text into a secret reference.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian.Notice(`Agent Secret Vault: encryption failed (${message}).`);
    }
  }
};
