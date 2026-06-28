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
var import_obsidian2 = require("obsidian");

// src/editor/selection.ts
function extractCurrentParagraph(documentText, cursorOffset) {
  const offset = Math.min(Math.max(cursorOffset, 0), documentText.length);
  const lines = [];
  let lineStart = 0;
  while (lineStart <= documentText.length) {
    const newline = documentText.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? documentText.length : newline;
    lines.push({
      start: lineStart,
      end: lineEnd,
      nextStart: newline === -1 ? documentText.length : newline + 1,
      blank: documentText.slice(lineStart, lineEnd).trim().length === 0
    });
    if (newline === -1) {
      break;
    }
    lineStart = newline + 1;
  }
  const currentLineIndex = Math.max(0, lines.findIndex((line, index) => {
    const nextLine = lines[index + 1];
    const lineLimit = nextLine ? nextLine.start : documentText.length + 1;
    return offset >= line.start && offset < lineLimit;
  }));
  const currentLine = lines[currentLineIndex];
  if (currentLine.blank) {
    return {
      start: currentLine.start,
      end: currentLine.end,
      text: documentText.slice(currentLine.start, currentLine.end)
    };
  }
  let previousBlank;
  for (let index = currentLineIndex - 1; index >= 0; index -= 1) {
    if (lines[index].blank) {
      previousBlank = lines[index];
      break;
    }
  }
  const nextBlank = lines.slice(currentLineIndex + 1).find((line) => line.blank);
  const start = previousBlank ? previousBlank.nextStart : 0;
  const end = nextBlank ? Math.max(start, nextBlank.start - 1) : documentText.length;
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

// src/ipc/client.ts
var MAX_FRAME_BYTES = 1048576;
var DEFAULT_REQUEST_TIMEOUT_MS = 1e4;
var SECRET_REFERENCE_PATTERN = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
async function loadRuntimeNet() {
  const runtimeRequire = Function("return typeof require === 'function' ? require : undefined")();
  if (runtimeRequire) {
    return runtimeRequire("node:net");
  }
  const runtimeImport = Function("specifier", "return import(specifier)");
  return await runtimeImport("node:net");
}
async function loadRuntimeFs() {
  const runtimeRequire = Function("return typeof require === 'function' ? require : undefined")();
  if (runtimeRequire) {
    return runtimeRequire("node:fs");
  }
  const runtimeImport = Function("specifier", "return import(specifier)");
  return await runtimeImport("node:fs");
}
function parseIpcResponse(json) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("Invalid IPC response.");
  }
  if (!isRecord(parsed) || typeof parsed.type !== "string") {
    throw new Error("Unexpected IPC response.");
  }
  if (parsed.type === "created" && isSecretReference(parsed.reference)) {
    return { type: "created", reference: parsed.reference };
  }
  if (parsed.type === "failure" && typeof parsed.code === "string" && parsed.code.length > 0) {
    return { type: "failure", code: parsed.code };
  }
  if (parsed.type === "revealSessionOpened" && typeof parsed.sessionID === "string" && parsed.sessionID.length > 0) {
    return { type: "revealSessionOpened", sessionID: parsed.sessionID };
  }
  if (parsed.type === "workbenchStatus" && isRecord(parsed.status)) {
    const status = parsed.status;
    if (typeof status.locked === "boolean" && typeof status.ipcAvailable === "boolean" && (typeof status.activeKnowledgeBaseRoot === "string" || status.activeKnowledgeBaseRoot === null) && typeof status.pluginConnected === "boolean") {
      return {
        type: "workbenchStatus",
        status: {
          locked: status.locked,
          ipcAvailable: status.ipcAvailable,
          activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
          pluginConnected: status.pluginConnected
        }
      };
    }
  }
  if (parsed.type === "orphanScan" && isRecord(parsed.result)) {
    const result = parsed.result;
    if (isSecretReferenceArray(result.missingRecords) && isSecretReferenceArray(result.unreferencedRecords)) {
      return {
        type: "orphanScan",
        result: {
          missingRecords: result.missingRecords,
          unreferencedRecords: result.unreferencedRecords
        }
      };
    }
  }
  throw new Error("Unexpected IPC response.");
}
function isRecord(value) {
  return typeof value === "object" && value !== null;
}
function isSecretReference(value) {
  return typeof value === "string" && SECRET_REFERENCE_PATTERN.test(value);
}
function isSecretReferenceArray(value) {
  return Array.isArray(value) && value.every(isSecretReference);
}
var LocalVaultClient = class {
  requestTimeoutMs;
  netModule;
  fsModule;
  tokenPath;
  constructor(socketPath, options = {}) {
    this.socketPath = socketPath;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.netModule = options.netModule;
    this.fsModule = options.fsModule;
    this.tokenPath = options.tokenPath ?? socketPath.replace(/agent-secret-vault\.sock$/, "capability.token");
  }
  socketPath;
  async request(request) {
    const net = this.netModule ?? await loadRuntimeNet();
    const fs = this.fsModule ?? await loadRuntimeFs();
    const authenticatedRequest = {
      capabilityToken: this.readCapabilityToken(fs),
      request
    };
    const payload = Buffer.from(JSON.stringify(authenticatedRequest), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);
    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = Buffer.alloc(0);
      let settled = false;
      const timeout = setTimeout(() => {
        rejectWith(new Error("IPC request timed out."));
      }, this.requestTimeoutMs);
      const settle = (callback) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
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
          const response = parseIpcResponse(json);
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
  readCapabilityToken(fs) {
    const tokenStat = fs.statSync(this.tokenPath);
    if ((tokenStat.mode & 63) !== 0) {
      throw new Error("IPC token permissions allow non-owner access.");
    }
    if (typeof process.getuid === "function" && tokenStat.uid !== process.getuid()) {
      throw new Error("IPC token owner does not match current user.");
    }
    return fs.readFileSync(this.tokenPath, "utf8").trim();
  }
};

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

// src/replace/transactionalReplace.ts
function compareFromEnd(left, right) {
  return right.start - left.start || right.end - left.end;
}
function validateReplacements(text, replacements) {
  const ascendingReplacements = [...replacements].sort((left, right) => left.start - right.start || left.end - right.end);
  for (const replacement of ascendingReplacements) {
    if (replacement.start < 0 || replacement.end < replacement.start || replacement.end > text.length) {
      throw new RangeError("Replacement range is outside the original text.");
    }
  }
  for (let index = 1; index < ascendingReplacements.length; index += 1) {
    if (ascendingReplacements[index].start < ascendingReplacements[index - 1].end) {
      throw new RangeError("Replacement ranges overlap.");
    }
  }
}
function applyReplacements(text, replacements) {
  validateReplacements(text, replacements);
  return [...replacements].sort(compareFromEnd).reduce(
    (updatedText, replacement) => `${updatedText.slice(0, replacement.start)}${replacement.replacementText}${updatedText.slice(replacement.end)}`,
    text
  );
}

// src/reveal/paragraphReveal.ts
var SECRET_SCHEME = "secret://";
var SECRET_ID_LENGTH = 26;
var ALLOWED_ID_CHARACTERS = new Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ".split(""));
var TOKEN_BOUNDARY_CHARACTERS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/.-".split(""));
function isBoundaryCharacter(text, index) {
  if (index < 0 || index >= text.length) {
    return true;
  }
  return !TOKEN_BOUNDARY_CHARACTERS.has(text[index] ?? "");
}
function extractReferenceMatches(paragraph) {
  const matches = [];
  let searchStart = 0;
  while (searchStart < paragraph.length) {
    const schemeStart = paragraph.indexOf(SECRET_SCHEME, searchStart);
    if (schemeStart === -1) {
      break;
    }
    searchStart = schemeStart + SECRET_SCHEME.length;
    if (!isBoundaryCharacter(paragraph, schemeStart - 1)) {
      continue;
    }
    const idStart = schemeStart + SECRET_SCHEME.length;
    const idEnd = idStart + SECRET_ID_LENGTH;
    if (idEnd > paragraph.length) {
      continue;
    }
    const id = paragraph.slice(idStart, idEnd);
    if (![...id].every((character) => ALLOWED_ID_CHARACTERS.has(character))) {
      continue;
    }
    if (!isBoundaryCharacter(paragraph, idEnd)) {
      continue;
    }
    matches.push({
      reference: `${SECRET_SCHEME}${id}`,
      start: schemeStart,
      end: idEnd
    });
  }
  return matches;
}
function placeholderNonce() {
  const randomUUID = globalThis.crypto?.randomUUID;
  if (typeof randomUUID === "function") {
    return randomUUID.call(globalThis.crypto).replace(/-/g, "");
  }
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}
function choosePlaceholder(index, paragraph, usedPlaceholders) {
  const legacyPlaceholder = `{{${index}}}`;
  if (!paragraph.includes(legacyPlaceholder) && !usedPlaceholders.has(legacyPlaceholder)) {
    return legacyPlaceholder;
  }
  while (true) {
    const candidate = `{{ASV_REVEAL_${index}_${placeholderNonce()}}}`;
    if (!paragraph.includes(candidate) && !usedPlaceholders.has(candidate)) {
      return candidate;
    }
  }
}
function buildParagraphRevealRequest(paragraph) {
  const matches = extractReferenceMatches(paragraph);
  if (matches.length === 0) {
    throw new Error("NO_SECRET_REFERENCES");
  }
  const references = [];
  const ranges = [];
  const usedPlaceholders = /* @__PURE__ */ new Set();
  let template = "";
  let lastEnd = 0;
  matches.forEach((match, referenceIndex) => {
    const placeholder = choosePlaceholder(referenceIndex, paragraph, usedPlaceholders);
    usedPlaceholders.add(placeholder);
    references.push(match.reference);
    ranges.push({ index: referenceIndex, placeholder });
    template += paragraph.slice(lastEnd, match.start);
    template += placeholder;
    lastEnd = match.end;
  });
  template += paragraph.slice(lastEnd);
  return {
    type: "revealReferences",
    references,
    context: {
      reason: "Reveal current paragraph",
      template,
      ranges
    }
  };
}

// src/scan/detectors.ts
function redactValue(value) {
  if (value.length <= 10) {
    return "********";
  }
  return `${value.slice(0, 8)}\u2026${value.slice(-4)}`;
}
function collectMatches(text, regex, ruleId, confidence) {
  const matches = [];
  for (const match of text.matchAll(regex)) {
    const value = match.slice(1).find((capture) => capture !== void 0) ?? match[0];
    const matchStart = match.index ?? 0;
    const valueOffset = match[0].indexOf(value);
    const start = matchStart + valueOffset;
    matches.push({
      start,
      end: start + value.length,
      value,
      ruleId,
      confidence
    });
  }
  return matches;
}
function detectSensitiveText(text) {
  const matches = [
    ...collectMatches(text, /sk-proj-[A-Za-z0-9_-]{20,}/g, "openai-api-key", "high"),
    ...collectMatches(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "private-key", "high"),
    ...collectMatches(text, /\bBearer\s+([A-Za-z0-9._~+/=-]{10,})/g, "bearer-token", "high"),
    ...collectMatches(text, /\b(?:password|passwd|pwd)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`]+))/gi, "password-assignment", "medium")
  ];
  return matches.sort((left, right) => left.start - right.start || left.end - right.end).map(({ start, end, ruleId, confidence, value }) => ({
    start,
    end,
    ruleId,
    confidence,
    redactedPreview: redactValue(value)
  }));
}

// src/scan/vaultScanner.ts
function hashMarkdown(text) {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `fnv1a32:${(hash >>> 0).toString(16).padStart(8, "0")}`;
}
function scanMarkdownFile(filePath, text) {
  const contentHash = hashMarkdown(text);
  return detectSensitiveText(text).map((finding) => ({
    ...finding,
    filePath,
    contentHash,
    plaintextForCurrentProcessOnly: text.slice(finding.start, finding.end)
  }));
}

// src/ui/reviewModal.ts
var import_obsidian = require("obsidian");
var ReviewModal = class extends import_obsidian.Modal {
  constructor(app, findings, applyFindings) {
    super(app);
    this.findings = findings;
    this.applyFindings = applyFindings;
  }
  findings;
  applyFindings;
  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Agent Secret Vault review queue" });
    if (this.findings.length === 0) {
      contentEl.createEl("p", { text: "No sensitive text findings in this scan." });
      return;
    }
    const list = contentEl.createEl("ul");
    const selected = new Set(this.findings);
    for (const finding of this.findings) {
      const item = list.createEl("li");
      const checkbox = item.createEl("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selected.add(finding);
        } else {
          selected.delete(finding);
        }
      });
      item.createEl("div", { text: finding.filePath });
      item.createEl("div", { text: `Rule: ${finding.ruleId}` });
      item.createEl("div", { text: `Confidence: ${finding.confidence}` });
      item.createEl("code", { text: finding.redactedPreview });
    }
    if (this.applyFindings) {
      const button = contentEl.createEl("button", { text: "Encrypt selected findings" });
      button.addEventListener("click", async () => {
        button.disabled = true;
        await this.applyFindings?.([...selected]);
        this.close();
      });
    }
  }
};

// src/ui/statusBar.ts
function updateStatusBar(element, state) {
  const connection = state.connected ? "connected" : "not connected";
  const lock = state.locked ? "locked" : "unlocked";
  element.textContent = `ASV: ${connection}, ${lock}`;
}

// src/main.ts
var DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;
function clonePosition(position) {
  return { line: position.line, ch: position.ch };
}
var commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
];
var AgentSecretVaultPlugin = class extends import_obsidian2.Plugin {
  createVaultClient() {
    return new LocalVaultClient(DEFAULT_SOCKET_PATH);
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
          new import_obsidian2.Notice(`Agent Secret Vault: ${definition.id} is not connected yet.`);
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
      } else if (definition.id === "reveal-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.revealCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "scan-current-note") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
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
      } else {
        this.addCommand(command);
      }
    }
  }
  async encryptSelection(editor) {
    const text = editor.getSelection();
    if (text.length === 0) {
      new import_obsidian2.Notice("Agent Secret Vault: select text to encrypt.");
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
  async encryptCurrentParagraph(editor) {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new import_obsidian2.Notice("Agent Secret Vault: current paragraph is empty.");
      return;
    }
    await this.encryptRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end));
  }
  async encryptRange(editor, range, fromPos, toPos) {
    try {
      const result = await encryptTextRange({
        documentText: editor.getValue(),
        range,
        label: null,
        policy: "credential",
        client: this.createVaultClient()
      });
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new import_obsidian2.Notice("Agent Secret Vault: note changed before encryption completed; leaving text unchanged.");
        return;
      }
      editor.replaceRange(result.reference, fromPos, toPos, "agent-secret-vault");
      new import_obsidian2.Notice("Agent Secret Vault: encrypted text into a secret reference.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`Agent Secret Vault: encryption failed (${message}).`);
    }
  }
  async revealCurrentParagraph(editor) {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    let request;
    try {
      request = buildParagraphRevealRequest(range.text);
    } catch {
      new import_obsidian2.Notice("Agent Secret Vault: current paragraph has no secret reference.");
      return;
    }
    try {
      const response = await this.createVaultClient().request(request);
      if (response.type !== "revealSessionOpened") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      new import_obsidian2.Notice("Agent Secret Vault: reveal session opened in the Mac app.");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`Agent Secret Vault: reveal failed (${message}).`);
    }
  }
  async scanCurrentNote(editor) {
    const originalText = editor.getValue();
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new import_obsidian2.Notice("Agent Secret Vault: note changed after scan; leaving text unchanged.");
          return;
        }
        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings);
        editor.setValue(updatedText);
        new import_obsidian2.Notice(`Agent Secret Vault: encrypted ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}.`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new import_obsidian2.Notice(`Agent Secret Vault: scan replacement failed (${message}).`);
      }
    }).open();
  }
  async scanVault() {
    const files = this.app.vault.getMarkdownFiles();
    const filesByPath = new Map(files.map((file) => [file.path, file]));
    const snapshots = /* @__PURE__ */ new Map();
    const allFindings = [];
    for (const file of files) {
      const text = await this.app.vault.cachedRead(file);
      snapshots.set(file.path, text);
      allFindings.push(...scanMarkdownFile(file.path, text));
    }
    new ReviewModal(this.app, allFindings, async (selectedFindings) => {
      try {
        await this.applyVaultFindings(selectedFindings, filesByPath, snapshots);
        new import_obsidian2.Notice(`Agent Secret Vault: encrypted ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}.`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new import_obsidian2.Notice(`Agent Secret Vault: scan replacement failed (${message}).`);
      }
    }).open();
  }
  async applyVaultFindings(selectedFindings, filesByPath, snapshots) {
    const findingsByPath = /* @__PURE__ */ new Map();
    for (const finding of selectedFindings) {
      const existing = findingsByPath.get(finding.filePath) ?? [];
      existing.push(finding);
      findingsByPath.set(finding.filePath, existing);
    }
    for (const [filePath, findings] of findingsByPath) {
      const file = filesByPath.get(filePath);
      const originalText = snapshots.get(filePath);
      if (!file || originalText === void 0) {
        continue;
      }
      const currentText = await this.app.vault.cachedRead(file);
      if (currentText !== originalText) {
        new import_obsidian2.Notice(`Agent Secret Vault: ${filePath} changed after scan; leaving it unchanged.`);
        continue;
      }
      const updatedText = await this.encryptFindingsInText(originalText, findings);
      await this.app.vault.modify(file, updatedText);
    }
  }
  async encryptFindingsInText(text, findings) {
    const client = this.createVaultClient();
    const replacements = [];
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
      finding.plaintextForCurrentProcessOnly = void 0;
    }
    return applyReplacements(text, replacements);
  }
};
