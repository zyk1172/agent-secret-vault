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

// src/scan/detectors.ts
var existingSecretReferencePattern = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
var existingSecretReferenceTailPattern = /^\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
var trailingReferencePunctuationPattern = /[.,，。；;:：)）\]}】>]+$/u;
function redactValue(value) {
  if (value.length <= 10) {
    return "********";
  }
  return `${value.slice(0, 8)}\u2026${value.slice(-4)}`;
}
function isExistingSecretReference(value) {
  const normalizedValue = value.replace(trailingReferencePunctuationPattern, "");
  return existingSecretReferencePattern.test(normalizedValue) || existingSecretReferenceTailPattern.test(normalizedValue);
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
var rulePriority = {
  "private-key": 0,
  "openai-api-key": 1,
  "github-token": 2,
  "jwt": 3,
  "bearer-token": 4,
  "url-secret-parameter": 5,
  "generic-secret-assignment": 6,
  "chinese-secret-assignment": 7,
  "password-assignment": 8,
  "china-id-card": 9,
  "bank-card": 10,
  "phone-number": 11,
  "email-address": 12
};
function confidencePriority(confidence) {
  return confidence === "high" ? 0 : 1;
}
function overlaps(left, right) {
  return left.start < right.end && right.start < left.end;
}
function compareFindingPriority(left, right) {
  return confidencePriority(left.confidence) - confidencePriority(right.confidence) || right.end - right.start - (left.end - left.start) || rulePriority[left.ruleId] - rulePriority[right.ruleId] || left.start - right.start || left.end - right.end;
}
function suppressOverlaps(matches) {
  const accepted = [];
  for (const candidate of [...matches].sort(compareFindingPriority)) {
    if (!accepted.some((finding) => overlaps(finding, candidate))) {
      accepted.push(candidate);
    }
  }
  return accepted.sort((left, right) => left.start - right.start || left.end - right.end);
}
function detectSensitiveText(text) {
  const matches = [
    ...collectMatches(text, /sk-proj-[A-Za-z0-9_-]{20,}/g, "openai-api-key", "high"),
    ...collectMatches(text, /gh[pousr]_[A-Za-z0-9_]{20,}/g, "github-token", "high"),
    ...collectMatches(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "private-key", "high"),
    ...collectMatches(text, /\bBearer\s+([A-Za-z0-9._~+/=-]{10,})/g, "bearer-token", "high"),
    ...collectMatches(text, /\b(?:password|passwd|pwd)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`]+))/gi, "password-assignment", "medium"),
    ...collectMatches(text, /(?:密码|口令|令牌|密钥|秘钥|访问密钥|api\s*key|API\s*Key|token|secret)\s*[:：=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`，。；;]+))/gi, "chinese-secret-assignment", "medium"),
    ...collectMatches(text, /\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|refresh[_-]?token|token|secret)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([A-Za-z0-9._~+/=-]{10,}))/gi, "generic-secret-assignment", "medium"),
    ...collectMatches(text, /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})\b/g, "jwt", "high"),
    ...collectMatches(text, /[?&](?:token|access_token|refresh_token|api_key|apikey|key|secret|client_secret)=([A-Za-z0-9._~+/=-]{10,})/gi, "url-secret-parameter", "high"),
    ...collectMatches(text, /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, "email-address", "medium"),
    ...collectMatches(text, /(?<!\d)(1[3-9]\d{9})(?!\d)/g, "phone-number", "medium"),
    ...collectMatches(text, /(?<!\d)([1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx])(?![0-9Xx])/g, "china-id-card", "medium"),
    ...collectMatches(text, /(?<!\d)([1-9]\d{15,18})(?!\d)/g, "bank-card", "medium")
  ];
  return suppressOverlaps(matches.filter(({ value }) => !isExistingSecretReference(value))).map(({ start, end, ruleId, confidence, value }) => ({
    start,
    end,
    ruleId,
    confidence,
    redactedPreview: redactValue(value)
  }));
}

// src/encrypt/paragraphContextTemplate.ts
var PARAGRAPH_REFERENCE_MARKER = "[[ASV_REFERENCE]]";
function buildParagraphContextTemplate(documentText, target) {
  const paragraph = extractCurrentParagraph(documentText, target.start);
  const targetStart = Math.max(0, target.start - paragraph.start);
  const targetEnd = Math.min(paragraph.text.length, Math.max(targetStart, target.end - paragraph.start));
  const replacements = [{
    start: targetStart,
    end: targetEnd,
    replacementText: PARAGRAPH_REFERENCE_MARKER
  }];
  for (const finding of detectSensitiveText(paragraph.text)) {
    if (finding.end <= targetStart || finding.start >= targetEnd) {
      replacements.push({ start: finding.start, end: finding.end, replacementText: "\u5DF2\u9690\u85CF" });
      continue;
    }
    if (finding.start < targetStart) {
      replacements.push({ start: finding.start, end: targetStart, replacementText: "\u5DF2\u9690\u85CF" });
    }
    if (targetEnd < finding.end) {
      replacements.push({ start: targetEnd, end: finding.end, replacementText: "\u5DF2\u9690\u85CF" });
    }
  }
  return applyReplacements(paragraph.text, replacements);
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
  const replacementText = formatMarkdownReference(input.referenceTitle, response.reference);
  return { updatedText: replaceRange(input.documentText, input.range, replacementText), reference: response.reference, replacementText };
}
function inferReferenceTitle(documentText, range) {
  const lineStart = documentText.lastIndexOf("\n", Math.max(0, range.start - 1)) + 1;
  const prefix = documentText.slice(lineStart, range.start).replace(/[：:=]\s*$/u, "").replace(/[*_`#>-]/gu, "").trim();
  return prefix.length > 0 ? prefix.slice(-48) : "\u654F\u611F\u4FE1\u606F";
}
function formatMarkdownReference(title, reference) {
  const safeTitle = title.replace(/[\[\]\r\n]/gu, " ").trim() || "\u654F\u611F\u4FE1\u606F";
  return `[${safeTitle}](${reference})`;
}

// src/ipc/client.ts
var MAX_FRAME_BYTES = 1048576;
var DEFAULT_REQUEST_TIMEOUT_MS = 1e4;
var DEFAULT_UNAVAILABLE_RETRY_COUNT = 8;
var DEFAULT_UNAVAILABLE_RETRY_DELAY_MS = 500;
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
  if (parsed.type === "restoredText" && typeof parsed.text === "string") {
    return { type: "restoredText", text: parsed.text };
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
  if (parsed.type === "catalogValidation" && typeof parsed.catalogStatus === "string" && [
    "FOUND",
    "NOT_FOUND",
    "INVALID_QUERY",
    "CATALOG_UNAVAILABLE",
    "LEGACY_CATALOG_UNSUPPORTED",
    "INTEGRITY_MISSING",
    "EXTERNAL_CATALOG_MODIFICATION",
    "PENDING_EXTERNAL_CHANGE",
    "CATALOG_INVALID"
  ].includes(parsed.catalogStatus) && (parsed.revision === void 0 || parsed.revision === null || isNonNegativeInteger(parsed.revision))) {
    const filePreflight = isCatalogFilePreflight(parsed.filePreflight) ? parsed.filePreflight : void 0;
    return {
      type: "catalogValidation",
      catalogStatus: parsed.catalogStatus,
      ...parsed.revision === void 0 ? {} : { revision: parsed.revision },
      ...filePreflight === void 0 ? {} : { filePreflight }
    };
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
function isNonNegativeInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
function isCatalogFilePreflight(value) {
  if (!isRecord(value)) {
    return false;
  }
  return ["read", "parentTempCreate", "parentTempFsync", "parentRename", "parentFsync"].every((key) => typeof value[key] === "string" && value[key].length <= 128);
}
var LocalVaultClient = class {
  requestTimeoutMs;
  netModule;
  fsModule;
  tokenPath;
  unavailableRetryCount;
  unavailableRetryDelayMs;
  constructor(socketPath, options = {}) {
    this.socketPath = socketPath;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.unavailableRetryCount = options.unavailableRetryCount ?? DEFAULT_UNAVAILABLE_RETRY_COUNT;
    this.unavailableRetryDelayMs = options.unavailableRetryDelayMs ?? DEFAULT_UNAVAILABLE_RETRY_DELAY_MS;
    this.netModule = options.netModule;
    this.fsModule = options.fsModule;
    this.tokenPath = options.tokenPath ?? socketPath.replace(/agent-secret-vault\.sock$/, "capability.token");
  }
  socketPath;
  async request(request) {
    for (let attempt = 0; attempt <= this.unavailableRetryCount; attempt += 1) {
      try {
        return await this.requestOnce(request);
      } catch (error) {
        if (!isUnavailableError(error) || attempt >= this.unavailableRetryCount) {
          if (isUnavailableError(error)) {
            return { type: "failure", code: "APP_UNAVAILABLE" };
          }
          throw error;
        }
        await delay(this.unavailableRetryDelayMs);
      }
    }
    return { type: "failure", code: "APP_UNAVAILABLE" };
  }
  async requestOnce(request) {
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
function isUnavailableError(error) {
  if (!(error instanceof Error)) {
    return false;
  }
  const code = error.code;
  return code === "ENOENT" || code === "ECONNREFUSED" || code === "ENOTSOCK" || code === "EACCES";
}
function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// src/catalog/managedCatalog.ts
var MANAGED_CATALOG_V3_MARKER = '<!-- SVLT-CATALOG schema="3" -->';
var MANAGED_CATALOG_V2_MARKER = '<!-- SVLT-MANAGED-CATALOG schema="2" -->';
var LEGACY_CATALOG_MARKER = "agent-secret-vault-sensitive-information: 1";
function classifyCatalogText(text) {
  const normalized = text.replace(/\r\n?/g, "\n");
  if (normalized.startsWith(MANAGED_CATALOG_V3_MARKER)) return "managedV3";
  if (normalized.startsWith(MANAGED_CATALOG_V2_MARKER)) return "managedV2";
  if (normalized.includes(LEGACY_CATALOG_MARKER)) return "legacy";
  return "unmanaged";
}
function isManagedCatalogText(text) {
  return classifyCatalogText(text) !== "unmanaged";
}

// src/pairing/pairing.ts
function interpretWorkbenchStatus(input) {
  if (!input.reachable) {
    return { canOperate: false, message: "SVLT \u670D\u52A1\u4E0D\u53EF\u7528\u3002" };
  }
  if (input.status.status.locked) {
    return { canOperate: false, message: "\u8BF7\u5148\u89E3\u9501 SVLT\u3002" };
  }
  if (!input.status.status.ipcAvailable) {
    return { canOperate: false, message: "SVLT \u672C\u673A\u901A\u9053\u4E0D\u53EF\u7528\u3002" };
  }
  return { canOperate: true, message: "SVLT \u5DF2\u5C31\u7EEA\u3002" };
}

// src/reveal/paragraphReveal.ts
var SECRET_SCHEME = "secret://";
var SECRET_ID_LENGTH = 26;
var ALLOWED_ID_CHARACTERS = new Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ".split(""));
var TOKEN_BOUNDARY_CHARACTERS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/-".split(""));
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
  const request = buildReferenceResolutionRequest(paragraph);
  return {
    ...request,
    type: "revealReferences"
  };
}
function buildParagraphRestoreRequest(paragraph) {
  const request = buildReferenceResolutionRequest(paragraph);
  return {
    ...request,
    type: "restoreReferences"
  };
}
function buildReferenceResolutionRequest(paragraph) {
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
    plaintextForCurrentProcessOnly: text.slice(finding.start, finding.end),
    sourceExcerptForCurrentProcessOnly: sourceExcerpt(text, finding.start, finding.end)
  }));
}
function sourceExcerpt(text, start, end) {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const nextLineBreak = text.indexOf("\n", end);
  const lineEnd = nextLineBreak === -1 ? text.length : nextLineBreak;
  const line = text.slice(lineStart, lineEnd);
  if (line.length <= 240) return line;
  const matchStart = start - lineStart;
  const excerptStart = Math.max(0, Math.min(matchStart - 100, line.length - 240));
  const excerptEnd = Math.min(line.length, excerptStart + 240);
  return `${excerptStart > 0 ? "..." : ""}${line.slice(excerptStart, excerptEnd)}${excerptEnd < line.length ? "..." : ""}`;
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
    contentEl.createEl("h2", { text: "\u654F\u611F\u4FE1\u606F\u626B\u63CF\u7ED3\u679C" });
    if (this.findings.length === 0) {
      contentEl.createEl("p", { text: "\u6CA1\u6709\u53D1\u73B0\u53EF\u81EA\u52A8\u8BC6\u522B\u7684\u654F\u611F\u4FE1\u606F\u3002" });
      contentEl.createEl("p", { text: "\u5F53\u524D\u4F1A\u626B\u63CF\u5BC6\u7801\u3001\u4EE4\u724C\u3001API Key\u3001\u79C1\u94A5\u3001JWT\u3001URL \u5BC6\u94A5\u53C2\u6570\u3001\u90AE\u7BB1\u3001\u624B\u673A\u53F7\u3001\u8EAB\u4EFD\u8BC1\u3001\u94F6\u884C\u5361\u7B49\u5E38\u89C1\u6A21\u5F0F\u3002\u4ECD\u7136\u53EF\u4EE5\u624B\u52A8\u9009\u4E2D\u6587\u5B57\u540E\u4F7F\u7528\u201C\u52A0\u5BC6\u9009\u4E2D\u6587\u672C\u201D\u3002" });
      return;
    }
    const fileCount = new Set(this.findings.map((finding) => finding.filePath)).size;
    contentEl.createEl("p", { text: `\u547D\u4E2D ${this.findings.length} \u9879\uFF0C\u6D89\u53CA ${fileCount} \u4E2A\u6587\u4EF6\u3002\u8BF7\u52FE\u9009\u8981\u52A0\u5BC6\u7684\u9879\u76EE\u3002` });
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
      item.createEl("div", { text: `\u6587\u4EF6\uFF1A${finding.filePath}` });
      item.createEl("div", { text: `\u89C4\u5219\uFF1A${finding.ruleId}` });
      item.createEl("div", { text: `\u7F6E\u4FE1\u5EA6\uFF1A${finding.confidence}` });
      item.createEl("div", { text: `\u547D\u4E2D\u5185\u5BB9\uFF1A${finding.plaintextForCurrentProcessOnly ?? finding.redactedPreview}` });
      item.createEl("div", { text: `\u6240\u5728\u5185\u5BB9\uFF1A${finding.sourceExcerptForCurrentProcessOnly ?? finding.redactedPreview}` });
    }
    if (this.applyFindings) {
      const button = contentEl.createEl("button", { text: "\u52A0\u5BC6\u9009\u4E2D\u9879" });
      button.addEventListener("click", async () => {
        button.disabled = true;
        await this.applyFindings?.([...selected]);
        this.close();
      });
    }
  }
  onClose() {
    for (const finding of this.findings) {
      finding.plaintextForCurrentProcessOnly = void 0;
      finding.sourceExcerptForCurrentProcessOnly = void 0;
    }
    this.findings = [];
    this.contentEl.empty();
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
function isLegacyManagedCatalogText(text) {
  const format = classifyCatalogText(text);
  return format === "legacy" || format === "managedV2";
}
var commandDefinitions = [
  { id: "encrypt-selection", name: "\u52A0\u5BC6\u9009\u4E2D\u6587\u672C" },
  { id: "reveal-selection", name: "\u5728 SVLT \u4E2D\u4E34\u65F6\u89E3\u5BC6\u9009\u4E2D\u6587\u672C" },
  { id: "reveal-current-paragraph", name: "\u5728 SVLT \u4E2D\u4E34\u65F6\u89E3\u5BC6\u5F53\u524D\u6BB5\u843D" },
  { id: "restore-selection", name: "\u8FD8\u539F\u9009\u4E2D\u6587\u672C\u4E2D\u7684\u5BC6\u6587\u5F15\u7528" },
  { id: "restore-current-paragraph", name: "\u8FD8\u539F\u5F53\u524D\u6BB5\u843D\u4E2D\u7684\u5BC6\u6587\u5F15\u7528" },
  { id: "validate-catalog", name: "\u9A8C\u8BC1 SVLT \u654F\u611F\u4FE1\u606F\u76EE\u5F55" }
];
var AgentSecretVaultPlugin = class extends import_obsidian2.Plugin {
  catalogValidationTimer;
  createVaultClient() {
    return new LocalVaultClient(DEFAULT_SOCKET_PATH);
  }
  async onload() {
    const pairing = interpretWorkbenchStatus({ reachable: false });
    const status = this.addStatusBarItem();
    updateStatusBar(status, { connected: pairing.canOperate, locked: !pairing.canOperate });
    await this.refreshStatus(status);
    for (const definition of commandDefinitions) {
      const command = {
        id: definition.id,
        name: definition.name,
        callback: () => {
          new import_obsidian2.Notice(`SVLT\uFF1A${definition.name} \u6682\u4E0D\u53EF\u7528\uFF0C\u8BF7\u5148\u8FDE\u63A5\u672C\u673A\u670D\u52A1\u3002`);
        }
      };
      if (definition.id === "encrypt-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.encryptSelection(editor);
          }
        });
      } else if (definition.id === "reveal-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.revealCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "reveal-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.revealSelection(editor);
          }
        });
      } else if (definition.id === "restore-selection") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.restoreSelection(editor);
          }
        });
      } else if (definition.id === "restore-current-paragraph") {
        this.addCommand({
          ...command,
          editorCallback: async (editor) => {
            await this.restoreCurrentParagraph(editor);
          }
        });
      } else if (definition.id === "validate-catalog") {
        this.addCommand({
          ...command,
          callback: async () => {
            await this.validateManagedCatalog();
          }
        });
      } else {
        this.addCommand(command);
      }
    }
    this.registerEditorMenu();
    this.registerJumpProtocol();
    this.registerCatalogWatcher();
  }
  registerCatalogWatcher() {
    const vault = this.app?.vault;
    if (typeof vault?.on !== "function" || typeof vault.cachedRead !== "function") return;
    const eventRef = vault.on("modify", (file) => {
      void (async () => {
        const text = await vault.cachedRead?.(file);
        if (text === void 0 || classifyCatalogText(text) !== "managedV3") return;
        this.scheduleCatalogValidation();
      })();
    });
    this.registerEvent(eventRef);
    const registerCleanup = this.register;
    registerCleanup?.call(this, () => {
      if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
      this.catalogValidationTimer = void 0;
    });
  }
  scheduleCatalogValidation() {
    if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
    this.catalogValidationTimer = setTimeout(() => {
      this.catalogValidationTimer = void 0;
      void this.validateManagedCatalog(true);
    }, 300);
  }
  registerJumpProtocol() {
    const registerProtocolHandler = this.registerObsidianProtocolHandler;
    if (typeof registerProtocolHandler !== "function") {
      return;
    }
    registerProtocolHandler.call(this, "svlt", async (params) => {
      const fullPath = typeof params.file === "string" ? params.file : "";
      const requestedLine = Number.parseInt(typeof params.line === "string" ? params.line : "1", 10);
      if (fullPath.length === 0 || !Number.isFinite(requestedLine) || requestedLine < 1) {
        new import_obsidian2.Notice("SVLT\uFF1A\u672C\u5730\u8DF3\u8F6C\u8BF7\u6C42\u65E0\u6548\u3002");
        return;
      }
      const adapter = this.app.vault.adapter;
      const file = this.app.vault.getMarkdownFiles().find((candidate) => adapter.getFullPath?.(candidate.path) === fullPath);
      if (!file) {
        new import_obsidian2.Notice("SVLT\uFF1A\u8BF7\u6C42\u7684\u6587\u4EF6\u4E0D\u5728\u5F53\u524D\u5E93\u4E2D\u3002");
        return;
      }
      const leaf = this.app.workspace.getLeaf(false);
      await leaf.openFile(file);
      if (leaf.view instanceof import_obsidian2.MarkdownView) {
        const line = Math.max(0, requestedLine - 1);
        leaf.view.editor.setCursor({ line, ch: 0 });
        leaf.view.editor.scrollIntoView({ from: { line, ch: 0 }, to: { line, ch: 0 } }, true);
      }
    });
  }
  registerEditorMenu() {
    this.registerEvent(this.app.workspace.on("editor-menu", (menu, editor) => {
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
  tryCreateSubmenu(item) {
    const maybeItem = item;
    if (typeof maybeItem.setSubmenu !== "function") {
      return null;
    }
    return maybeItem.setSubmenu();
  }
  showEditorActionMenu(event, editor) {
    const actionMenu = new import_obsidian2.Menu();
    actionMenu.setUseNativeMenu(false);
    this.populateEditorActionMenu(actionMenu, editor);
    if ("clientX" in event && "clientY" in event) {
      actionMenu.showAtMouseEvent(event);
      return;
    }
    actionMenu.showAtPosition({ x: 0, y: 0 });
  }
  populateEditorActionMenu(menu, editor) {
    menu.addItem((item) => {
      item.setTitle("\u52A0\u5BC6\u9009\u4E2D\u6587\u672C").setIcon("lock").onClick(async () => {
        await this.encryptSelection(editor);
      });
    });
    menu.addSeparator();
    menu.addItem((item) => {
      item.setTitle("\u4E34\u65F6\u89E3\u5BC6\u9009\u4E2D\u6587\u672C").setIcon("eye").onClick(async () => {
        await this.revealSelection(editor);
      });
    });
    menu.addItem((item) => {
      item.setTitle("\u8FD8\u539F\u9009\u4E2D\u6587\u672C").setIcon("rotate-ccw").onClick(async () => {
        await this.restoreSelection(editor);
      });
    });
  }
  async refreshStatus(status) {
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
  async validateManagedCatalog(silentWhenAccepted = false) {
    try {
      const response = await this.createVaultClient().request({ type: "catalogValidate" });
      if (response.type === "catalogValidation") {
        if (response.catalogStatus === "FOUND") {
          if (!silentWhenAccepted) new import_obsidian2.Notice("SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u9A8C\u8BC1\u901A\u8FC7\u3002");
        } else if (response.catalogStatus === "PENDING_EXTERNAL_CHANGE") {
          new import_obsidian2.Notice("SVLT\uFF1A\u76EE\u5F55\u6709\u5F85\u5BA1\u6279\u7684\u9AD8\u98CE\u9669\u5916\u90E8\u4FEE\u6539\uFF0C\u8BF7\u5728 SVLT App \u4E2D\u6279\u51C6\u3002");
        } else {
          new import_obsidian2.Notice(`SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u9A8C\u8BC1\u5931\u8D25\uFF08${response.catalogStatus}\uFF09\u3002`);
        }
        return;
      }
      new import_obsidian2.Notice(`SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u9A8C\u8BC1\u5931\u8D25\uFF08${response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE"}\uFF09\u3002`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u9A8C\u8BC1\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async refuseManagedCatalogMutation(documentText) {
    const format = classifyCatalogText(documentText);
    if (format === "unmanaged" || format === "managedV3") {
      if (format === "managedV3") await this.validateManagedCatalog(true);
      return false;
    }
    await this.validateManagedCatalog();
    new import_obsidian2.Notice("SVLT\uFF1Av2 \u6216\u65E7\u7248\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u8BF7\u5148\u5728 SVLT App \u4E2D\u5347\u7EA7\uFF1BObsidian \u4E0D\u4F1A\u76F4\u63A5\u6539\u5199\u65E7\u7ED3\u6784\u3002");
    return true;
  }
  async refuseManagedCatalogEncryption(documentText) {
    if (classifyCatalogText(documentText) === "managedV3") {
      await this.validateManagedCatalog(true);
      new import_obsidian2.Notice("SVLT\uFF1Av3 \u654F\u611F\u4FE1\u606F\u76EE\u5F55\u4E2D\u7684\u666E\u901A\u5B57\u6BB5\u4E0D\u80FD\u76F4\u63A5\u52A0\u5BC6\uFF1B\u8BF7\u5148\u5728 SVLT App \u4E2D\u628A\u5B57\u6BB5\u8BBE\u4E3A\u5BC6\u7801\u5B57\u6BB5\u3002\u624B\u5DE5 Markdown \u7F16\u8F91\u4ECD\u7136\u53EF\u7528\u3002");
      return true;
    }
    return this.refuseManagedCatalogMutation(documentText);
  }
  async refuseManagedCatalogRestore(documentText) {
    if (classifyCatalogText(documentText) === "managedV3") {
      await this.validateManagedCatalog(true);
      new import_obsidian2.Notice("SVLT\uFF1Av3 \u654F\u611F\u4FE1\u606F\u76EE\u5F55\u7981\u6B62\u5728 Obsidian \u4E2D\u8FD8\u539F secret://\uFF1B\u660E\u6587\u53EA\u53EF\u5728 SVLT App \u5B89\u5168\u7A97\u53E3\u4E2D\u4E34\u65F6\u67E5\u770B\u3002");
      return true;
    }
    return this.refuseManagedCatalogMutation(documentText);
  }
  async encryptSelection(editor) {
    if (isManagedCatalogText(editor.getValue()) && await this.refuseManagedCatalogEncryption(editor.getValue())) {
      return;
    }
    const text = editor.getSelection();
    if (text.length === 0) {
      new import_obsidian2.Notice("SVLT\uFF1A\u8BF7\u5148\u9009\u62E9\u8981\u52A0\u5BC6\u7684\u6587\u672C\u3002");
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
    if (isManagedCatalogText(documentText) && await this.refuseManagedCatalogEncryption(documentText)) {
      return;
    }
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new import_obsidian2.Notice("SVLT\uFF1A\u5F53\u524D\u6BB5\u843D\u4E3A\u7A7A\u3002");
      return;
    }
    const findings = scanMarkdownFile(this.app.workspace?.getActiveFile()?.path ?? "current-paragraph.md", range.text);
    if (findings.length === 0) {
      new import_obsidian2.Notice("SVLT\uFF1A\u5F53\u524D\u6BB5\u843D\u672A\u68C0\u6D4B\u5230\u654F\u611F\u6587\u672C\uFF1B\u8BF7\u624B\u52A8\u9009\u62E9\u51C6\u786E\u5185\u5BB9\u540E\u52A0\u5BC6\u3002");
      return;
    }
    try {
      const updatedText = await this.encryptFindingsInText(range.text, findings);
      const fromPos = editor.offsetToPos(range.start);
      const toPos = editor.offsetToPos(range.end);
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new import_obsidian2.Notice("SVLT\uFF1A\u52A0\u5BC6\u5B8C\u6210\u524D\u7B14\u8BB0\u5DF2\u53D8\u5316\uFF0C\u672A\u5199\u5165\u4FEE\u6539\u3002");
        return;
      }
      editor.replaceRange(updatedText, fromPos, toPos, "svlt");
      new import_obsidian2.Notice(`SVLT\uFF1A\u5F53\u524D\u6BB5\u843D\u5DF2\u52A0\u5BC6 ${findings.length} \u5904\u654F\u611F\u5185\u5BB9\u3002`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u6BB5\u843D\u52A0\u5BC6\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async encryptRange(editor, range, fromPos, toPos) {
    try {
      const documentText = editor.getValue();
      if (isManagedCatalogText(documentText) && await this.refuseManagedCatalogEncryption(documentText)) {
        return;
      }
      const result = await encryptTextRange({
        documentText,
        range,
        label: buildParagraphContextTemplate(documentText, range),
        referenceTitle: inferReferenceTitle(documentText, range),
        policy: "credential",
        client: this.createVaultClient()
      });
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new import_obsidian2.Notice("SVLT\uFF1A\u52A0\u5BC6\u5B8C\u6210\u524D\u7B14\u8BB0\u5DF2\u53D8\u5316\uFF0C\u672A\u5199\u5165\u4FEE\u6539\u3002");
        return;
      }
      editor.replaceRange(result.replacementText, fromPos, toPos, "svlt");
      new import_obsidian2.Notice("SVLT\uFF1A\u6587\u672C\u5DF2\u8F6C\u6362\u4E3A\u52A0\u5BC6\u5F15\u7528\u3002");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u52A0\u5BC6\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async revealCurrentParagraph(editor) {
    const documentText = editor.getValue();
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.revealText(range.text, "SVLT: current paragraph has no secret reference.");
  }
  async revealSelection(editor) {
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new import_obsidian2.Notice("SVLT\uFF1A\u8BF7\u9009\u62E9\u5305\u542B\u52A0\u5BC6\u5F15\u7528\u7684\u6587\u672C\u540E\u67E5\u770B\u3002");
      return;
    }
    await this.revealText(text, "SVLT: selected text has no secret reference.");
  }
  async revealText(text, noReferenceMessage) {
    let request;
    try {
      request = buildParagraphRevealRequest(text);
    } catch {
      new import_obsidian2.Notice(noReferenceMessage);
      return;
    }
    try {
      const response = await this.createVaultClient().request(request);
      if (response.type !== "revealSessionOpened") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      new import_obsidian2.Notice("SVLT\uFF1A\u5DF2\u5728 SVLT App \u4E2D\u6253\u5F00\u4E34\u65F6\u67E5\u770B\u4F1A\u8BDD\u3002");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u4E34\u65F6\u67E5\u770B\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async restoreCurrentParagraph(editor) {
    const documentText = editor.getValue();
    if (isManagedCatalogText(documentText) && await this.refuseManagedCatalogRestore(documentText)) {
      return;
    }
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.restoreRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end), "SVLT: current paragraph has no secret reference.");
  }
  async restoreSelection(editor) {
    if (isManagedCatalogText(editor.getValue()) && await this.refuseManagedCatalogRestore(editor.getValue())) {
      return;
    }
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new import_obsidian2.Notice("SVLT\uFF1A\u8BF7\u9009\u62E9\u5305\u542B\u52A0\u5BC6\u5F15\u7528\u7684\u6587\u672C\u540E\u8FD8\u539F\u3002");
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
  async restoreRange(editor, range, fromPos, toPos, noReferenceMessage) {
    let request;
    try {
      request = buildParagraphRestoreRequest(range.text);
    } catch {
      new import_obsidian2.Notice(noReferenceMessage);
      return;
    }
    try {
      const response = await this.createVaultClient().request(request);
      if (response.type !== "restoredText") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new import_obsidian2.Notice("SVLT\uFF1A\u8FD8\u539F\u5B8C\u6210\u524D\u7B14\u8BB0\u5DF2\u53D8\u5316\uFF0C\u672A\u5199\u5165\u4FEE\u6539\u3002");
        return;
      }
      editor.replaceRange(response.text, fromPos, toPos, "svlt-restore");
      new import_obsidian2.Notice("SVLT\uFF1A\u5DF2\u5C06\u52A0\u5BC6\u5F15\u7528\u8FD8\u539F\u4E3A\u660E\u6587\u3002");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u8FD8\u539F\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async scanCurrentNote(editor) {
    const originalText = editor.getValue();
    if (isManagedCatalogText(originalText) && await this.refuseManagedCatalogEncryption(originalText)) {
      return;
    }
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new import_obsidian2.Notice("SVLT\uFF1A\u626B\u63CF\u540E\u7B14\u8BB0\u5DF2\u53D8\u5316\uFF0C\u672A\u5199\u5165\u4FEE\u6539\u3002");
          return;
        }
        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings);
        editor.setValue(updatedText);
        new import_obsidian2.Notice(`SVLT\uFF1A\u5DF2\u52A0\u5BC6 ${selectedFindings.length} \u5904\u654F\u611F\u5185\u5BB9\u3002`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new import_obsidian2.Notice(`SVLT\uFF1A\u626B\u63CF\u7ED3\u679C\u5199\u56DE\u5931\u8D25\uFF08${message}\uFF09\u3002`);
      }
    }).open();
  }
  async scanVault() {
    const files = this.app.vault.getMarkdownFiles();
    const filesByPath = new Map(files.map((file) => [file.path, file]));
    const snapshots = /* @__PURE__ */ new Map();
    const allFindings = [];
    let skippedManagedCatalog = false;
    for (const file of files) {
      const text = await this.app.vault.cachedRead(file);
      snapshots.set(file.path, text);
      if (isManagedCatalogText(text)) {
        skippedManagedCatalog = true;
        continue;
      }
      allFindings.push(...scanMarkdownFile(file.path, text));
    }
    if (skippedManagedCatalog) {
      await this.validateManagedCatalog();
      new import_obsidian2.Notice("SVLT\uFF1A\u5DF2\u8DF3\u8FC7\u53D7\u7BA1\u654F\u611F\u4FE1\u606F.md\uFF1B\u5BC6\u7801\u5B57\u6BB5\u8BF7\u5728 SVLT App \u4E2D\u7BA1\u7406\uFF0C\u666E\u901A Markdown \u4ECD\u53EF\u624B\u5DE5\u7F16\u8F91\u3002");
    }
    new ReviewModal(this.app, allFindings, async (selectedFindings) => {
      try {
        const result = await this.applyVaultFindings(selectedFindings, filesByPath, snapshots);
        new import_obsidian2.Notice(this.replacementSummary(result.appliedCount, result.skippedCount));
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new import_obsidian2.Notice(`SVLT\uFF1A\u626B\u63CF\u7ED3\u679C\u5199\u56DE\u5931\u8D25\uFF08${message}\uFF09\u3002`);
      }
    }).open();
  }
  async scanOrphans() {
    const references = /* @__PURE__ */ new Set();
    let skippedManagedCatalog = false;
    for (const file of this.app.vault.getMarkdownFiles()) {
      const text = await this.app.vault.cachedRead(file);
      if (isLegacyManagedCatalogText(text)) {
        skippedManagedCatalog = true;
        continue;
      }
      for (const reference of extractSecretReferences(text)) {
        references.add(reference);
      }
    }
    if (skippedManagedCatalog) {
      await this.validateManagedCatalog();
      new import_obsidian2.Notice("SVLT\uFF1A\u5DF2\u8DF3\u8FC7\u65E7\u7248\u654F\u611F\u4FE1\u606F.md\uFF1B\u5347\u7EA7\u4E3A v3 \u540E\u53EF\u7531 Obsidian \u6B63\u5E38\u7F16\u8F91\u3002");
    }
    try {
      const response = await this.createVaultClient().request({
        type: "scanOrphans",
        markdownReferences: [...references].sort()
      });
      if (response.type !== "orphanScan") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      new import_obsidian2.Notice("SVLT\uFF1A\u5B64\u7ACB\u5F15\u7528\u626B\u63CF\u8BF7\u6C42\u5DF2\u53D1\u9001\u5230 SVLT App\u3002");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new import_obsidian2.Notice(`SVLT\uFF1A\u5B64\u7ACB\u5F15\u7528\u626B\u63CF\u5931\u8D25\uFF08${message}\uFF09\u3002`);
    }
  }
  async applyVaultFindings(selectedFindings, filesByPath, snapshots) {
    const findingsByPath = /* @__PURE__ */ new Map();
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
      if (!file || originalText === void 0) {
        skippedCount += findings.length;
        continue;
      }
      if (isManagedCatalogText(originalText)) {
        await this.validateManagedCatalog();
        new import_obsidian2.Notice("SVLT\uFF1A\u5DF2\u8DF3\u8FC7\u53D7\u7BA1\u654F\u611F\u4FE1\u606F.md\uFF0C\u672A\u901A\u8FC7\u666E\u901A\u52A0\u5BC6\u547D\u4EE4\u5199\u5165\u76EE\u5F55\uFF1B\u8BF7\u5728 SVLT App \u4E2D\u7BA1\u7406\u5BC6\u7801\u5B57\u6BB5\u3002");
        skippedCount += findings.length;
        continue;
      }
      const currentText = await this.app.vault.cachedRead(file);
      if (currentText !== originalText) {
        new import_obsidian2.Notice(`SVLT\uFF1A\u626B\u63CF\u540E\u6587\u4EF6 ${filePath} \u5DF2\u53D8\u5316\uFF0C\u672A\u5199\u5165\u4FEE\u6539\u3002`);
        skippedCount += findings.length;
        continue;
      }
      const updatedText = await this.encryptFindingsInText(originalText, findings);
      await this.app.vault.modify(file, updatedText);
      appliedCount += findings.length;
    }
    return { appliedCount, skippedCount };
  }
  replacementSummary(appliedCount, skippedCount) {
    const applied = `\u5DF2\u52A0\u5BC6 ${appliedCount} \u5904\u654F\u611F\u5185\u5BB9`;
    if (skippedCount === 0) {
      return `SVLT\uFF1A${applied}\u3002`;
    }
    return `SVLT\uFF1A${applied}\uFF1B\u6709 ${skippedCount} \u5904\u6587\u4EF6\u5DF2\u53D8\u5316\uFF0C\u5DF2\u8DF3\u8FC7\u3002`;
  }
  async encryptFindingsInText(text, findings) {
    const client = this.createVaultClient();
    const replacements = [];
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
      finding.plaintextForCurrentProcessOnly = void 0;
    }
    return applyReplacements(text, replacements);
  }
};
var SECRET_SCHEME2 = "secret://";
var SECRET_ID_LENGTH2 = 26;
var SECRET_REFERENCE_REGEX = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g;
var SECRET_TOKEN_CHARACTERS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/-".split(""));
function extractSecretReferences(text) {
  return [...text.matchAll(SECRET_REFERENCE_REGEX)].filter((match) => {
    const start = match.index ?? 0;
    const end = start + SECRET_SCHEME2.length + SECRET_ID_LENGTH2;
    return isReferenceBoundary(text, start - 1) && isReferenceBoundary(text, end);
  }).map((match) => match[0]);
}
function isReferenceBoundary(text, index) {
  if (index < 0 || index >= text.length) {
    return true;
  }
  return !SECRET_TOKEN_CHARACTERS.has(text[index] ?? "");
}
