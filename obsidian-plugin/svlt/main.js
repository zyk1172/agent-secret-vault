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

// src/ipc/client.ts
var MAX_FRAME_BYTES = 1048576;
var DEFAULT_REQUEST_TIMEOUT_MS = 1e4;
var DEFAULT_UNAVAILABLE_RETRY_COUNT = 8;
var DEFAULT_UNAVAILABLE_RETRY_DELAY_MS = 500;
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
  if (parsed.type === "failure" && typeof parsed.code === "string" && parsed.code.length > 0) {
    return { type: "failure", code: parsed.code };
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
    const rawSHA256 = parsed.rawSHA256 === void 0 || parsed.rawSHA256 === null || typeof parsed.rawSHA256 === "string" ? parsed.rawSHA256 : void 0;
    const diagnostics = isCatalogValidationDiagnosticArray(parsed.diagnostics) ? parsed.diagnostics : [];
    return {
      type: "catalogValidation",
      catalogStatus: parsed.catalogStatus,
      ...parsed.revision === void 0 ? {} : { revision: parsed.revision },
      ...rawSHA256 === void 0 ? {} : { rawSHA256 },
      diagnostics
    };
  }
  throw new Error("Unexpected IPC response.");
}
function isRecord(value) {
  return typeof value === "object" && value !== null;
}
function isNonNegativeInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
function isCatalogValidationDiagnosticArray(value) {
  return Array.isArray(value) && value.every((item) => {
    if (!isRecord(item)) return false;
    return typeof item.id === "string" && (item.severity === "error" || item.severity === "warning") && typeof item.code === "string" && isPositiveInteger(item.line) && (item.column === void 0 || item.column === null || isPositiveInteger(item.column)) && (item.endLine === void 0 || item.endLine === null || isPositiveInteger(item.endLine)) && (item.endColumn === void 0 || item.endColumn === null || isPositiveInteger(item.endColumn)) && ["document", "policy", "index", "entry", "field", "unmanaged"].includes(String(item.scope)) && typeof item.message === "string" && (item.hint === void 0 || item.hint === null || typeof item.hint === "string");
  });
}
function isPositiveInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 1;
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

// src/ui/statusBar.ts
function updateStatusBar(element, state) {
  const connection = state.connected ? "connected" : "not connected";
  const lock = state.locked ? "locked" : "unlocked";
  element.textContent = `ASV: ${connection}, ${lock}`;
}

// src/main.ts
var DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;
var commandDefinitions = [
  { id: "validate-catalog", name: "\u9A8C\u8BC1 SVLT \u654F\u611F\u4FE1\u606F\u76EE\u5F55" },
  { id: "show-catalog-diagnostics", name: "\u67E5\u770B SVLT \u76EE\u5F55\u8BCA\u65AD" }
];
var AgentSecretVaultPlugin = class extends import_obsidian.Plugin {
  catalogValidationTimer;
  statusBar;
  latestDiagnostics = [];
  lastNoticeFingerprint;
  latestValidation;
  activeCatalogFile;
  createVaultClient() {
    return new LocalVaultClient(DEFAULT_SOCKET_PATH);
  }
  async onload() {
    const pairing = interpretWorkbenchStatus({ reachable: false });
    this.statusBar = this.addStatusBarItem();
    updateStatusBar(this.statusBar, { connected: pairing.canOperate, locked: !pairing.canOperate });
    this.addCommand({
      id: "validate-catalog",
      name: "\u9A8C\u8BC1 SVLT \u654F\u611F\u4FE1\u606F\u76EE\u5F55",
      callback: async () => {
        await this.validateManagedCatalog();
      }
    });
    this.addCommand({
      id: "show-catalog-diagnostics",
      name: "\u67E5\u770B SVLT \u76EE\u5F55\u8BCA\u65AD",
      callback: () => this.showCatalogDiagnostics()
    });
    await this.refreshStatus();
    this.registerJumpProtocol();
    this.registerCatalogWatcher();
    this.register(() => {
      if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
      this.catalogValidationTimer = void 0;
    });
  }
  registerCatalogWatcher() {
    const eventRef = this.app.vault.on("modify", (file) => {
      if (!(file instanceof Object) || !("extension" in file) || file.extension !== "md") return;
      void this.validateModifiedCatalog(file);
    });
    this.registerEvent(eventRef);
  }
  async validateModifiedCatalog(file) {
    try {
      const text = await this.app.vault.cachedRead(file);
      if (!classifyCatalogText(text).startsWith("managed")) return;
      this.activeCatalogFile = file;
      this.scheduleCatalogValidation();
    } catch {
    }
  }
  scheduleCatalogValidation() {
    if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
    this.catalogValidationTimer = setTimeout(() => {
      this.catalogValidationTimer = void 0;
      void this.validateManagedCatalog();
    }, 300);
  }
  registerJumpProtocol() {
    const registerProtocolHandler = this.registerObsidianProtocolHandler;
    if (typeof registerProtocolHandler !== "function") return;
    registerProtocolHandler.call(this, "svlt", async (params) => {
      const fullPath = typeof params.file === "string" ? params.file : "";
      const requestedLine = Number.parseInt(typeof params.line === "string" ? params.line : "1", 10);
      if (fullPath.length === 0 || !Number.isFinite(requestedLine) || requestedLine < 1) {
        new import_obsidian.Notice("SVLT\uFF1A\u672C\u5730\u8DF3\u8F6C\u8BF7\u6C42\u65E0\u6548\u3002");
        return;
      }
      const adapter = this.app.vault.adapter;
      const file = this.app.vault.getMarkdownFiles().find((candidate) => adapter.getFullPath?.(candidate.path) === fullPath);
      if (!file) {
        new import_obsidian.Notice("SVLT\uFF1A\u8BF7\u6C42\u7684\u6587\u4EF6\u4E0D\u5728\u5F53\u524D\u5E93\u4E2D\u3002");
        return;
      }
      const leaf = this.app.workspace.getLeaf(false);
      await leaf.openFile(file);
      if (leaf.view instanceof import_obsidian.MarkdownView) {
        const line = Math.max(0, requestedLine - 1);
        leaf.view.editor.setCursor({ line, ch: 0 });
        leaf.view.editor.scrollIntoView({ from: { line, ch: 0 }, to: { line, ch: 0 } }, true);
      }
    });
  }
  async refreshStatus() {
    if (!this.statusBar) return;
    try {
      const response = await this.createVaultClient().request({ type: "workbenchStatus" });
      if (response.type !== "workbenchStatus") throw new Error("UNEXPECTED_RESPONSE");
      const pairing = interpretWorkbenchStatus({ reachable: true, status: response });
      updateStatusBar(this.statusBar, {
        connected: pairing.canOperate && response.status.pluginConnected,
        locked: response.status.locked
      });
    } catch {
      updateStatusBar(this.statusBar, { connected: false, locked: true });
    }
  }
  async validateManagedCatalog() {
    try {
      const response = await this.createVaultClient().request({ type: "catalogValidate" });
      if (response.type !== "catalogValidation") {
        this.publishValidationFailure(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
        return;
      }
      this.latestDiagnostics = response.diagnostics ?? [];
      this.latestValidation = {
        status: response.catalogStatus,
        rawSHA256: response.rawSHA256,
        fingerprint: validationFingerprint(response)
      };
      this.updateDiagnosticStatusBar();
      if (response.catalogStatus === "FOUND") {
        return;
      }
      const noticeFingerprint = validationFingerprint(response);
      if (this.lastNoticeFingerprint === noticeFingerprint) return;
      this.lastNoticeFingerprint = noticeFingerprint;
      this.publishDiagnosticsNotice(response);
    } catch {
      this.publishValidationFailure("APP_UNAVAILABLE");
    }
  }
  publishDiagnosticsNotice(response) {
    const diagnostics = response.diagnostics ?? [];
    const first = response.diagnostics?.[0];
    const location = first ? `\u7B2C ${first.line} \u884C${first.column ? `\u3001\u7B2C ${first.column} \u5217` : ""}` : "\u672A\u63D0\u4F9B\u4F4D\u7F6E";
    const count = diagnostics.length > 0 ? `${diagnostics.length} \u4E2A\u683C\u5F0F\u95EE\u9898` : `\u76EE\u5F55\u72B6\u6001 ${response.catalogStatus}`;
    new import_obsidian.Notice(`SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u6709 ${count}\uFF0C\u7B2C\u4E00\u4E2A\u4F4D\u4E8E ${location}\u3002`);
  }
  publishValidationFailure(code) {
    const fingerprint = `failure:${code}`;
    if (this.lastNoticeFingerprint === fingerprint) return;
    this.lastNoticeFingerprint = fingerprint;
    this.latestValidation = { status: "CATALOG_UNAVAILABLE", fingerprint };
    this.latestDiagnostics = [];
    this.updateDiagnosticStatusBar();
    new import_obsidian.Notice(`SVLT\uFF1A\u654F\u611F\u4FE1\u606F\u76EE\u5F55\u9A8C\u8BC1\u5931\u8D25\uFF08${code}\uFF09\u3002`);
  }
  showCatalogDiagnostics() {
    const diagnostics = this.latestDiagnostics;
    if (diagnostics.length === 0) {
      new import_obsidian.Notice("SVLT\uFF1A\u5F53\u524D\u6CA1\u6709\u76EE\u5F55\u8BCA\u65AD\uFF1B\u53EF\u5148\u8FD0\u884C\u201C\u9A8C\u8BC1 SVLT \u654F\u611F\u4FE1\u606F\u76EE\u5F55\u201D\u3002");
      return;
    }
    new CatalogDiagnosticsModal(this.app, diagnostics, (diagnostic) => {
      void this.jumpToDiagnostic(diagnostic);
    }).open();
  }
  async jumpToDiagnostic(diagnostic) {
    const file = this.activeCatalogFile ?? this.app.workspace.getActiveFile();
    if (!file) {
      new import_obsidian.Notice("SVLT\uFF1A\u65E0\u6CD5\u5B9A\u4F4D\u5F53\u524D\u76EE\u5F55\u6587\u4EF6\u3002");
      return;
    }
    const leaf = this.app.workspace.getLeaf(false);
    await leaf.openFile(file);
    if (leaf.view instanceof import_obsidian.MarkdownView) {
      const line = Math.max(0, diagnostic.line - 1);
      leaf.view.editor.setCursor({ line, ch: diagnostic.column != null ? Math.max(0, diagnostic.column - 1) : 0 });
      leaf.view.editor.scrollIntoView(
        { from: { line, ch: 0 }, to: { line, ch: leaf.view.editor.getLine(line).length } },
        true
      );
    }
  }
  updateDiagnosticStatusBar() {
    if (!this.statusBar) return;
    const issueCount = this.latestDiagnostics.length;
    const baseText = (this.statusBar.textContent ?? "").replace(/ · \d+ 个问题$/, "");
    this.statusBar.textContent = issueCount === 0 ? baseText : `${baseText} \xB7 ${issueCount} \u4E2A\u95EE\u9898`;
    this.statusBar.setAttribute(
      "aria-label",
      issueCount === 0 ? "SVLT \u76EE\u5F55\u6821\u9A8C\u901A\u8FC7\u6216\u6682\u65E0\u8BCA\u65AD" : `SVLT \u76EE\u5F55\u6709 ${issueCount} \u6761\u8BCA\u65AD`
    );
  }
};
function validationFingerprint(response) {
  const diagnostics = (response.diagnostics ?? []).map((diagnostic) => [
    diagnostic.id,
    diagnostic.severity,
    diagnostic.code,
    diagnostic.line,
    diagnostic.column ?? "",
    diagnostic.endLine ?? "",
    diagnostic.endColumn ?? "",
    diagnostic.scope,
    diagnostic.message,
    diagnostic.hint ?? ""
  ].join("|")).sort().join(";");
  return [response.catalogStatus, response.rawSHA256 ?? "", diagnostics].join("::");
}
var CatalogDiagnosticsModal = class extends import_obsidian.Modal {
  constructor(app, diagnostics, jumpHandler) {
    super(app);
    this.diagnostics = diagnostics;
    this.jumpHandler = jumpHandler;
  }
  diagnostics;
  jumpHandler;
  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h3", { text: "SVLT \u683C\u5F0F\u68C0\u67E5" });
    const subtitle = contentEl.createDiv({ text: "\u8BCA\u65AD\u53EA\u5305\u542B\u9519\u8BEF\u7C7B\u578B\u548C\u4F4D\u7F6E\uFF0C\u4E0D\u5305\u542B\u76EE\u5F55\u6B63\u6587\u3001\u8DEF\u5F84\u6216\u654F\u611F\u5F15\u7528\u3002" });
    subtitle.addClass("svlt-diagnostics-subtitle");
    const list = contentEl.createDiv({ cls: "svlt-diagnostics-list" });
    for (const diagnostic of this.diagnostics) {
      const row = list.createDiv({ cls: "svlt-diagnostic-row" });
      const severity = row.createSpan({ cls: "svlt-diagnostic-severity" });
      severity.textContent = diagnostic.severity === "error" ? "\u{1F534}" : "\u{1F7E0}";
      const location = row.createSpan({ cls: "svlt-diagnostic-location" });
      location.textContent = `\u7B2C ${diagnostic.line} \u884C${diagnostic.column ? `\u3001\u7B2C ${diagnostic.column} \u5217` : ""}`;
      const code = row.createSpan({ cls: "svlt-diagnostic-code" });
      code.textContent = diagnostic.code;
      const message = row.createSpan({ cls: "svlt-diagnostic-message" });
      message.textContent = diagnostic.message;
      if (diagnostic.hint) {
        const hint = row.createDiv({ cls: "svlt-diagnostic-hint" });
        hint.textContent = `\u5EFA\u8BAE\uFF1A${diagnostic.hint}`;
      }
      const jump = row.createEl("button", { text: "\u8DF3\u8F6C" });
      jump.addClass("svlt-diagnostic-jump");
      jump.addEventListener("click", () => this.jumpHandler(diagnostic));
    }
  }
  onClose() {
    this.contentEl.empty();
  }
};
