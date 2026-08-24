import { MarkdownView, Menu, Notice, Plugin, type Editor, type EditorPosition, type EventRef, type TFile } from "obsidian";
import { buildParagraphContextTemplate } from "./encrypt/paragraphContextTemplate";
import { encryptTextRange, inferReferenceTitle } from "./encrypt/encryptSelection";
import { extractCurrentParagraph, type TextRange } from "./editor/selection";
import { LocalVaultClient } from "./ipc/client";
import type { IpcRequest } from "./ipc/protocol";
import { classifyCatalogText, isManagedCatalogText } from "./catalog/managedCatalog";
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

function isLegacyManagedCatalogText(text: string): boolean {
  const format = classifyCatalogText(text);
  return format === "legacy" || format === "managedV2";
}

export const commandDefinitions = [
  { id: "encrypt-selection", name: "加密选中文本" },
  { id: "reveal-selection", name: "在 SVLT 中临时解密选中文本" },
  { id: "reveal-current-paragraph", name: "在 SVLT 中临时解密当前段落" },
  { id: "restore-selection", name: "还原选中文本中的密文引用" },
  { id: "restore-current-paragraph", name: "还原当前段落中的密文引用" },
  { id: "validate-catalog", name: "验证 SVLT 敏感信息目录" }
] as const;

export default class AgentSecretVaultPlugin extends Plugin {
  private catalogValidationTimer: ReturnType<typeof setTimeout> | undefined;

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
          new Notice(`SVLT：${definition.name} 暂不可用，请先连接本机服务。`);
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

  private registerCatalogWatcher(): void {
    const vault = this.app?.vault as unknown as {
      on?: (event: string, callback: (file: { path?: string; name?: string }) => void) => unknown;
      cachedRead?: (file: unknown) => Promise<string>;
    } | undefined;
    if (typeof vault?.on !== "function" || typeof vault.cachedRead !== "function") return;

    const eventRef = vault.on("modify", (file) => {
      void (async () => {
        const text = await vault.cachedRead?.(file);
        if (text === undefined || classifyCatalogText(text) !== "managedV3") return;
        this.scheduleCatalogValidation();
      })();
    }) as EventRef;
    this.registerEvent(eventRef);
    const registerCleanup = (this as unknown as { register?: (callback: () => void) => void }).register;
    registerCleanup?.call(this, () => {
      if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
      this.catalogValidationTimer = undefined;
    });
  }

  private scheduleCatalogValidation(): void {
    if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
    this.catalogValidationTimer = setTimeout(() => {
      this.catalogValidationTimer = undefined;
      void this.validateManagedCatalog(true);
    }, 300);
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
        new Notice("SVLT：本地跳转请求无效。");
        return;
      }

      const adapter = this.app.vault.adapter as unknown as { getFullPath?: (path: string) => string };
      const file = this.app.vault.getMarkdownFiles().find((candidate) => adapter.getFullPath?.(candidate.path) === fullPath);
      if (!file) {
        new Notice("SVLT：请求的文件不在当前库中。");
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

  private async validateManagedCatalog(silentWhenAccepted = false): Promise<void> {
    try {
      const response = await this.createVaultClient().request({ type: "catalogValidate" });
      if (response.type === "catalogValidation") {
        if (response.catalogStatus === "FOUND") {
          if (!silentWhenAccepted) new Notice("SVLT：敏感信息目录验证通过。");
        } else if (response.catalogStatus === "PENDING_EXTERNAL_CHANGE") {
          new Notice("SVLT：目录有待审批的高风险外部修改，请在 SVLT App 中批准。");
        } else {
          new Notice(`SVLT：敏感信息目录验证失败（${response.catalogStatus}）。`);
        }
        return;
      }

      new Notice(`SVLT：敏感信息目录验证失败（${response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE"}）。`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：敏感信息目录验证失败（${message}）。`);
    }
  }

  private async refuseManagedCatalogMutation(documentText: string): Promise<boolean> {
    const format = classifyCatalogText(documentText);
    if (format === "unmanaged" || format === "managedV3") {
      if (format === "managedV3") await this.validateManagedCatalog(true);
      return false;
    }

    await this.validateManagedCatalog();
    new Notice("SVLT：v2 或旧版敏感信息目录请先在 SVLT App 中升级；Obsidian 不会直接改写旧结构。");
    return true;
  }

  private async refuseManagedCatalogEncryption(documentText: string): Promise<boolean> {
    if (classifyCatalogText(documentText) === "managedV3") {
      await this.validateManagedCatalog(true);
      new Notice("SVLT：v3 敏感信息目录中的普通字段不能直接加密；请先在 SVLT App 中把字段设为密码字段。手工 Markdown 编辑仍然可用。");
      return true;
    }
    return this.refuseManagedCatalogMutation(documentText);
  }

  private async refuseManagedCatalogRestore(documentText: string): Promise<boolean> {
    if (classifyCatalogText(documentText) === "managedV3") {
      await this.validateManagedCatalog(true);
      new Notice("SVLT：v3 敏感信息目录禁止在 Obsidian 中还原 secret://；明文只可在 SVLT App 安全窗口中临时查看。");
      return true;
    }
    return this.refuseManagedCatalogMutation(documentText);
  }

  private async encryptSelection(editor: Editor): Promise<void> {
    if (isManagedCatalogText(editor.getValue()) && await this.refuseManagedCatalogEncryption(editor.getValue())) {
      return;
    }
    const text = editor.getSelection();
    if (text.length === 0) {
      new Notice("SVLT：请先选择要加密的文本。");
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
    if (isManagedCatalogText(documentText) && await this.refuseManagedCatalogEncryption(documentText)) {
      return;
    }
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    if (range.text.trim().length === 0) {
      new Notice("SVLT：当前段落为空。");
      return;
    }

    const findings = scanMarkdownFile(this.app.workspace?.getActiveFile()?.path ?? "current-paragraph.md", range.text);
    if (findings.length === 0) {
      new Notice("SVLT：当前段落未检测到敏感文本；请手动选择准确内容后加密。");
      return;
    }

    try {
      const updatedText = await this.encryptFindingsInText(range.text, findings);
      const fromPos = editor.offsetToPos(range.start);
      const toPos = editor.offsetToPos(range.end);
      if (editor.getRange(fromPos, toPos) !== range.text) {
        new Notice("SVLT：加密完成前笔记已变化，未写入修改。");
        return;
      }
      editor.replaceRange(updatedText, fromPos, toPos, "svlt");
      new Notice(`SVLT：当前段落已加密 ${findings.length} 处敏感内容。`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：段落加密失败（${message}）。`);
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
        new Notice("SVLT：加密完成前笔记已变化，未写入修改。");
        return;
      }

      editor.replaceRange(result.replacementText, fromPos, toPos, "svlt");
      new Notice("SVLT：文本已转换为加密引用。");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：加密失败（${message}）。`);
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
      new Notice("SVLT：请选择包含加密引用的文本后查看。");
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

      new Notice("SVLT：已在 SVLT App 中打开临时查看会话。");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：临时查看失败（${message}）。`);
    }
  }

  private async restoreCurrentParagraph(editor: Editor): Promise<void> {
    const documentText = editor.getValue();
    if (isManagedCatalogText(documentText) && await this.refuseManagedCatalogRestore(documentText)) {
      return;
    }
    const range = extractCurrentParagraph(documentText, editor.posToOffset(editor.getCursor()));
    await this.restoreRange(editor, range, editor.offsetToPos(range.start), editor.offsetToPos(range.end), "SVLT: current paragraph has no secret reference.");
  }

  private async restoreSelection(editor: Editor): Promise<void> {
    if (isManagedCatalogText(editor.getValue()) && await this.refuseManagedCatalogRestore(editor.getValue())) {
      return;
    }
    const text = editor.getSelection();
    if (text.trim().length === 0) {
      new Notice("SVLT：请选择包含加密引用的文本后还原。");
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
        new Notice("SVLT：还原完成前笔记已变化，未写入修改。");
        return;
      }
      editor.replaceRange(response.text, fromPos, toPos, "svlt-restore");
      new Notice("SVLT：已将加密引用还原为明文。");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：还原失败（${message}）。`);
    }
  }

  private async scanCurrentNote(editor: Editor): Promise<void> {
    const originalText = editor.getValue();
    if (isManagedCatalogText(originalText) && await this.refuseManagedCatalogEncryption(originalText)) {
      return;
    }
    const activeFilePath = this.app.workspace?.getActiveFile()?.path ?? "current-note.md";
    const findings = scanMarkdownFile(activeFilePath, originalText);
    new ReviewModal(this.app, findings, async (selectedFindings) => {
      try {
        if (editor.getValue() !== originalText) {
          new Notice("SVLT：扫描后笔记已变化，未写入修改。");
          return;
        }

        const updatedText = await this.encryptFindingsInText(originalText, selectedFindings);
        editor.setValue(updatedText);
        new Notice(`SVLT：已加密 ${selectedFindings.length} 处敏感内容。`);
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`SVLT：扫描结果写回失败（${message}）。`);
      }
    }).open();
  }

  private async scanVault(): Promise<void> {
    const files = this.app.vault.getMarkdownFiles();
    const filesByPath = new Map(files.map((file) => [file.path, file]));
    const snapshots = new Map<string, string>();
    const allFindings: ScanFindingState[] = [];
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
      new Notice("SVLT：已跳过受管敏感信息.md；密码字段请在 SVLT App 中管理，普通 Markdown 仍可手工编辑。");
    }

    new ReviewModal(this.app, allFindings, async (selectedFindings) => {
      try {
        const result = await this.applyVaultFindings(selectedFindings, filesByPath, snapshots);
        new Notice(this.replacementSummary(result.appliedCount, result.skippedCount));
      } catch (error) {
        const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
        new Notice(`SVLT：扫描结果写回失败（${message}）。`);
      }
    }).open();
  }

  private async scanOrphans(): Promise<void> {
    const references = new Set<string>();
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
      new Notice("SVLT：已跳过旧版敏感信息.md；升级为 v3 后可由 Obsidian 正常编辑。");
    }

    try {
      const response = await this.createVaultClient().request({
        type: "scanOrphans",
        markdownReferences: [...references].sort()
      });
      if (response.type !== "orphanScan") {
        throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
      }
      new Notice("SVLT：孤立引用扫描请求已发送到 SVLT App。");
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      new Notice(`SVLT：孤立引用扫描失败（${message}）。`);
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

      if (isManagedCatalogText(originalText)) {
        await this.validateManagedCatalog();
        new Notice("SVLT：已跳过受管敏感信息.md，未通过普通加密命令写入目录；请在 SVLT App 中管理密码字段。");
        skippedCount += findings.length;
        continue;
      }

      const currentText = await this.app.vault.cachedRead(file);
      if (currentText !== originalText) {
        new Notice(`SVLT：扫描后文件 ${filePath} 已变化，未写入修改。`);
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
    const applied = `已加密 ${appliedCount} 处敏感内容`;
    if (skippedCount === 0) {
      return `SVLT：${applied}。`;
    }
    return `SVLT：${applied}；有 ${skippedCount} 处文件已变化，已跳过。`;
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
