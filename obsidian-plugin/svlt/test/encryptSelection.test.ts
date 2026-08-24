import { describe, expect, it, vi } from "vitest";
import { encryptTextRange, inferReferenceTitle } from "../src/encrypt/encryptSelection";

const obsidianMock = vi.hoisted(() => ({
  notices: [] as string[]
}));

vi.mock("obsidian", () => ({
  Notice: class NoticeTestDouble {
    constructor(message: string) {
      obsidianMock.notices.push(message);
    }
  },
  Modal: class ModalTestDouble {
    contentEl = { empty: vi.fn(), createEl: vi.fn() };

    constructor(_app: unknown) {}

    open(): void {}
    close(): void {}
  },
  Plugin: class ObsidianPluginTestDouble {
    app: unknown;

    constructor(app: unknown) {
      this.app = app;
    }

    addStatusBarItem(): HTMLElement {
      return { textContent: "" } as HTMLElement;
    }

    addCommand(command: unknown): unknown {
      return command;
    }
  }
}));

import AgentSecretVaultPlugin from "../src/main";

interface TestEditorPosition {
  line: number;
  ch: number;
}

class TestEditor {
  replaceCalls: Array<{
    replacement: string;
    from: TestEditorPosition;
    to: TestEditorPosition;
    origin?: string;
  }> = [];

  setValueCalls = 0;

  constructor(
    public text: string,
    private readonly selectionStart: number,
    private readonly selectionEnd: number
  ) {}

  getSelection(): string {
    return this.text.slice(this.selectionStart, this.selectionEnd);
  }

  getCursor(which?: "from" | "to"): TestEditorPosition {
    return this.offsetToPos(which === "to" ? this.selectionEnd : this.selectionStart);
  }

  posToOffset(position: TestEditorPosition): number {
    return position.ch;
  }

  offsetToPos(offset: number): TestEditorPosition {
    return { line: 0, ch: offset };
  }

  getValue(): string {
    return this.text;
  }

  getRange(from: TestEditorPosition, to: TestEditorPosition): string {
    return this.text.slice(this.posToOffset(from), this.posToOffset(to));
  }

  replaceRange(
    replacement: string,
    from: TestEditorPosition,
    to: TestEditorPosition,
    origin?: string
  ): void {
    this.replaceCalls.push({ replacement, from, to, origin });
    this.text = `${this.text.slice(0, this.posToOffset(from))}${replacement}${this.text.slice(this.posToOffset(to))}`;
  }

  setValue(): void {
    this.setValueCalls += 1;
    throw new Error("setValue must not be used for async encryption replacement");
  }
}

describe("encrypt selection", () => {
  it("replaces selected plaintext with a titled markdown reference", async () => {
    let observedRequest: unknown;
    const result = await encryptTextRange({
      documentText: "token = ASV_CANARY_PLUGIN",
      range: { start: 8, end: 25, text: "ASV_CANARY_PLUGIN" },
      label: null,
      referenceTitle: "NAS 密码",
      policy: "credential",
      client: {
        request: async (request) => {
          observedRequest = request;
          return {
            type: "created",
            reference: "secret://0123456789ABCDEFGHJKMNPQRS"
          };
        }
      }
    });

    expect(observedRequest).toEqual({
      type: "encryptText",
      plaintext: "ASV_CANARY_PLUGIN",
      label: null,
      policy: "credential"
    });
    expect(result.updatedText).toBe("token = [NAS 密码](secret://0123456789ABCDEFGHJKMNPQRS)");
    expect(JSON.stringify(result)).not.toContain("ASV_CANARY_PLUGIN");
  });

  it("rejects app-side encryption failures without returning plaintext", async () => {
    await expect(encryptTextRange({
      documentText: "token = ASV_CANARY_PLUGIN",
      range: { start: 8, end: 25, text: "ASV_CANARY_PLUGIN" },
      label: null,
      referenceTitle: "敏感信息",
      policy: "credential",
      client: {
        request: async () => ({ type: "failure", code: "VAULT_LOCKED" })
      }
    })).rejects.toThrow("VAULT_LOCKED");
  });

  it("rejects unexpected IPC response types", async () => {
    await expect(encryptTextRange({
      documentText: "token = ASV_CANARY_PLUGIN",
      range: { start: 8, end: 25, text: "ASV_CANARY_PLUGIN" },
      label: null,
      referenceTitle: "敏感信息",
      policy: "credential",
      client: {
        request: async () => ({
          type: "workbenchStatus",
          status: {
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: null,
            pluginConnected: true
          }
        })
      }
    })).rejects.toThrow("UNEXPECTED_RESPONSE");
  });

  it("uses replaceRange for the original selection when it is unchanged after IPC", async () => {
    obsidianMock.notices = [];
    const editor = new TestEditor("token = ASV_CANARY_PLUGIN", 8, 25);
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      encryptSelection: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return {
          type: "created",
          reference: "secret://0123456789ABCDEFGHJKMNPQRS"
        };
      }
    });

    await plugin.encryptSelection(editor);

    expect(editor.text).toBe("token = [token](secret://0123456789ABCDEFGHJKMNPQRS)");
    expect(editor.setValueCalls).toBe(0);
    expect(editor.replaceCalls).toEqual([{
      replacement: "[token](secret://0123456789ABCDEFGHJKMNPQRS)",
      from: { line: 0, ch: 8 },
      to: { line: 0, ch: 25 },
      origin: "svlt"
    }]);
    expect(requests).toContainEqual(expect.objectContaining({
      type: "encryptText",
      label: "token = [[ASV_REFERENCE]]"
    }));
  });

  it("uses the line label before the selected value as the visible reference title", () => {
    const text = "NAS 密码：ASV_CANARY_PLUGIN";
    expect(inferReferenceTitle(text, { start: 7, end: text.length, text: "ASV_CANARY_PLUGIN" })).toBe("NAS 密码");
  });

  it("does not replace the selection when the editor text changes before IPC returns", async () => {
    obsidianMock.notices = [];
    const editor = new TestEditor("token = ASV_CANARY_PLUGIN", 8, 25);
    let resolveResponse: ((reference: string) => void) | undefined;
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      encryptSelection: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async () => new Promise((resolve) => {
        resolveResponse = (reference: string) => resolve({ type: "created", reference });
      })
    });

    const pendingEncryption = plugin.encryptSelection(editor);
    editor.text = "token = USER_EDITED_VALUE";
    resolveResponse?.("secret://0123456789ABCDEFGHJKMNPQRS");
    await pendingEncryption;

    expect(editor.text).toBe("token = USER_EDITED_VALUE");
    expect(editor.setValueCalls).toBe(0);
    expect(editor.replaceCalls).toEqual([]);
    expect(obsidianMock.notices).toContain("SVLT: note changed before encryption completed; leaving text unchanged.");
  });

  it("refuses direct encryption inside a managed catalog", async () => {
    obsidianMock.notices = [];
    const text = '<!-- SVLT-MANAGED-CATALOG schema="2" -->\npassword = ASV_CANARY_PLUGIN';
    const selectionStart = text.indexOf("ASV_CANARY_PLUGIN");
    const editor = new TestEditor(text, selectionStart, selectionStart + "ASV_CANARY_PLUGIN".length);
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      encryptSelection: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return { type: "catalogValidation", catalogStatus: "FOUND", revision: 1 };
      }
    });

    await plugin.encryptSelection(editor);

    expect(editor.text).toContain("ASV_CANARY_PLUGIN");
    expect(editor.replaceCalls).toEqual([]);
    expect(requests).toEqual([{ type: "catalogValidate" }]);
    expect(obsidianMock.notices).toContain("SVLT: managed 敏感信息.md 只能通过 SVLT App/MCP Catalog 工具修改；Obsidian 不会直接写入 Markdown/JSON。");
  });

  it("encrypts only detected sensitive snippets in the current paragraph", async () => {
    obsidianMock.notices = [];
    const editor = new TestEditor("context before\n\nlogin password = hunter2 for server\n\ncontext after", 24, 24);
    const plaintexts: string[] = [];
    const plugin = new AgentSecretVaultPlugin({
      workspace: {
        getActiveFile: () => ({ path: "Secrets.md" })
      }
    } as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      encryptCurrentParagraph: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: { plaintext: string }) => {
        plaintexts.push(request.plaintext);
        return {
          type: "created",
          reference: "secret://0123456789ABCDEFGHJKMNPQRS"
        };
      }
    });

    await plugin.encryptCurrentParagraph(editor);

    expect(plaintexts).toEqual(["hunter2"]);
    expect(editor.text).toBe("context before\n\nlogin password = secret://0123456789ABCDEFGHJKMNPQRS for server\n\ncontext after");
    expect(editor.replaceCalls).toEqual([{
      replacement: "login password = secret://0123456789ABCDEFGHJKMNPQRS for server",
      from: { line: 0, ch: 16 },
      to: { line: 0, ch: 51 },
      origin: "svlt"
    }]);
  });

  it("restores secret references in the current paragraph through explicit write-back IPC", async () => {
    obsidianMock.notices = [];
    const editor = new TestEditor("token = secret://0123456789ABCDEFGHJKMNPQRS for server", 10, 10);
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      restoreCurrentParagraph: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return { type: "restoredText", text: "token = hunter2 for server" };
      }
    });

    await plugin.restoreCurrentParagraph(editor);

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ type: "restoreReferences" });
    expect(editor.text).toBe("token = hunter2 for server");
    expect(editor.replaceCalls[0]).toMatchObject({
      replacement: "token = hunter2 for server",
      origin: "svlt-restore"
    });
  });
});
