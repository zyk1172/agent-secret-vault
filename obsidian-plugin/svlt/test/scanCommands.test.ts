import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanFindingState } from "../src/scan/scanState";

const obsidianMock = vi.hoisted(() => ({
  notices: [] as string[]
}));

const reviewMock = vi.hoisted(() => ({
  findings: [] as ScanFindingState[],
  apply: undefined as undefined | ((findings: ScanFindingState[]) => Promise<void>)
}));

vi.mock("obsidian", () => ({
  Notice: class NoticeTestDouble {
    constructor(message: string) {
      obsidianMock.notices.push(message);
    }
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
  },
  Modal: class ModalTestDouble {
    app: unknown;
    contentEl = { empty: vi.fn(), createEl: vi.fn() };

    constructor(app: unknown) {
      this.app = app;
    }

    open(): void {}
    close(): void {}
  }
}));

vi.mock("../src/ui/reviewModal", () => ({
  ReviewModal: class ReviewModalTestDouble {
    constructor(
      _app: unknown,
      findings: ScanFindingState[],
      apply: (findings: ScanFindingState[]) => Promise<void>
    ) {
      reviewMock.findings = findings;
      reviewMock.apply = apply;
    }

    open(): void {}
  }
}));

import AgentSecretVaultPlugin from "../src/main";

class TestEditor {
  setValueCalls: string[] = [];

  constructor(public text: string) {}

  getValue(): string {
    return this.text;
  }

  setValue(updatedText: string): void {
    this.setValueCalls.push(updatedText);
    this.text = updatedText;
  }
}

function makeReference(index: number): string {
  return `secret://0000000000000000000000000${index}`;
}

describe("scan commands", () => {
  beforeEach(() => {
    obsidianMock.notices = [];
    reviewMock.findings = [];
    reviewMock.apply = undefined;
  });

  it("scans the current note and replaces reviewed findings through authenticated IPC", async () => {
    const editor = new TestEditor("password = hunter2");
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      scanCurrentNote: (editor: TestEditor) => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: { plaintext: string }) => {
        requests.push(request);
        return {
          type: "created",
          reference: request.plaintext === "hunter2" ? makeReference(1) : makeReference(2)
        };
      }
    });

    await plugin.scanCurrentNote(editor);
    expect(reviewMock.findings).toHaveLength(1);
    expect(reviewMock.findings[0].plaintextForCurrentProcessOnly).toBe("hunter2");

    await reviewMock.apply?.(reviewMock.findings);

    expect(editor.text).toBe(`password = ${makeReference(1)}`);
    expect(editor.setValueCalls).toEqual([`password = ${makeReference(1)}`]);
    expect(obsidianMock.notices).toContain("SVLT：已加密 1 处敏感内容。");
    expect(requests).toContainEqual(expect.objectContaining({
      type: "encryptText",
      label: "password = [[ASV_REFERENCE]]"
    }));
  });

  it("scans the vault and modifies reviewed markdown files only when unchanged", async () => {
    const files = [{ path: "a.md" }, { path: "b.md" }];
    const contents = new Map([
      ["a.md", "api password = hunter2"],
      ["b.md", "no secrets here"]
    ]);
    const plugin = new AgentSecretVaultPlugin({
      vault: {
        getMarkdownFiles: () => files,
        cachedRead: async (file: { path: string }) => contents.get(file.path) ?? "",
        modify: async (file: { path: string }, updatedText: string) => {
          contents.set(file.path, updatedText);
        }
      }
    } as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      scanVault: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async () => ({ type: "created", reference: makeReference(3) })
    });

    await plugin.scanVault();
    expect(reviewMock.findings.map((finding) => finding.filePath)).toEqual(["a.md"]);

    await reviewMock.apply?.(reviewMock.findings);

    expect(contents.get("a.md")).toBe(`api password = ${makeReference(3)}`);
    expect(contents.get("b.md")).toBe("no secrets here");
    expect(obsidianMock.notices).toContain("SVLT：已加密 1 处敏感内容。");
  });

  it("reports skipped findings when vault files changed after scan", async () => {
    const files = [{ path: "a.md" }];
    const contents = new Map([["a.md", "password = hunter2"]]);
    const plugin = new AgentSecretVaultPlugin({
      vault: {
        getMarkdownFiles: () => files,
        cachedRead: async (file: { path: string }) => contents.get(file.path) ?? "",
        modify: async (file: { path: string }, updatedText: string) => {
          contents.set(file.path, updatedText);
        }
      }
    } as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      scanVault: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async () => ({ type: "created", reference: makeReference(4) })
    });

    await plugin.scanVault();
    contents.set("a.md", "password = user-edited");

    await reviewMock.apply?.(reviewMock.findings);

    expect(contents.get("a.md")).toBe("password = user-edited");
    expect(obsidianMock.notices).toContain("SVLT：已加密 0 处敏感内容；有 1 处文件已变化，已跳过。");
  });

  it("does not scan or write an SVLT managed catalog through Obsidian", async () => {
    const files = [{ path: "敏感信息.md" }];
    const managedCatalog = '<!-- SVLT-MANAGED-CATALOG schema="2" -->\n\n# 敏感信息\n\nQNAP password = must stay in Catalog Store';
    const contents = new Map([["敏感信息.md", managedCatalog]]);
    const requests: unknown[] = [];
    let modifyCalls = 0;
    const plugin = new AgentSecretVaultPlugin({
      vault: {
        getMarkdownFiles: () => files,
        cachedRead: async (file: { path: string }) => contents.get(file.path) ?? "",
        modify: async () => {
          modifyCalls += 1;
        }
      }
    } as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      scanVault: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return { type: "catalogValidation", catalogStatus: "FOUND", revision: 3 };
      }
    });

    await plugin.scanVault();

    expect(reviewMock.findings).toEqual([]);
    expect(modifyCalls).toBe(0);
    expect(requests).toEqual([{ type: "catalogValidate" }]);
    expect(obsidianMock.notices).toContain("SVLT：已跳过旧版敏感信息.md；请先在 SVLT App 中升级为 v3。");
  });

  it("sends markdown references to the app orphan scanner", async () => {
    const files = [{ path: "a.md" }, { path: "b.md" }];
    const contents = new Map([
      ["a.md", `one ${makeReference(5)}`],
      ["b.md", [
        `duplicate ${makeReference(5)} and two ${makeReference(6)}.`,
        `embedded prefix${makeReference(7)} ignored`,
        `long ${makeReference(8)}ABC ignored`
      ].join("\n")]
    ]);
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin({
      vault: {
        getMarkdownFiles: () => files,
        cachedRead: async (file: { path: string }) => contents.get(file.path) ?? ""
      }
    } as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      scanOrphans: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return { type: "orphanScan", result: { missingRecords: [], unreferencedRecords: [] } };
      }
    });

    await plugin.scanOrphans();

    expect(requests).toEqual([{
      type: "scanOrphans",
      markdownReferences: [makeReference(5), makeReference(6)]
    }]);
    expect(obsidianMock.notices).toContain("SVLT：孤立引用扫描请求已发送到 SVLT App。");
  });
});
