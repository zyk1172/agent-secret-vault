import { beforeEach, describe, expect, it, vi } from "vitest";

const obsidianMock = vi.hoisted(() => ({
  registeredCommands: [] as Array<{ id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void }>,
  registeredEvents: [] as unknown[],
  vaultEvents: [] as Array<{ name: string; callback: (...args: unknown[]) => void }>,
  notices: [] as string[],
  statusItems: [] as HTMLElement[]
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
      const element = { textContent: "", setAttribute: vi.fn() } as unknown as HTMLElement;
      obsidianMock.statusItems.push(element);
      return element;
    }

    addCommand(command: { id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void }): { id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void } {
      obsidianMock.registeredCommands.push(command);
      return command;
    }

    registerEvent(eventRef: unknown): void {
      obsidianMock.registeredEvents.push(eventRef);
    }

    register(callback: () => void): void {
      callback();
    }
  }
}));

import AgentSecretVaultPlugin, { commandDefinitions } from "../src/main";

function makeApp() {
  return {
    vault: {
      on: (name: string, callback: (...args: unknown[]) => void) => {
        const eventRef = { name, callback };
        obsidianMock.vaultEvents.push(eventRef);
        return eventRef;
      }
    },
    workspace: {
      getActiveFile: () => null,
      getLeaf: () => ({ openFile: async () => undefined, view: null })
    }
  };
}

function makePlugin(clientResponse: unknown = { type: "failure", code: "APP_UNAVAILABLE" }) {
  const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never) as unknown as {
    createVaultClient: () => unknown;
    onload: () => Promise<void>;
  };
  plugin.createVaultClient = () => ({
    request: async () => clientResponse
  });
  return plugin;
}

describe("plugin commands", () => {
  beforeEach(() => {
    obsidianMock.registeredCommands = [];
    obsidianMock.registeredEvents = [];
    obsidianMock.vaultEvents = [];
    obsidianMock.notices = [];
    obsidianMock.statusItems = [];
  });

  it("registers validator-only commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "validate-catalog",
      "show-catalog-diagnostics"
    ]);
  });

  it("uses Chinese command names in the command palette", () => {
    expect(commandDefinitions.map((command) => command.name)).toEqual([
      "验证 SVLT 敏感信息目录",
      "查看 SVLT 目录诊断"
    ]);
  });

  it("registers commands and a modify watcher on load", async () => {
    const plugin = makePlugin({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });

    await plugin.onload();

    expect(obsidianMock.registeredCommands.map((command) => command.id)).toEqual([
      "validate-catalog",
      "show-catalog-diagnostics"
    ]);
    expect(obsidianMock.vaultEvents.map((event) => event.name)).toEqual(["modify"]);
  });

  it("updates the status bar from live workbench status", async () => {
    const plugin = makePlugin({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });

    await plugin.onload();

    expect(obsidianMock.statusItems[0]?.textContent).toBe("ASV: connected, unlocked");
  });

  it("shows a failure notice when the app is unavailable", async () => {
    const plugin = makePlugin();

    await plugin.onload();
    await obsidianMock.registeredCommands.find((command) => command.id === "validate-catalog")?.callback?.();

    expect(obsidianMock.notices).toEqual([
      "SVLT：敏感信息目录验证失败（APP_UNAVAILABLE）。"
    ]);
  });

  it("reports diagnostics count and first location", async () => {
    const plugin = makePlugin({
      type: "catalogValidation",
      catalogStatus: "CATALOG_INVALID",
      revision: 3,
      diagnostics: [
        {
          id: "HEADING_MARKER_MISMATCH:7:1",
          severity: "error",
          code: "HEADING_MARKER_MISMATCH",
          line: 7,
          column: 1,
          scope: "entry",
          message: "heading 与 marker 标题不一致",
          hint: "使 heading 与 marker 中的标题保持一致"
        },
        {
          id: "FIELD_KEY_DUPLICATE:9:1",
          severity: "error",
          code: "FIELD_KEY_DUPLICATE",
          line: 9,
          column: 1,
          scope: "field",
          message: "同一条目中存在重复字段 key。",
          hint: "每个条目的字段 key 必须唯一。"
        }
      ]
    });

    await plugin.onload();
    await obsidianMock.registeredCommands.find((command) => command.id === "validate-catalog")?.callback?.();

    expect(obsidianMock.notices).toEqual([
      "SVLT：敏感信息目录有 2 个格式问题，第一个位于 第 7 行、第 1 列。"
    ]);
    expect(obsidianMock.statusItems[0]?.textContent).toContain("2 个问题");
  });
});
