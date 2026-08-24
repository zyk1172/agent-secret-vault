import { beforeEach, describe, expect, it, vi } from "vitest";

const obsidianMock = vi.hoisted(() => ({
  registeredCommands: [] as Array<{ id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void }>,
  registeredEvents: [] as unknown[],
  workspaceEvents: [] as Array<{ name: string; callback: (...args: unknown[]) => void }>,
  supportsSubmenu: true,
  menuItems: [] as Array<{ title?: string; icon?: string; onClick?: (event?: unknown) => void }>,
  submenuItems: [] as Array<{ title?: string; icon?: string; onClick?: (event?: unknown) => void }>,
  shownMenus: [] as Array<{ x: number; y: number }>,
  shownMouseEvents: [] as unknown[],
  useNativeMenuCalls: [] as boolean[],
  notices: [] as string[],
  statusItems: [] as HTMLElement[]
}));

vi.mock("obsidian", () => ({
  Menu: class MenuTestDouble {
    constructor(private readonly targetItems = obsidianMock.menuItems) {}

    addItem(callback: (item: {
      setTitle: (title: string) => unknown;
      setIcon: (icon: string) => unknown;
      setSubmenu?: () => unknown;
      onClick: (handler: (event?: unknown) => void) => unknown;
    }) => void): void {
      const item: { title?: string; icon?: string; onClick?: (event?: unknown) => void } = {};
      const fluentItem = {
        setTitle: (title: string) => {
          item.title = title;
          return fluentItem;
        },
        setIcon: (icon: string) => {
          item.icon = icon;
          return fluentItem;
        },
        onClick: (handler: () => void) => {
          item.onClick = handler;
          return fluentItem;
        }
      };
      if (obsidianMock.supportsSubmenu) {
        (fluentItem as typeof fluentItem & { setSubmenu: () => MenuTestDouble }).setSubmenu = () => new MenuTestDouble(obsidianMock.submenuItems);
      }
      callback(fluentItem);
      this.targetItems.push(item);
    }

    addSeparator(): void {}

    setUseNativeMenu(useNativeMenu: boolean): this {
      obsidianMock.useNativeMenuCalls.push(useNativeMenu);
      return this;
    }

    showAtPosition(position: { x: number; y: number }): void {
      obsidianMock.shownMenus.push(position);
    }

    showAtMouseEvent(event: unknown): void {
      obsidianMock.shownMouseEvents.push(event);
    }
  },
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
      const element = { textContent: "" } as HTMLElement;
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
  }
}));

import AgentSecretVaultPlugin, { commandDefinitions } from "../src/main";

function makeApp() {
  return {
    workspace: {
      on: (name: string, callback: (...args: unknown[]) => void) => {
        const eventRef = { name, callback };
        obsidianMock.workspaceEvents.push(eventRef);
        return eventRef;
      }
    }
  };
}

describe("plugin commands", () => {
  beforeEach(() => {
    obsidianMock.registeredCommands = [];
    obsidianMock.registeredEvents = [];
    obsidianMock.workspaceEvents = [];
    obsidianMock.supportsSubmenu = true;
    obsidianMock.menuItems = [];
    obsidianMock.submenuItems = [];
    obsidianMock.shownMenus = [];
    obsidianMock.shownMouseEvents = [];
    obsidianMock.useNativeMenuCalls = [];
    obsidianMock.notices = [];
    obsidianMock.statusItems = [];
  });

  it("registers core workbench commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "encrypt-selection",
      "reveal-selection",
      "reveal-current-paragraph",
      "restore-selection",
      "restore-current-paragraph",
      "validate-catalog"
    ]);
  });

  it("uses Chinese command names in the command palette", () => {
    expect(commandDefinitions.map((command) => command.name)).toEqual([
      "加密选中文本",
      "在 SVLT 中临时解密选中文本",
      "在 SVLT 中临时解密当前段落",
      "还原选中文本中的密文引用",
      "还原当前段落中的密文引用",
      "验证 SVLT 敏感信息目录"
    ]);
  });

  it("shows a visible not-connected notice for placeholder commands", async () => {
    const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never);

    await plugin.onload();
    obsidianMock.registeredCommands[0].callback?.();

    expect(obsidianMock.notices).toEqual([
      "SVLT：加密选中文本 暂不可用，请先连接本机服务。"
    ]);
  });

  it("updates the status bar from live workbench status", async () => {
    const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      onload: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async () => ({
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      })
    });

    await plugin.onload();

    expect(obsidianMock.statusItems[0]?.textContent).toBe("ASV: connected, unlocked");
  });

  it("adds a second-level SVLT menu to the Obsidian right-click menu", async () => {
    const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never);

    await plugin.onload();
    obsidianMock.workspaceEvents.find((event) => event.name === "editor-menu")?.callback(new (await import("obsidian")).Menu(), {} as never);

    expect(obsidianMock.menuItems.map((item) => item.title)).toEqual(["SVLT"]);
    expect(obsidianMock.registeredEvents).toHaveLength(1);

    expect(obsidianMock.shownMenus).toEqual([]);
    expect(obsidianMock.submenuItems.map((item) => item.title)).toEqual([
      "加密选中文本",
      "临时解密选中文本",
      "还原选中文本"
    ]);
  });

  it("keeps one top-level menu item when native submenu is unavailable", async () => {
    obsidianMock.supportsSubmenu = false;
    const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never);

    await plugin.onload();
    obsidianMock.workspaceEvents.find((event) => event.name === "editor-menu")?.callback(new (await import("obsidian")).Menu(), {} as never);

    expect(obsidianMock.menuItems.map((item) => item.title)).toEqual(["SVLT"]);
    expect(obsidianMock.submenuItems).toEqual([]);

    const clickEvent = { clientX: 42, clientY: 24 };
    obsidianMock.menuItems[0].onClick?.(clickEvent);

    expect(obsidianMock.useNativeMenuCalls).toEqual([false]);
    expect(obsidianMock.shownMouseEvents).toEqual([clickEvent]);
    expect(obsidianMock.menuItems.map((item) => item.title)).toEqual([
      "SVLT",
      "加密选中文本",
      "临时解密选中文本",
      "还原选中文本"
    ]);
  });

  it("uses credential encryption from the simplified editor menu", async () => {
    const editor = {
      getSelection: () => "sensitive-value",
      getCursor: (which?: "from" | "to") => ({ line: 0, ch: which === "to" ? 15 : 0 }),
      posToOffset: (position: { ch: number }) => position.ch,
      getValue: () => "sensitive-value",
      getRange: () => "sensitive-value",
      replaceRange: () => undefined
    };
    const requests: unknown[] = [];
    const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never) as unknown as {
      createVaultClient: () => unknown;
      onload: () => Promise<void>;
    };
    plugin.createVaultClient = () => ({
      request: async (request: unknown) => {
        requests.push(request);
        return { type: "created", reference: "secret://0123456789ABCDEFGHJKMNPQRS" };
      }
    });
    await plugin.onload();
    obsidianMock.workspaceEvents.find((event) => event.name === "editor-menu")?.callback(new (await import("obsidian")).Menu(), editor);
    await obsidianMock.submenuItems[0]?.onClick?.();

    expect(requests).toContainEqual(expect.objectContaining({ type: "encryptText", policy: "credential" }));
  });
});
