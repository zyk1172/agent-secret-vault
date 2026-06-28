import { beforeEach, describe, expect, it, vi } from "vitest";

const obsidianMock = vi.hoisted(() => ({
  registeredCommands: [] as Array<{ id: string; callback?: () => void }>,
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
      const element = { textContent: "" } as HTMLElement;
      obsidianMock.statusItems.push(element);
      return element;
    }

    addCommand(command: { id: string; callback?: () => void }): { id: string; callback?: () => void } {
      obsidianMock.registeredCommands.push(command);
      return command;
    }
  }
}));

import AgentSecretVaultPlugin, { commandDefinitions } from "../src/main";

describe("plugin commands", () => {
  beforeEach(() => {
    obsidianMock.registeredCommands = [];
    obsidianMock.notices = [];
    obsidianMock.statusItems = [];
  });

  it("registers core workbench commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "encrypt-selection",
      "encrypt-current-paragraph",
      "scan-current-note",
      "scan-vault",
      "scan-orphans",
      "reveal-current-paragraph"
    ]);
  });

  it("shows a visible not-connected notice for placeholder commands", async () => {
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never);

    await plugin.onload();
    obsidianMock.registeredCommands[0].callback?.();

    expect(obsidianMock.notices).toEqual([
      "Agent Secret Vault: encrypt-selection is not connected yet."
    ]);
  });

  it("updates the status bar from live workbench status", async () => {
    const plugin = new AgentSecretVaultPlugin({} as never, {} as never) as unknown as {
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
});
