import { beforeEach, describe, expect, it, vi } from "vitest";

const obsidianMock = vi.hoisted(() => ({
  registeredCommands: [] as Array<{ id: string; callback?: () => void }>,
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
  });

  it("registers core workbench commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "encrypt-selection",
      "encrypt-current-paragraph",
      "scan-current-note",
      "scan-vault",
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
});
