import { describe, expect, it, vi } from "vitest";

vi.mock("obsidian", () => ({
  Plugin: class ObsidianPluginTestDouble {}
}));

import { commandDefinitions } from "../src/main";

describe("plugin commands", () => {
  it("registers core workbench commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "encrypt-selection",
      "encrypt-current-paragraph",
      "scan-current-note",
      "scan-vault",
      "reveal-current-paragraph"
    ]);
  });
});
