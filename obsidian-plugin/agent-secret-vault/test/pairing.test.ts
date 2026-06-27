import { describe, expect, it } from "vitest";
import { interpretWorkbenchStatus } from "../src/pairing/pairing";

describe("pairing", () => {
  it("blocks operations when the app is locked or unreachable", () => {
    expect(interpretWorkbenchStatus({ reachable: false })).toEqual({
      canOperate: false,
      message: "Agent Secret Vault is unavailable."
    });

    expect(interpretWorkbenchStatus({
      reachable: true,
      status: {
        type: "workbenchStatus",
        locked: true,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    })).toEqual({
      canOperate: false,
      message: "Unlock Agent Secret Vault to continue."
    });
  });
});
