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
        status: {
          locked: true,
          ipcAvailable: true,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      }
    })).toEqual({
      canOperate: false,
      message: "Unlock Agent Secret Vault to continue."
    });
  });

  it("blocks operations when IPC is unavailable", () => {
    expect(interpretWorkbenchStatus({
      reachable: true,
      status: {
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: false,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      }
    })).toEqual({
      canOperate: false,
      message: "Agent Secret Vault IPC is unavailable."
    });
  });

  it("allows operations when the app is unlocked and IPC is available", () => {
    expect(interpretWorkbenchStatus({
      reachable: true,
      status: {
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      }
    })).toEqual({
      canOperate: true,
      message: "Agent Secret Vault is ready."
    });
  });
});
