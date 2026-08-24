import { describe, expect, it } from "vitest";
import { interpretWorkbenchStatus } from "../src/pairing/pairing";

describe("pairing", () => {
  it("blocks operations when the app is locked or unreachable", () => {
    expect(interpretWorkbenchStatus({ reachable: false })).toEqual({
      canOperate: false,
      message: "SVLT 服务不可用。"
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
      message: "请先解锁 SVLT。"
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
      message: "SVLT 本机通道不可用。"
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
      message: "SVLT 已就绪。"
    });
  });
});
