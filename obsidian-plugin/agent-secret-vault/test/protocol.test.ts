import { describe, expect, it } from "vitest";
import { IpcResponse, IpcRequest } from "../src/ipc/protocol";

describe("IPC protocol", () => {
  it("allows plugin-to-app encryptText but rejects plaintext-shaped responses", () => {
    expect(IpcRequest.parse({
      type: "encryptText",
      plaintext: "local-only selected text",
      label: null,
      policy: "credential"
    })).toBeTruthy();

    expect(() => IpcResponse.parse({
      type: "revealSessionOpened",
      plaintext: "must not return"
    })).toThrow();
  });

  it("parses status-only reveal responses", () => {
    expect(IpcResponse.parse({
      type: "revealSessionOpened",
      sessionID: "session-1"
    })).toEqual({
      type: "revealSessionOpened",
      sessionID: "session-1"
    });
  });

  it("parses Swift-shaped workbench status responses", () => {
    expect(IpcResponse.parse({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    })).toEqual({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });
  });

  it("parses Swift-shaped orphan scan responses", () => {
    expect(IpcResponse.parse({
      type: "orphanScan",
      result: {
        missingRecords: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        unreferencedRecords: []
      }
    })).toEqual({
      type: "orphanScan",
      result: {
        missingRecords: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        unreferencedRecords: []
      }
    });
  });
});
