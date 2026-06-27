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
});
