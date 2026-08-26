import { describe, expect, it } from "vitest";
import { IpcRequest, IpcResponse } from "../src/ipc/protocol";

describe("IPC protocol", () => {
  it("allows only read-only validator requests", () => {
    expect(IpcRequest.parse({ type: "workbenchStatus" })).toEqual({ type: "workbenchStatus" });
    expect(IpcRequest.parse({ type: "catalogValidate" })).toEqual({ type: "catalogValidate" });

    expect(() => IpcRequest.parse({
      type: "encryptText",
      plaintext: "local-only selected text",
      label: null,
      policy: "credential"
    })).toThrow();
    expect(() => IpcRequest.parse({
      type: "revealReferences",
      references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
      context: { reason: "reveal", template: "{{0}}", ranges: [{ index: 0, placeholder: "{{0}}" }] }
    })).toThrow();
    expect(() => IpcRequest.parse({
      type: "restoreReferences",
      references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
      context: { reason: "restore", template: "{{0}}", ranges: [{ index: 0, placeholder: "{{0}}" }] }
    })).toThrow();
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

  it("parses managed catalog diagnostics without accepting document content", () => {
    expect(IpcRequest.parse({ type: "catalogValidate" })).toEqual({ type: "catalogValidate" });
    expect(IpcResponse.parse({
      type: "catalogValidation",
      catalogStatus: "CATALOG_INVALID",
      revision: 7,
      rawSHA256: "a".repeat(64),
      diagnostics: [{
        id: "HEADING_MARKER_MISMATCH:7:1",
        severity: "error",
        code: "HEADING_MARKER_MISMATCH",
        line: 7,
        column: 1,
        scope: "entry",
        message: "heading 与 marker 标题不一致",
        hint: "使 heading 与 marker 中的标题保持一致"
      }]
    })).toEqual({
      type: "catalogValidation",
      catalogStatus: "CATALOG_INVALID",
      revision: 7,
      rawSHA256: "a".repeat(64),
      diagnostics: [{
        id: "HEADING_MARKER_MISMATCH:7:1",
        severity: "error",
        code: "HEADING_MARKER_MISMATCH",
        line: 7,
        column: 1,
        scope: "entry",
        message: "heading 与 marker 标题不一致",
        hint: "使 heading 与 marker 中的标题保持一致"
      }]
    });

    expect(() => IpcResponse.parse({
      type: "catalogValidation",
      catalogStatus: "FOUND",
      document: "must not be returned"
    })).toThrow();
  });

  it("rejects plaintext-bearing response cases", () => {
    expect(() => IpcResponse.parse({
      type: "revealSessionOpened",
      sessionID: "session-1"
    })).toThrow();
    expect(() => IpcResponse.parse({
      type: "restoredText",
      text: "token=plaintext-for-write-back"
    })).toThrow();
    expect(() => IpcResponse.parse({
      type: "created",
      reference: "secret://0123456789ABCDEFGHJKMNPQRS"
    })).toThrow();
  });
});
