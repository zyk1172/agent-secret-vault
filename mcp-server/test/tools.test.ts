import { describe, expect, it } from "vitest";

import { type IpcRequest, type IpcResponse } from "../src/protocol.js";
import { createVaultToolDefinitions, type VaultIpcClient } from "../src/server.js";

const validReference = "secret://0123456789ABCDEFGHJKMNPQRS";

describe("MCP tool contracts", () => {
  it("registers only the five non-plaintext tools", () => {
    const tools = createVaultToolDefinitions(new FakeClient([]));

    expect(tools.map((tool) => tool.name).sort()).toEqual([
      "paragraph_reveal_request",
      "secret_create_request",
      "secret_reveal_request",
      "secure_execute",
      "vault_status"
    ]);
    for (const tool of tools) {
      expect(tool.description).toMatch(/plaintext is never returned/i);
    }
  });

  it("vault_status returns lock state without sensitive fields", async () => {
    const client = new FakeClient([{ type: "status", locked: false }]);
    const tool = getTool(client, "vault_status");

    const result = await tool.handler({});

    expect(client.requests).toEqual([{ type: "status" }]);
    expect(result.structuredContent).toEqual({ locked: false });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_reveal_request only reports that plaintext was displayed to the user", async () => {
    const client = new FakeClient([{ type: "displayedToUser" }]);
    const tool = getTool(client, "secret_reveal_request");

    const result = await tool.handler({ reference: validReference, reason: "manual verification" });

    expect(client.requests).toEqual([
      { type: "reveal", reference: validReference, reason: "manual verification" }
    ]);
    expect(result.structuredContent).toEqual({ status: "DISPLAYED_TO_USER" });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("paragraph_reveal_request opens a local reveal session without returning plaintext", async () => {
    const references = [validReference];
    const client = new FakeClient([{ type: "revealSessionOpened", sessionID: "session-1" }]);
    const tool = getTool(client, "paragraph_reveal_request");

    const result = await tool.handler({
      references,
      template: "Deploy token: {{0}}",
      reason: "ASV_CANARY plaintext boundary check"
    });

    expect(client.requests).toEqual([
      {
        type: "revealReferences",
        references,
        context: {
          reason: "ASV_CANARY plaintext boundary check",
          template: "Deploy token: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(result.structuredContent).toEqual({ status: "DISPLAYED_TO_USER" });
    const resultJson = JSON.stringify(result);
    expect(resultJson).not.toContain("ASV_CANARY");
    expect(resultJson).not.toMatch(/plaintext/i);
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_create_request returns only a secret reference", async () => {
    const client = new FakeClient([{ type: "created", reference: validReference }]);
    const tool = getTool(client, "secret_create_request");

    const result = await tool.handler({ label: "api token", policy: "externalSend" });

    expect(client.requests).toEqual([
      { type: "encrypt", label: "api token", policy: "externalSend" }
    ]);
    expect(result.structuredContent).toEqual({ reference: validReference });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secure_execute returns only sanitized execution output", async () => {
    const client = new FakeClient([
      {
        type: "execution",
        result: { type: "completed", exitCode: 0, stdout: "ok [REDACTED_SECRET]", stderr: "" }
      }
    ]);
    const tool = getTool(client, "secure_execute");

    const result = await tool.handler({
      templateID: "send-message",
      executable: "/usr/bin/printf",
      values: { message: "hello" },
      secrets: { apiToken: validReference },
      destinationHost: "api.example.com",
      destinationPath: "/v1/send",
      requestedRisk: 1
    });

    expect(client.requests).toEqual([
      {
        type: "execute",
        request: {
          templateID: "send-message",
          executable: "/usr/bin/printf",
          values: { message: "hello" },
          secrets: { apiToken: validReference },
          destinationHost: "api.example.com",
          destinationPath: "/v1/send",
          requestedRisk: 1
        }
      }
    ]);
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      exitCode: 0,
      stdout: "ok [REDACTED_SECRET]",
      stderr: ""
    });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secure_execute rejects raw values in secret slots", async () => {
    const tool = getTool(new FakeClient([]), "secure_execute");

    await expect(
      tool.handler({
        templateID: "send-message",
        executable: "/usr/bin/printf",
        values: { message: "hello" },
        secrets: { apiToken: "raw-token-value" },
        requestedRisk: 1
      })
    ).rejects.toThrow();
  });
});

class FakeClient implements VaultIpcClient {
  readonly requests: IpcRequest[] = [];

  constructor(private readonly responses: IpcResponse[]) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    this.requests.push(request);
    const response = this.responses.shift();
    if (response === undefined) {
      throw new Error("unexpected request");
    }
    return response;
  }
}

function getTool(client: VaultIpcClient, name: string) {
  const tool = createVaultToolDefinitions(client).find((candidate) => candidate.name === name);
  if (tool === undefined) {
    throw new Error(`missing tool ${name}`);
  }
  return tool;
}

function expectForbiddenKeysAbsent(value: unknown): void {
  const forbiddenKeys = collectForbiddenKeys(value);
  expect(forbiddenKeys).toEqual([]);
}

function collectForbiddenKeys(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap(collectForbiddenKeys);
  }

  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, nestedValue]) => {
      const matches = /plaintext|secretValue|resolvedArguments|masterKey/i.test(key) ? [key] : [];
      return matches.concat(collectForbiddenKeys(nestedValue));
    });
  }

  return [];
}
