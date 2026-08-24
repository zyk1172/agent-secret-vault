import { describe, expect, it } from "vitest";

import { type IpcRequest, type IpcResponse } from "../src/protocol.js";
import {
  createVaultToolDefinitions,
  type VaultIpcClient
} from "../src/server.js";

const reference = "secret://0123456789ABCDEFGHJKMNPQRS";
const usernameReference = "secret://0123456789ABCDEFGHJKMNPQT";

class FakeClient implements VaultIpcClient {
  readonly requests: IpcRequest[] = [];

  constructor(private readonly responses: IpcResponse[]) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    this.requests.push(request);
    return this.responses.shift() ?? { type: "failure", code: "NO_FIXTURE" };
  }
}

function operationResponse(extra: Record<string, unknown> = {}): IpcResponse {
  return {
    type: "secretOperation",
    output: { status: "COMPLETED", redacted: true, ...extra }
  } as IpcResponse;
}

function tool(client: VaultIpcClient, name: string) {
  const definition = createVaultToolDefinitions(client).find((item) => item.name === name);
  if (definition === undefined) {
    throw new Error(`missing tool ${name}`);
  }
  return definition;
}

describe("MCP tool contracts", () => {
  it("exposes dedicated opaque secret tools", () => {
    const names = createVaultToolDefinitions(new FakeClient([])).map((item) => item.name);
    expect(names).toEqual(expect.arrayContaining([
      "vault_status",
      "secret_search",
      "secret_catalog_search",
      "secret_catalog_get",
      "secret_catalog_create_index",
      "secret_catalog_create_entry",
      "secret_catalog_create_draft",
      "secret_catalog_patch_metadata",
      "secret_catalog_commit",
      "secret_catalog_add_secret_placeholder",
      "secret_catalog_bind_existing_secret",
      "secret_catalog_validate",
      "secret_inspect_reference",
      "ssh_command_with_secret",
      "local_http_request_with_secret",
      "api_request_with_token",
      "database_query_with_secret",
      "sftp_transfer_with_secret",
      "secret_reveal_request"
    ]));
    expect(names).not.toContain("restore_references");
  });

  it("does not gate normal work on the compatibility locked field", async () => {
    const client = new FakeClient([{
      type: "workbenchStatus",
      status: {
        locked: true,
        ipcAvailable: true,
        available: true,
        ready: true,
        approvalPending: false,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    } as IpcResponse]);

    const result = await tool(client, "vault_status").handler({});
    expect(result.structuredContent).toEqual({
      status: "READY",
      available: true,
      ready: true,
      approvalPending: false
    });
  });

  it("returns destination binding as non-sensitive metadata", async () => {
    const client = new FakeClient([{
      type: "referenceMetadata",
      metadata: {
        reference,
        policy: "credential",
        label: "QNAP credential",
        allowedDestinations: ["192.168.2.240", "qnap.local"],
        allowedProtocols: ["ssh", "https"],
        createdAt: 1,
        updatedAt: 2
      }
    } as IpcResponse]);

    const result = await tool(client, "secret_inspect_reference").handler({ reference });
    expect(result.structuredContent).toEqual({
      reference,
      policy: "credential",
      label: "QNAP credential",
      allowedDestinations: ["192.168.2.240", "qnap.local"],
      allowedProtocols: ["ssh", "https"],
      createdAt: 1,
      updatedAt: 2
    });
  });

  it("searches the local catalog by service and returns opaque metadata only", async () => {
    const client = new FakeClient([{
      type: "catalogSearchResult",
      result: {
        status: "FOUND",
        matches: [{
          index: {
            id: "0123456789ABCDEFGHJKMNPQRT",
            title: "QNAP",
            aliases: ["NAS"],
            tags: ["设备"]
          },
          entry: {
            id: "0123456789ABCDEFGHJKMNPQRV",
            indexId: "0123456789ABCDEFGHJKMNPQRT",
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: ["QNAP 登录"],
            endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
            fields: [
              { key: "username", label: "用户名", type: "text", value: "admin" },
              { key: "password", label: "密码", type: "secret", secretRef: reference }
            ],
            notes: "媒体管理",
            tags: ["QNAP"]
          }
        }]
      }
    }]);

    const result = await tool(client, "secret_search").handler({
      query: "qnap",
      field: "password",
      limit: 10
    });

    expect(result.structuredContent).toEqual({
      status: "FOUND",
      matches: [{
        index: {
          id: "0123456789ABCDEFGHJKMNPQRT",
          title: "QNAP",
          aliases: ["NAS"],
          tags: ["设备"]
        },
        entry: {
          id: "0123456789ABCDEFGHJKMNPQRV",
          indexId: "0123456789ABCDEFGHJKMNPQRT",
          title: "QNAP 管理后台登录",
          type: "credential",
          aliases: ["QNAP 登录"],
          endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
          fields: [
            { key: "username", label: "用户名", type: "text", value: "admin" },
            { key: "password", label: "密码", type: "secret", secretRef: reference }
          ],
          notes: "媒体管理",
          tags: ["QNAP"]
        }
      }]
    });
    expect(client.requests).toEqual([{
      type: "catalogSearch",
      query: "qnap",
      field: "password",
      limit: 10
    }]);
    const serialized = JSON.stringify(result.structuredContent);
    expect(serialized).not.toContain("plaintext-secret-value");
    expect(serialized).not.toContain("sensitive-index-selection");
    expect(serialized).not.toContain("line");
  });

  it("rejects empty catalog queries before touching IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_search").handler({ query: "   " })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("uses App-controlled authorization for metadata writes and never accepts catalog plaintext", async () => {
    const client = new FakeClient([
      { type: "catalogWriteResult", result: { revision: 2, entry: null } },
      { type: "catalogValidation", catalogStatus: "FOUND", revision: 2 }
    ]);

    const write = await tool(client, "secret_catalog_patch_metadata").handler({
      entryID: "0123456789ABCDEFGHJKMNPQRV",
      patch: { title: "QNAP 管理后台登录" },
      expectedRevision: 1
    });
    expect(write.structuredContent).toEqual({ revision: 2, entry: null });
    expect(client.requests[0]).toMatchObject({
      type: "catalogPatchMetadata",
      expectedRevision: 1,
    });
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");

    const validation = await tool(client, "secret_catalog_validate").handler({});
    expect(validation.structuredContent).toEqual({ status: "FOUND", revision: 2 });
    expect(client.requests[1]).toEqual({ type: "catalogValidate" });
  });

  it("creates a safe Entry in one call without a lease, reference, or plaintext", async () => {
    const client = new FakeClient([{
      type: "catalogWriteResult",
      result: {
        revision: 4,
        entry: {
          id: "0123456789ABCDEFGHJKMNPQRS",
          indexId: "0123456789ABCDEFGHJKMNPQRT",
          title: "音乐服务器",
          type: "credential",
          aliases: [],
          endpoints: [{ type: "http", host: "192.168.2.240", port: 4533 }],
          fields: [
            { key: "username", label: "用户名", type: "text", agentVisible: true, searchable: true, value: "zyk" },
            { key: "password", label: "密码", type: "secret", agentVisible: true, searchable: false }
          ],
          notes: null,
          tags: []
        }
      }
    } as IpcResponse]);

    const result = await tool(client, "secret_catalog_create_entry").handler({
      indexID: "0123456789ABCDEFGHJKMNPQRT",
      title: "音乐服务器",
      endpoints: [{ type: "http", host: "192.168.2.240", port: 4533 }],
      fields: [
        { key: "username", label: "用户名", type: "text", value: "zyk" },
        { key: "password", label: "密码", type: "secret", searchable: false }
      ]
    });

    expect(result.structuredContent).toEqual({
      status: "CREATED",
      entryID: "0123456789ABCDEFGHJKMNPQRS",
      revision: 4
    });
    expect(client.requests[0]).toMatchObject({
      type: "catalogCreateEntry",
      request: {
        indexID: "0123456789ABCDEFGHJKMNPQRT",
        title: "音乐服务器"
      }
    });
    expect(JSON.stringify(client.requests)).not.toContain("secretRef");
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");
  });

  it("rejects an existing secretRef on the direct safe create tool before IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_catalog_create_entry").handler({
      indexID: "0123456789ABCDEFGHJKMNPQRT",
      title: "危险绑定",
      fields: [{
        key: "password",
        label: "密码",
        type: "secret",
        secretRef: reference
      }]
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("does not send a draft containing a secret plaintext value", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_catalog_create_draft").handler({
      request: {
        indexID: "0123456789ABCDEFGHJKMNPQRT",
        title: "QNAP",
        fields: [{ key: "password", label: "密码", type: "secret", value: "plaintext" }]
      }
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("sends SSH actions as opaque descriptors and preserves the agent hint", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "qnap", stderr: "" })]);
    const result = await tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname",
      agentAssessment: {
        declaredRisk: "silent",
        reason: "read QNAP status",
        intendedEffect: "read-only"
      }
    });

    expect(result.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor).toMatchObject({
      actionType: "sshCommand",
      secretReferences: [reference],
      destination: "qnap.local",
      command: "hostname",
      protocolType: "ssh",
      agentAssessment: { declaredRisk: "silent" }
    });
    expect(JSON.stringify(request)).not.toContain("plaintext-secret-value");
    expect(JSON.stringify(request)).not.toContain("restoreReferences");
  });

  it("does not let a low agent hint hide a dangerous SSH command", async () => {
    const client = new FakeClient([{ type: "failure", code: "OPERATION_DENIED" }]);
    const result = await tool(client, "ssh_command_with_secret").handler({
      host: "192.168.2.240",
      passwordRef: reference,
      command: "rm -rf /volume1/@tmp",
      agentAssessment: {
        declaredRisk: "silent",
        reason: "maintenance",
        intendedEffect: "read-only"
      }
    });

    expect(result.structuredContent).toEqual({ status: "OPERATION_DENIED" });
    expect(client.requests[0].type).toBe("executeSecretOperation");
  });

  it("carries HTTP method and destination into the operation descriptor", async () => {
    const client = new FakeClient([operationResponse({ httpStatus: 200, contentType: "application/json" })]);
    await tool(client, "api_request_with_token").handler({
      url: "https://qnap.local/api/status",
      method: "POST",
      tokenRef: reference,
      body: "{\"probe\":true}"
    });

    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor).toMatchObject({
      actionType: "apiRequest",
      destination: "qnap.local",
      httpMethod: "POST",
      url: "https://qnap.local/api/status",
      requestedEffects: ["remote-write"]
    });
  });

  it("rejects credential-shaped URLs and secret references in API bodies", async () => {
    const urlClient = new FakeClient([]);
    const urlResult = await tool(urlClient, "api_request_with_token").handler({
      url: "https://qnap.local/api?token=secret",
      tokenRef: reference
    });
    expect(urlResult.structuredContent).toEqual({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
    expect(urlClient.requests).toHaveLength(0);

    const bodyClient = new FakeClient([]);
    const bodyResult = await tool(bodyClient, "api_request_with_token").handler({
      url: "https://qnap.local/api",
      tokenRef: reference,
      body: `value=${reference}`
    });
    expect(bodyResult.structuredContent).toEqual({ status: "PLAINTEXT_REFERENCE_NOT_ALLOWED" });
    expect(bodyClient.requests).toHaveLength(0);
  });

  it("uses operation descriptors for database and SFTP actions", async () => {
    const client = new FakeClient([
      operationResponse({ rowCount: 1, rowsPreview: "hostname" }),
      operationResponse({ listingPreview: "file.txt" })
    ]);

    await tool(client, "database_query_with_secret").handler({
      engine: "postgres",
      host: "qnap.local",
      database: "postgres",
      username: "admin",
      passwordRef: reference,
      query: "SELECT hostname FROM status"
    });
    await tool(client, "sftp_transfer_with_secret").handler({
      operation: "list",
      host: "qnap.local",
      remotePath: "/share",
      passwordRef: reference
    });

    expect(client.requests).toHaveLength(2);
    expect(client.requests.every((request) => request.type === "executeSecretOperation")).toBe(true);
    const database = client.requests[0];
    if (database.type === "executeSecretOperation") {
      expect(database.descriptor.databaseStatement).toMatch(/^SELECT/i);
    }
    const sftp = client.requests[1];
    if (sftp.type === "executeSecretOperation") {
      expect(sftp.descriptor.fileOperation).toBe("list");
    }
  });

  it("keeps local reveal as an app-owned request and never asks MCP for plaintext", async () => {
    const client = new FakeClient([{ type: "revealSessionOpened", sessionID: "session-1" }]);
    const result = await tool(client, "secret_reveal_request").handler({
      reference,
      reason: "show it in the local app"
    });

    expect(result.structuredContent).toEqual({ status: "DISPLAYED_TO_USER" });
    expect(client.requests[0].type).toBe("revealReferences");
    expect(client.requests.some((request) => request.type === "restoreReferences")).toBe(false);
  });

  it("states the risk-aware workflow without a global unlock instruction", async () => {
    const result = await tool(new FakeClient([]), "agent_secret_usage_policy").handler({});
    const policy = result.structuredContent as { safeWorkflow: string[]; forbidden: string[] };
    expect(policy.safeWorkflow.join(" ")).not.toMatch(/unlock/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/locked/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/secret_search/);
    expect(policy.safeWorkflow.join(" ")).toMatch(/Index.*Entry|entry-centric/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/secret_catalog_validate/);
    expect(policy.catalogPolicy).toMatch(/敏感信息\.md/);
    expect(policy.catalogPolicy).toMatch(/Index.*Entry.*Field|Index.*Entry\/SubIndex/);
    expect(policy.catalogPolicy).toMatch(/直接修改|直接写入/);
    expect(policy.catalogPolicy).toMatch(/placeholder/);
    expect(policy.forbidden.join(" ")).toMatch(/plaintext|shell|environment/i);
  });
});
