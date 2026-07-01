import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { type IpcRequest, type IpcResponse } from "../src/protocol.js";
import {
  createMcpServer,
  createVaultToolDefinitions,
  defaultSecretLocalActionPolicy,
  type SecretBrowserLoginRunner,
  type SecretDatabaseRunner,
  type SecretFileTransferRunner,
  type SecretLocalAppFillRunner,
  type SecretSshRunner,
  type VaultIpcClient
} from "../src/server.js";

const validReference = "secret://0123456789ABCDEFGHJKMNPQRS";

describe("MCP tool contracts", () => {
  it("registers only non-plaintext tools", () => {
    const tools = createVaultToolDefinitions(new FakeClient([]));

    expect(tools.map((tool) => tool.name).sort()).toEqual([
      "agent_secret_usage_policy",
      "api_request_with_token",
      "browser_web_login_with_secret",
      "database_query_with_secret",
      "export_resolved_text_to_local_file",
      "local_app_form_fill_with_secret",
      "local_http_request_with_secret",
      "paragraph_reveal_request",
      "secret_action_router",
      "secret_auto_handle_text",
      "secret_create_request",
      "secret_inspect_reference",
      "secret_reveal_request",
      "secure_execute",
      "sftp_transfer_with_secret",
      "ssh_command_with_secret",
      "vault_status"
    ]);
    for (const tool of tools) {
      expect(tool.description).toMatch(/plaintext is never returned/i);
    }
  });

  it("serves MCP tool calls without SDK Zod output-schema failures", async () => {
    const mcpServer = createMcpServer(
      new FakeClient([
        { type: "status", locked: false },
        {
          type: "referenceMetadata",
          metadata: {
            reference: validReference,
            policy: "read",
            label: "NAS credential",
            createdAt: 1,
            updatedAt: 2
          }
        }
      ])
    );
    const mcpClient = new Client({ name: "hermes-compat-test", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    try {
      await Promise.all([
        mcpClient.connect(clientTransport),
        mcpServer.connect(serverTransport)
      ]);

      const tools = await mcpClient.listTools();
      expect(tools.tools.map((tool) => tool.name)).toContain("vault_status");

      const status = await mcpClient.callTool({ name: "vault_status", arguments: {} });
      expect(status.isError).not.toBe(true);
      expect(status.structuredContent).toEqual({ locked: false });

      const metadata = await mcpClient.callTool({
        name: "secret_inspect_reference",
        arguments: { reference: validReference }
      });
      expect(metadata.isError).not.toBe(true);
      expect(metadata.structuredContent).toMatchObject({
        reference: validReference,
        policy: "read",
        label: "NAS credential"
      });
      expect(JSON.stringify([status, metadata])).not.toContain("_zod");
    } finally {
      await Promise.allSettled([mcpClient.close(), mcpServer.close()]);
    }
  });

  it("agent_secret_usage_policy gives generic agent rules without sensitive fields", async () => {
    const tool = getTool(new FakeClient([]), "agent_secret_usage_policy");

    const result = await tool.handler({});
    const resultJson = JSON.stringify(result.structuredContent);

    expect(result.structuredContent).toMatchObject({
      status: "OK",
      intendedClients: expect.arrayContaining(["Codex", "Claude", "Hermes"])
    });
    expect(resultJson).toContain("secret://");
    expect(resultJson).toContain("local_http_request_with_secret");
    expect(resultJson).not.toMatch(/qnap/i);
    expect(resultJson).not.toMatch(/decrypted value is/i);
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_auto_handle_text detects references and redacts text without contacting the app", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "secret_auto_handle_text");

    const result = await tool.handler({
      text: `登录密码是 ${validReference}，不要展示。`
    });

    expect(client.requests).toEqual([]);
    expect(result.structuredContent).toEqual({
      status: "REFERENCES_DETECTED",
      action: "KEEP_REFERENCES_OPAQUE",
      referenceCount: 1,
      references: [validReference],
      redactedText: "登录密码是 [SECRET_REFERENCE]，不要展示。"
    });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_auto_handle_text opens local paragraph reveal without returning decrypted content", async () => {
    const client = new FakeClient([{ type: "revealSessionOpened", sessionID: "session-1" }]);
    const tool = getTool(client, "secret_auto_handle_text");

    const result = await tool.handler({
      text: `账号段落：password ${validReference}`,
      intent: "reveal_to_user",
      reason: "用户要求查看整段"
    });

    expect(client.requests).toEqual([
      {
        type: "revealReferences",
        references: [validReference],
        context: {
          reason: "用户要求查看整段",
          template: "账号段落：password {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(result.structuredContent).toEqual({
      status: "DISPLAYED_TO_USER",
      action: "LOCAL_APP_REVEAL",
      referenceCount: 1,
      references: [validReference],
      redactedText: "账号段落：password [SECRET_REFERENCE]"
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("vault_status returns lock state without sensitive fields", async () => {
    const client = new FakeClient([{ type: "status", locked: false }]);
    const tool = getTool(client, "vault_status");

    const result = await tool.handler({});

    expect(client.requests).toEqual([{ type: "status" }]);
    expect(result.structuredContent).toEqual({ locked: false });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_inspect_reference returns metadata without plaintext", async () => {
    const client = new FakeClient([{
      type: "referenceMetadata",
      metadata: {
        reference: validReference,
        policy: "read",
        label: "local device password",
        createdAt: 1,
        updatedAt: 2
      }
    }]);
    const tool = getTool(client, "secret_inspect_reference");

    const result = await tool.handler({ reference: validReference });

    expect(client.requests).toEqual([
      { type: "inspectReference", reference: validReference }
    ]);
    expect(result.structuredContent).toEqual({
      reference: validReference,
      policy: "read",
      label: "local device password",
      createdAt: 1,
      updatedAt: 2
    });
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

  it("paragraph_reveal_request accepts raw text with repeated secret references", async () => {
    const client = new FakeClient([{ type: "revealSessionOpened", sessionID: "session-1" }]);
    const tool = getTool(client, "paragraph_reveal_request");

    const result = await tool.handler({
      text: `主密码 ${validReference}，确认密码 ${validReference}`,
      reason: "本机显示重复引用段落"
    });

    expect(client.requests).toEqual([
      {
        type: "revealReferences",
        references: [validReference, validReference],
        context: {
          reason: "本机显示重复引用段落",
          template: "主密码 {{0}}，确认密码 {{1}}",
          ranges: [
            { index: 0, placeholder: "{{0}}" },
            { index: 1, placeholder: "{{1}}" }
          ]
        }
      }
    ]);
    expect(result.structuredContent).toEqual({ status: "DISPLAYED_TO_USER" });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("export_resolved_text_to_local_file asks the app to write locally and returns only path", async () => {
    const references = [validReference];
    const destinationPath = "/Users/example/Desktop/NAS.md";
    const client = new FakeClient([{ type: "exported", path: destinationPath }]);
    const tool = getTool(client, "export_resolved_text_to_local_file");

    const result = await tool.handler({
      references,
      template: "NAS password: {{0}}",
      reason: "用户明确要求由 App 写入本地文件",
      destinationPath
    });

    expect(client.requests).toEqual([
      {
        type: "exportResolvedText",
        references,
        destinationPath,
        context: {
          reason: "用户明确要求由 App 写入本地文件",
          template: "NAS password: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(result.structuredContent).toEqual({ status: "EXPORTED", path: destinationPath });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("export_resolved_text_to_local_file accepts raw text with secret references", async () => {
    const destinationPath = "/Users/example/Desktop/nas-test.md";
    const client = new FakeClient([{ type: "exported", path: destinationPath }]);
    const tool = getTool(client, "export_resolved_text_to_local_file");

    const result = await tool.handler({
      text: `NAS 密码：${validReference}`,
      reason: "用户明确要求由 App 写入本地文件",
      destinationPath
    });

    expect(client.requests).toEqual([
      {
        type: "exportResolvedText",
        references: [validReference],
        destinationPath,
        context: {
          reason: "用户明确要求由 App 写入本地文件",
          template: "NAS 密码：{{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(result.structuredContent).toEqual({ status: "EXPORTED", path: destinationPath });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
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

  it("ssh_command_with_secret uses restored password internally and returns sanitized output", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const sshCalls: unknown[] = [];
    const tool = getTool(client, "ssh_command_with_secret", {
      sshRunner: async (request) => {
        sshCalls.push(request);
        return {
          exitCode: 0,
          stdout: `host=NAS-zyk\npassword=LOCAL_PASSWORD_CANARY\n`,
          stderr: ""
        };
      }
    });

    const result = await tool.handler({
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      command: "hostname && whoami && uptime",
      risk: "read"
    });

    expect(client.requests).toEqual([
      {
        type: "restoreReferences",
        references: [validReference],
        context: {
          reason: "Use SSH password for local device",
          template: "{{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(JSON.stringify(sshCalls)).toContain("LOCAL_PASSWORD_CANARY");
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      exitCode: 0,
      stdout: "host=NAS-zyk\npassword=[REDACTED_SECRET]\n",
      stderr: "",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("ssh_command_with_secret rejects public hosts and dangerous commands before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "ssh_command_with_secret");

    const publicHost = await tool.handler({
      host: "example.com",
      username: "zyk",
      passwordRef: validReference,
      command: "hostname"
    });
    const dangerousCommand = await tool.handler({
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      command: "rm -rf /"
    });

    expect(client.requests).toEqual([]);
    expect(publicHost.structuredContent).toEqual({ status: "HOST_NOT_ALLOWED" });
    expect(dangerousCommand.structuredContent).toEqual({ status: "COMMAND_NOT_ALLOWED" });
  });

  it("ssh_command_with_secret returns app failure status when secret resolution fails", async () => {
    const client = new FakeClient([
      { type: "failure", code: "APP_UNAVAILABLE" }
    ]);
    const tool = getTool(client, "ssh_command_with_secret");

    const result = await tool.handler({
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      command: "hostname"
    });

    expect(result.structuredContent).toEqual({ status: "APP_UNAVAILABLE" });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("ssh_command_with_secret uses injectable policy instead of app-owned command rules", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const tool = getTool(client, "ssh_command_with_secret", {
      policy: {
        ...defaultSecretLocalActionPolicy,
        hosts: {
          ...defaultSecretLocalActionPolicy.hosts,
          allowPrivateIPv4: false,
          allowedHosts: ["example.com"]
        },
        ssh: {
          ...defaultSecretLocalActionPolicy.ssh,
          blockedCommandNames: []
        }
      },
      sshRunner: async () => ({
        exitCode: 0,
        stdout: "ok",
        stderr: ""
      })
    });

    const result = await tool.handler({
      host: "example.com",
      username: "zyk",
      passwordRef: validReference,
      command: "rm --version",
      risk: "read"
    });

    expect(client.requests).toHaveLength(1);
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      exitCode: 0,
      stdout: "ok",
      stderr: "",
      redacted: true
    });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("secret_action_router dispatches SSH actions without returning secrets", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const sshRunner: SecretSshRunner = async () => ({
      exitCode: 0,
      stdout: "ok LOCAL_PASSWORD_CANARY",
      stderr: ""
    });
    const tool = getTool(client, "secret_action_router", { sshRunner });

    const result = await tool.handler({
      intent: "ssh_command",
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      command: "hostname",
      risk: "read"
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      exitCode: 0,
      stdout: "ok [REDACTED_SECRET]",
      stderr: "",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("local_http_request_with_secret uses restored password internally without returning it", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const fetchCalls: unknown[] = [];
    const tool = getTool(client, "local_http_request_with_secret", {
      fetch: async (url, init) => {
        fetchCalls.push({ url, init });
        return {
          status: 200,
          headers: {
            get: (name: string) => name.toLowerCase() === "content-type"
              ? "text/plain; password=LOCAL_PASSWORD_CANARY"
              : null
          },
          text: async () => "status ok password=LOCAL_PASSWORD_CANARY Authorization: Basic enl..."
        };
      }
    });

    const result = await tool.handler({
      url: "http://192.168.2.240:8080/status",
      username: "zyk",
      passwordRef: validReference,
      includeBodyPreview: true
    });

    expect(client.requests).toEqual([
      {
        type: "restoreReferences",
        references: [validReference],
        context: {
          reason: "Use local device password",
          template: "{{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(JSON.stringify(fetchCalls)).toContain("Basic");
    expect(JSON.stringify(fetchCalls)).not.toContain("LOCAL_PASSWORD_CANARY");
    expect(JSON.stringify(fetchCalls)).toContain('"redirect":"manual"');
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: "text/plain; password=[REDACTED_SECRET]",
      redacted: true,
      bodyPreview: "status ok password=[REDACTED_SECRET] Authorization: Basic [REDACTED_SECRET]..."
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("local_http_request_with_secret rejects incomplete auth before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "local_http_request_with_secret");

    const passwordOnly = await tool.handler({
      url: "http://192.168.2.240:8080/status",
      passwordRef: validReference
    });
    const usernameOnly = await tool.handler({
      url: "http://192.168.2.240:8080/status",
      usernameRef: validReference
    });

    expect(client.requests).toEqual([]);
    expect(passwordOnly.structuredContent).toEqual({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
    expect(usernameOnly.structuredContent).toEqual({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
  });

  it("local_http_request_with_secret returns app failure status when secret resolution fails", async () => {
    const client = new FakeClient([
      { type: "failure", code: "APP_UNAVAILABLE" }
    ]);
    const tool = getTool(client, "local_http_request_with_secret");

    const result = await tool.handler({
      url: "http://192.168.2.240:8080/status",
      username: "zyk",
      passwordRef: validReference
    });

    expect(result.structuredContent).toEqual({ status: "APP_UNAVAILABLE" });
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("local_http_request_with_secret redacts derived basic auth and url encoded variants", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "user@example.local" },
      { type: "restoredText", text: "p@ss word" }
    ]);
    const derivedBasic = Buffer.from("user@example.local:p@ss word", "utf8").toString("base64");
    const tool = getTool(client, "local_http_request_with_secret", {
      fetch: async () => ({
        status: 200,
        headers: { get: () => null },
        text: async () =>
          `authorization=Basic ${derivedBasic} user=user%40example.local password=p%40ss%20word Bearer abc123 Set-Cookie: sid=abc`
      })
    });

    const result = await tool.handler({
      url: "http://192.168.2.240:8080/status",
      usernameRef: validReference,
      passwordRef: validReference,
      includeBodyPreview: true
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: null,
      redacted: true,
      bodyPreview:
        "authorization=Basic [REDACTED_SECRET] user=[REDACTED_SECRET] password=[REDACTED_SECRET] Bearer abc123 Set-Cookie=[REDACTED_SECRET]"
    });
    expect(JSON.stringify(result)).not.toContain(derivedBasic);
    expect(JSON.stringify(result)).not.toContain("user%40example.local");
    expect(JSON.stringify(result)).not.toContain("p%40ss%20word");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("local_http_request_with_secret rejects public URLs before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "local_http_request_with_secret");

    const result = await tool.handler({
      url: "https://example.com/status",
      username: "zyk",
      passwordRef: validReference
    });

    expect(client.requests).toEqual([]);
    expect(result.structuredContent).toEqual({ status: "URL_NOT_ALLOWED" });
  });

  it("secret_action_router dispatches HTTP and export actions", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" },
      { type: "exported", path: "/Users/example/Desktop/out.md" }
    ]);
    const tool = getTool(client, "secret_action_router", {
      fetch: async () => ({
        status: 204,
        headers: { get: () => "text/plain" },
        text: async () => ""
      })
    });

    const httpResult = await tool.handler({
      intent: "local_http_request",
      url: "http://192.168.2.240/status",
      username: "zyk",
      passwordRef: validReference
    });
    const exportResult = await tool.handler({
      intent: "export_resolved_text",
      references: [validReference],
      template: "Token: {{0}}",
      reason: "导出本地文件",
      destinationPath: "/Users/example/Desktop/out.md"
    });

    expect(httpResult.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 204,
      contentType: "text/plain",
      redacted: true
    });
    expect(exportResult.structuredContent).toEqual({
      status: "EXPORTED",
      path: "/Users/example/Desktop/out.md"
    });
    expectForbiddenKeysAbsent(httpResult.structuredContent);
    expectForbiddenKeysAbsent(exportResult.structuredContent);
  });

  it("api_request_with_token uses restored token internally and redacts token echoes", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "API_TOKEN_CANARY" }
    ]);
    const fetchCalls: unknown[] = [];
    const tool = getTool(client, "api_request_with_token", {
      fetch: async (url, init) => {
        fetchCalls.push({ url, init });
        return {
          status: 200,
          headers: {
            get: (name: string) => name.toLowerCase() === "content-type"
              ? "application/json; token=API_TOKEN_CANARY"
              : null
          },
          text: async () => "ok Authorization: Bearer API_TOKEN_CANARY token=API_TOKEN_CANARY"
        };
      }
    });

    const result = await tool.handler({
      url: "http://192.168.2.240:8080/api/status",
      tokenRef: validReference,
      includeBodyPreview: true
    });

    expect(client.requests).toEqual([
      {
        type: "restoreReferences",
        references: [validReference],
        context: {
          reason: "Use API token for restricted local/API request",
          template: "{{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      }
    ]);
    expect(JSON.stringify(fetchCalls)).toContain("API_TOKEN_CANARY");
    expect(JSON.stringify(fetchCalls)).toContain('"redirect":"manual"');
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: "application/json; token=[REDACTED_SECRET]",
      redacted: true,
      bodyPreview: "ok Authorization: Bearer [REDACTED_SECRET] token=[REDACTED_SECRET]"
    });
    expect(JSON.stringify(result)).not.toContain("API_TOKEN_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("api_request_with_token rejects public URLs and token query params before resolving", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "api_request_with_token");

    const publicUrl = await tool.handler({
      url: "https://example.com/v1/status",
      tokenRef: validReference
    });
    const tokenQuery = await tool.handler({
      url: "http://192.168.2.240:8080/status?token=raw",
      tokenRef: validReference
    });

    expect(client.requests).toEqual([]);
    expect(publicUrl.structuredContent).toEqual({ status: "URL_NOT_ALLOWED" });
    expect(tokenQuery.structuredContent).toEqual({ status: "URL_TOKEN_NOT_ALLOWED" });
  });

  it("database_query_with_secret uses restored password internally and redacts rows", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const dbCalls: unknown[] = [];
    const databaseRunner: SecretDatabaseRunner = async (request) => {
      dbCalls.push(request);
      return {
        rowCount: 1,
        rowsPreview: "user=zyk password=LOCAL_PASSWORD_CANARY json={\"token\":\"API_TOKEN_CANARY\"}",
        stderr: "notice token=LOCAL_PASSWORD_CANARY"
      };
    };
    const tool = getTool(client, "database_query_with_secret", { databaseRunner });

    const result = await tool.handler({
      engine: "postgres",
      host: "192.168.2.240",
      database: "app",
      username: "zyk",
      passwordRef: validReference,
      query: "select current_user"
    });

    expect(JSON.stringify(dbCalls)).toContain("LOCAL_PASSWORD_CANARY");
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      rowCount: 1,
      rowsPreview: "user=zyk password=[REDACTED_SECRET] json={\"token\":\"[REDACTED_SECRET]\"}",
      stderr: "notice token=[REDACTED_SECRET]",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expect(JSON.stringify(result)).not.toContain("API_TOKEN_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("database_query_with_secret rejects unsafe SQL before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "database_query_with_secret");

    const result = await tool.handler({
      engine: "postgres",
      host: "192.168.2.240",
      database: "app",
      username: "zyk",
      passwordRef: validReference,
      query: "drop table users"
    });

    expect(client.requests).toEqual([]);
    expect(result.structuredContent).toEqual({ status: "QUERY_NOT_ALLOWED" });
  });

  it("sftp_transfer_with_secret uses restored password internally and redacts runner output", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const transferCalls: unknown[] = [];
    const fileTransferRunner: SecretFileTransferRunner = async (request) => {
      transferCalls.push(request);
      return {
        listingPreview: "secret.txt password=LOCAL_PASSWORD_CANARY",
        stderr: "ok"
      };
    };
    const tool = getTool(client, "sftp_transfer_with_secret", { fileTransferRunner });

    const result = await tool.handler({
      operation: "list",
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      remotePath: "/share/CACHEDEV1_DATA"
    });

    expect(JSON.stringify(transferCalls)).toContain("LOCAL_PASSWORD_CANARY");
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      listingPreview: "secret.txt password=[REDACTED_SECRET]",
      stderr: "ok",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("sftp_transfer_with_secret rejects unsafe paths before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "sftp_transfer_with_secret");

    const result = await tool.handler({
      operation: "download",
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      remotePath: "../etc/passwd",
      localPath: "/tmp/passwd"
    });

    expect(client.requests).toEqual([]);
    expect(result.structuredContent).toEqual({ status: "PATH_NOT_ALLOWED" });
  });

  it("browser_web_login_with_secret fills through a runner without returning credentials", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const browserCalls: unknown[] = [];
    const browserLoginRunner: SecretBrowserLoginRunner = async (request) => {
      browserCalls.push(request);
      return { url: "http://192.168.2.240/login", note: "filled password=LOCAL_PASSWORD_CANARY" };
    };
    const tool = getTool(client, "browser_web_login_with_secret", { browserLoginRunner });

    const result = await tool.handler({
      url: "http://192.168.2.240/login",
      username: "zyk",
      passwordRef: validReference,
      usernameSelector: "#user",
      passwordSelector: "#password",
      submitSelector: "button[type=submit]",
      submit: true
    });

    expect(JSON.stringify(browserCalls)).toContain("LOCAL_PASSWORD_CANARY");
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      url: "http://192.168.2.240/login",
      note: "filled password=[REDACTED_SECRET]",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("browser_web_login_with_secret rejects public login URLs before resolving secrets", async () => {
    const client = new FakeClient([]);
    const tool = getTool(client, "browser_web_login_with_secret");

    const result = await tool.handler({
      url: "https://example.com/login",
      username: "zyk",
      passwordRef: validReference,
      passwordSelector: "#password"
    });

    expect(client.requests).toEqual([]);
    expect(result.structuredContent).toEqual({ status: "URL_NOT_ALLOWED" });
  });

  it("local_app_form_fill_with_secret fills through a runner without returning field values", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const appCalls: unknown[] = [];
    const localAppFillRunner: SecretLocalAppFillRunner = async (request) => {
      appCalls.push(request);
      return {
        filledFields: request.fields.map((field) => field.name),
        note: "filled secret=LOCAL_PASSWORD_CANARY"
      };
    };
    const tool = getTool(client, "local_app_form_fill_with_secret", { localAppFillRunner });

    const result = await tool.handler({
      bundleId: "com.example.Client",
      fields: [
        { name: "用户名", value: "zyk" },
        { name: "密码", valueRef: validReference }
      ],
      submitButton: "登录"
    });

    expect(JSON.stringify(appCalls)).toContain("LOCAL_PASSWORD_CANARY");
    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      filledFields: ["用户名", "密码"],
      note: "filled secret=[REDACTED_SECRET]",
      redacted: true
    });
    expect(JSON.stringify(result)).not.toContain("LOCAL_PASSWORD_CANARY");
    expectForbiddenKeysAbsent(result.structuredContent);
  });

  it("new action router intents dispatch to API, database, transfer, browser, and app handlers", async () => {
    const client = new FakeClient([
      { type: "restoredText", text: "API_TOKEN_CANARY" },
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" },
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" },
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" },
      { type: "restoredText", text: "LOCAL_PASSWORD_CANARY" }
    ]);
    const tool = getTool(client, "secret_action_router", {
      fetch: async () => ({ status: 204, headers: { get: () => null }, text: async () => "" }),
      databaseRunner: async () => ({ rowCount: 0 }),
      fileTransferRunner: async () => ({ listingPreview: "ok" }),
      browserLoginRunner: async () => ({ note: "ok" }),
      localAppFillRunner: async () => ({ filledFields: ["密码"] })
    });

    const apiResult = await tool.handler({
      intent: "api_request",
      url: "http://192.168.2.240/api",
      tokenRef: validReference
    });
    const dbResult = await tool.handler({
      intent: "database_query",
      engine: "postgres",
      host: "192.168.2.240",
      database: "app",
      username: "zyk",
      passwordRef: validReference,
      query: "select 1"
    });
    const transferResult = await tool.handler({
      intent: "sftp_transfer",
      operation: "list",
      host: "192.168.2.240",
      username: "zyk",
      passwordRef: validReference,
      remotePath: "/share"
    });
    const browserResult = await tool.handler({
      intent: "browser_web_login",
      url: "http://192.168.2.240/login",
      username: "zyk",
      passwordRef: validReference,
      passwordSelector: "#password"
    });
    const appResult = await tool.handler({
      intent: "local_app_form_fill",
      appName: "Client",
      fields: [{ name: "密码", valueRef: validReference }]
    });

    expect(apiResult.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    expect(dbResult.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    expect(transferResult.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    expect(browserResult.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    expect(appResult.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    expect(JSON.stringify([apiResult, dbResult, transferResult, browserResult, appResult]))
      .not.toMatch(/API_TOKEN_CANARY|LOCAL_PASSWORD_CANARY/);
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

function getTool(client: VaultIpcClient, name: string, options?: Parameters<typeof createVaultToolDefinitions>[1]) {
  const tool = createVaultToolDefinitions(client, options).find((candidate) => candidate.name === name);
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
