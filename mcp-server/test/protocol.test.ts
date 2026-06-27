import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuthenticatedIpcRequest,
  CapabilityToken,
  IpcFrameCodec,
  IpcRequest,
  IpcResponse
} from "../src/protocol.js";
import {
  LocalIpcClient,
  appSupportIpcPaths
} from "../src/client.js";

const validReference = "secret://0123456789ABCDEFGHJKMNPQRS";
const validToken = Buffer.alloc(32, 0x4d).toString("base64");

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

describe("IPC response schema", () => {
  it("accepts every Swift IPCResponse case", () => {
    const fixtures = [
      { type: "status", locked: false },
      {
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      },
      { type: "displayedToUser" },
      { type: "created", reference: validReference },
      { type: "revealSessionOpened", sessionID: "session-1" },
      { type: "orphanScan", result: { missingRecords: [], unreferencedRecords: [] } },
      {
        type: "execution",
        result: { type: "completed", exitCode: 0, stdout: "ok [REDACTED_SECRET]", stderr: "" }
      },
      {
        type: "execution",
        result: { type: "quarantined", reason: "binaryOutput" }
      },
      { type: "failure", code: "APP_UNAVAILABLE" }
    ];

    for (const fixture of fixtures) {
      expect(IpcResponse.parse(fixture)).toEqual(fixture);
    }
  });

  it("rejects plaintext-shaped fields", () => {
    expect(() => IpcResponse.parse({ plaintext: "leak" })).toThrow();
    expect(() =>
      IpcResponse.parse({ type: "created", reference: validReference, plaintext: "leak" })
    ).toThrow();
    expect(() =>
      IpcResponse.parse({
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        },
        plaintext: "leak"
      })
    ).toThrow();
    expect(() =>
      IpcResponse.parse({
        type: "execution",
        result: {
          type: "completed",
          exitCode: 0,
          stdout: "",
          stderr: "",
          resolvedArguments: ["leak"]
        }
      })
    ).toThrow();
  });
});

describe("IPC request schema", () => {
  it("accepts every Swift IPCRequest case", () => {
    const fixtures = [
      { type: "status" },
      { type: "workbenchStatus" },
      { type: "reveal", reference: validReference, reason: "show to user" },
      { type: "encrypt", label: "api token", policy: "externalSend" },
      {
        type: "encryptText",
        plaintext: "local-only plaintext",
        label: null,
        policy: "credential"
      },
      {
        type: "revealReferences",
        references: [validReference],
        context: {
          reason: "Paragraph reveal",
          template: "Token: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      { type: "scanOrphans", markdownReferences: [validReference] },
      {
        type: "execute",
        request: {
          templateID: "send-message",
          executable: "/usr/bin/printf",
          values: { message: "hello" },
          secrets: { apiToken: validReference },
          destinationHost: "api.example.com",
          destinationPath: "/v1/send",
          requestedRisk: 2
        }
      }
    ];

    for (const fixture of fixtures) {
      expect(IpcRequest.parse(fixture)).toEqual(fixture);
    }
  });
});

describe("authenticated IPC request schema", () => {
  it("requires a base64 encoded 256-bit capability token", () => {
    const valid = AuthenticatedIpcRequest.parse({
      capabilityToken: validToken,
      request: { type: "status" }
    });

    expect(valid.capabilityToken).toBe(validToken);
    expect(() =>
      AuthenticatedIpcRequest.parse({
        capabilityToken: Buffer.alloc(31, 0x00).toString("base64"),
        request: { type: "status" }
      })
    ).toThrow();
  });

  it("accepts authenticated workbench request cases", () => {
    const requests = [
      { type: "workbenchStatus" },
      {
        type: "encryptText",
        plaintext: "local-only plaintext",
        label: null,
        policy: "credential"
      },
      {
        type: "revealReferences",
        references: [validReference],
        context: {
          reason: "Paragraph reveal",
          template: "Token: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      { type: "scanOrphans", markdownReferences: [validReference] }
    ];

    for (const request of requests) {
      const authenticated = { capabilityToken: validToken, request };
      expect(AuthenticatedIpcRequest.parse(authenticated)).toEqual(authenticated);
    }
  });
});

describe("IPC frame codec", () => {
  it("uses a four-byte big-endian length prefix and round trips JSON", () => {
    const frame = IpcFrameCodec.encode({ type: "status", locked: false });

    expect([...frame.subarray(0, 4)]).toEqual([0, 0, 0, frame.byteLength - 4]);
    expect(IpcFrameCodec.decode(frame, IpcResponse)).toEqual({ type: "status", locked: false });
  });

  it("rejects frames over one MiB", () => {
    const frame = Buffer.alloc(4 + 1_048_577, 0x41);
    frame.writeUInt32BE(1_048_577, 0);

    expect(() => IpcFrameCodec.decode(frame, IpcResponse)).toThrow(/frame too large/i);
  });
});

describe("local IPC client", () => {
  it("derives fixed app-support IPC paths", () => {
    const paths = appSupportIpcPaths();

    expect(paths.directory).toBe(
      path.join(os.homedir(), "Library", "Application Support", "AgentSecretVault", "IPC")
    );
    expect(paths.socket).toBe(path.join(paths.directory, "agent-secret-vault.sock"));
    expect(paths.token).toBe(path.join(paths.directory, "capability.token"));
  });

  it("rejects token files readable by non-owners", async () => {
    const directory = await makeTempDirectory();
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o644 });
    await chmod(tokenPath, 0o644);

    await expect(LocalIpcClient.readCapabilityToken(tokenPath)).rejects.toThrow(
      /token file permissions/i
    );
  });

  it("maps socket connection failures to APP_UNAVAILABLE", async () => {
    const directory = await makeTempDirectory();
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const client = new LocalIpcClient({
      socketPath: path.join(directory, "missing.sock"),
      tokenPath
    });

    await expect(client.request({ type: "status" })).resolves.toEqual({
      type: "failure",
      code: "APP_UNAVAILABLE"
    });
  });

  it("sends authenticated framed requests and validates framed responses", async () => {
    const directory = await makeTempDirectory();
    const socketPath = path.join(directory, "agent-secret-vault.sock");
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const server = net.createServer();
    const received = new Promise<unknown>((resolve, reject) => {
      server.on("connection", (socket) => {
        const chunks: Buffer[] = [];
        socket.on("data", (chunk) => chunks.push(chunk));
        socket.on("end", () => {
          try {
            resolve(IpcFrameCodec.decode(Buffer.concat(chunks), AuthenticatedIpcRequest));
            socket.end(IpcFrameCodec.encode({ type: "status", locked: false }));
          } catch (error) {
            reject(error);
          } finally {
            server.close();
          }
        });
      });
      server.on("error", reject);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
      server.listen(socketPath);
    });

    const client = new LocalIpcClient({ socketPath, tokenPath });
    const response = await client.request({ type: "status" });

    expect(response).toEqual({ type: "status", locked: false });
    await expect(received).resolves.toEqual({
      capabilityToken: validToken,
      request: { type: "status" }
    });
  });
});

async function makeTempDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "asv-mcp-"));
  temporaryDirectories.push(directory);
  return directory;
}
