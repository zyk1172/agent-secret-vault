import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { LocalVaultClient } from "../src/ipc/client";

const openServers: net.Server[] = [];
const openSockets: net.Socket[] = [];
const temporaryDirectories: string[] = [];

function encodeFrame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

async function createSocketServer(onConnection: (socket: net.Socket) => void): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "asv-client-test-"));
  temporaryDirectories.push(directory);
  const socketPath = join(directory, "agent-secret-vault.sock");
  const server = net.createServer((socket) => {
    openSockets.push(socket);
    onConnection(socket);
  });
  openServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return socketPath;
}

async function expectWithin<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`timed out after ${milliseconds}ms`)), milliseconds);
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

afterEach(async () => {
  for (const socket of openSockets.splice(0)) {
    socket.destroy();
  }
  await Promise.all(openServers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("LocalVaultClient", () => {
  it("resolves after a complete response frame without waiting for socket end", async () => {
    const socketPath = await createSocketServer((socket) => {
      socket.on("data", () => {
        socket.write(encodeFrame({
          type: "workbenchStatus",
          status: {
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: null,
            pluginConnected: true
          }
        }));
      });
    });

    const client = new LocalVaultClient(socketPath);

    await expect(expectWithin(client.request({ type: "workbenchStatus" }), 100)).resolves.toEqual({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });
  });

  it("rejects short frames cleanly", async () => {
    const socketPath = await createSocketServer((socket) => {
      socket.write(Buffer.from([0x00, 0x00]));
      socket.end();
    });

    const client = new LocalVaultClient(socketPath);

    await expect(client.request({ type: "workbenchStatus" })).rejects.toThrow("Incomplete IPC frame");
  });
});
