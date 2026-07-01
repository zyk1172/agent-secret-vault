import type { AuthenticatedIpcRequest, IpcRequest, IpcResponse } from "./protocol";

const MAX_FRAME_BYTES = 1_048_576;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const SECRET_REFERENCE_PATTERN = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;

type NetModule = Pick<typeof import("node:net"), "createConnection">;
type NetSocket = import("node:net").Socket;
interface FsModule {
  readFileSync(path: string, encoding: BufferEncoding): string;
  statSync(path: string): { mode: number; uid: number };
}

export interface LocalVaultClientOptions {
  requestTimeoutMs?: number;
  netModule?: NetModule;
  fsModule?: FsModule;
  tokenPath?: string;
}

async function loadRuntimeNet(): Promise<NetModule> {
  const runtimeRequire = Function("return typeof require === 'function' ? require : undefined")() as
    | ((specifier: string) => NetModule)
    | undefined;
  if (runtimeRequire) {
    return runtimeRequire("node:net");
  }

  const runtimeImport = Function("specifier", "return import(specifier)") as (specifier: string) => Promise<NetModule>;
  return await runtimeImport("node:net");
}

async function loadRuntimeFs(): Promise<FsModule> {
  const runtimeRequire = Function("return typeof require === 'function' ? require : undefined")() as
    | ((specifier: string) => FsModule)
    | undefined;
  if (runtimeRequire) {
    return runtimeRequire("node:fs");
  }

  const runtimeImport = Function("specifier", "return import(specifier)") as (specifier: string) => Promise<FsModule>;
  return await runtimeImport("node:fs");
}

function parseIpcResponse(json: string): IpcResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("Invalid IPC response.");
  }

  if (!isRecord(parsed) || typeof parsed.type !== "string") {
    throw new Error("Unexpected IPC response.");
  }

  if (parsed.type === "created" && isSecretReference(parsed.reference)) {
    return { type: "created", reference: parsed.reference };
  }

  if (parsed.type === "failure" && typeof parsed.code === "string" && parsed.code.length > 0) {
    return { type: "failure", code: parsed.code };
  }

  if (parsed.type === "revealSessionOpened" && typeof parsed.sessionID === "string" && parsed.sessionID.length > 0) {
    return { type: "revealSessionOpened", sessionID: parsed.sessionID };
  }

  if (parsed.type === "restoredText" && typeof parsed.text === "string") {
    return { type: "restoredText", text: parsed.text };
  }

  if (parsed.type === "workbenchStatus" && isRecord(parsed.status)) {
    const status = parsed.status;
    if (
      typeof status.locked === "boolean" &&
      typeof status.ipcAvailable === "boolean" &&
      (typeof status.activeKnowledgeBaseRoot === "string" || status.activeKnowledgeBaseRoot === null) &&
      typeof status.pluginConnected === "boolean"
    ) {
      return {
        type: "workbenchStatus",
        status: {
          locked: status.locked,
          ipcAvailable: status.ipcAvailable,
          activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
          pluginConnected: status.pluginConnected
        }
      };
    }
  }

  if (parsed.type === "orphanScan" && isRecord(parsed.result)) {
    const result = parsed.result;
    if (isSecretReferenceArray(result.missingRecords) && isSecretReferenceArray(result.unreferencedRecords)) {
      return {
        type: "orphanScan",
        result: {
          missingRecords: result.missingRecords,
          unreferencedRecords: result.unreferencedRecords
        }
      };
    }
  }

  throw new Error("Unexpected IPC response.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isSecretReference(value: unknown): value is string {
  return typeof value === "string" && SECRET_REFERENCE_PATTERN.test(value);
}

function isSecretReferenceArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isSecretReference);
}

export class LocalVaultClient {
  private readonly requestTimeoutMs: number;
  private readonly netModule?: NetModule;
  private readonly fsModule?: FsModule;
  private readonly tokenPath: string;

  constructor(socketPath: string, options: LocalVaultClientOptions = {}) {
    this.socketPath = socketPath;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.netModule = options.netModule;
    this.fsModule = options.fsModule;
    this.tokenPath = options.tokenPath ?? socketPath.replace(/agent-secret-vault\.sock$/, "capability.token");
  }

  private readonly socketPath: string;

  async request(request: IpcRequest): Promise<IpcResponse> {
    const net = this.netModule ?? await loadRuntimeNet();
    const fs = this.fsModule ?? await loadRuntimeFs();
    const authenticatedRequest: AuthenticatedIpcRequest = {
      capabilityToken: this.readCapabilityToken(fs),
      request
    };
    const payload = Buffer.from(JSON.stringify(authenticatedRequest), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = Buffer.alloc(0);
      let settled = false;
      const timeout = setTimeout(() => {
        rejectWith(new Error("IPC request timed out."));
      }, this.requestTimeoutMs);

      const settle = (callback: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        callback();
        (socket as NetSocket).destroy();
      };

      const rejectWith = (error: unknown): void => {
        settle(() => reject(error instanceof Error ? error : new Error(String(error))));
      };

      const parseAvailableFrame = (): void => {
        if (buffer.length < 4) {
          return;
        }

        const length = buffer.readUInt32BE(0);
        if (length > MAX_FRAME_BYTES) {
          rejectWith(new Error("IPC frame exceeds maximum size."));
          return;
        }

        const frameLength = 4 + length;
        if (buffer.length < frameLength) {
          return;
        }

        try {
          const json = buffer.subarray(4, frameLength).toString("utf8");
          const response = parseIpcResponse(json);
          settle(() => resolve(response));
        } catch (error) {
          rejectWith(error);
        }
      };

      socket.on("connect", () => socket.write(frame));
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        parseAvailableFrame();
      });
      socket.on("error", rejectWith);
      socket.on("end", () => {
        if (!settled) {
          rejectWith(new Error("Incomplete IPC frame."));
        }
      });
    });
  }

  private readCapabilityToken(fs: FsModule): string {
    const tokenStat = fs.statSync(this.tokenPath);
    if ((tokenStat.mode & 0o077) !== 0) {
      throw new Error("IPC token permissions allow non-owner access.");
    }

    if (typeof process.getuid === "function" && tokenStat.uid !== process.getuid()) {
      throw new Error("IPC token owner does not match current user.");
    }

    return fs.readFileSync(this.tokenPath, "utf8").trim();
  }
}
