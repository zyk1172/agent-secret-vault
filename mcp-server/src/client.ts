import { readFile, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import {
  AuthenticatedIpcRequest,
  AgentCallerIdentity,
  CapabilityToken,
  IpcFrameCodec,
  IpcRequest,
  IpcResponse
} from "./protocol.js";

export interface IpcPaths {
  directory: string;
  socket: string;
  token: string;
}

export interface LocalIpcClientOptions {
  socketPath?: string;
  tokenPath?: string;
  unavailableRetryCount?: number;
  unavailableRetryDelayMs?: number;
  requestTimeoutMs?: number;
  declaredCaller?: AgentCallerIdentity;
}

const DEFAULT_UNAVAILABLE_RETRY_COUNT = 8;
const DEFAULT_UNAVAILABLE_RETRY_DELAY_MS = 500;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

export function appSupportIpcPaths(): IpcPaths {
  const directory = path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "AgentSecretVault",
    "IPC"
  );

  return {
    directory,
    socket: path.join(directory, "agent-secret-vault.sock"),
    token: path.join(directory, "capability.token")
  };
}

export class LocalIpcClient {
  private readonly socketPath: string;
  private readonly tokenPath: string;
  private readonly unavailableRetryCount: number;
  private readonly unavailableRetryDelayMs: number;
  private readonly requestTimeoutMs: number;
  private readonly declaredCaller?: AgentCallerIdentity;

  constructor(options: LocalIpcClientOptions = {}) {
    const defaults = appSupportIpcPaths();
    this.socketPath = options.socketPath ?? defaults.socket;
    this.tokenPath = options.tokenPath ?? defaults.token;
    this.unavailableRetryCount = options.unavailableRetryCount ?? DEFAULT_UNAVAILABLE_RETRY_COUNT;
    this.unavailableRetryDelayMs = options.unavailableRetryDelayMs ?? DEFAULT_UNAVAILABLE_RETRY_DELAY_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.declaredCaller = options.declaredCaller;
  }

  static async readCapabilityToken(tokenPath: string): Promise<CapabilityToken> {
    const tokenStat = await stat(tokenPath);
    const permissionBits = tokenStat.mode & 0o777;
    if ((permissionBits & 0o077) !== 0) {
      throw new Error("token file permissions allow non-owner access");
    }

    if (typeof process.getuid === "function" && tokenStat.uid !== process.getuid()) {
      throw new Error("token file owner does not match current user");
    }

    const token = (await readFile(tokenPath, "utf8")).trim();
    return CapabilityToken.parse(token);
  }

  async request(request: IpcRequest, caller?: AgentCallerIdentity): Promise<IpcResponse> {
    const parsedRequest = IpcRequest.parse(request);
    for (let attempt = 0; attempt <= this.unavailableRetryCount; attempt += 1) {
      const response = await this.requestOnce(parsedRequest, caller ?? this.declaredCaller);
      if (
        response.type !== "failure" ||
        response.code !== "APP_UNAVAILABLE" ||
        attempt >= this.unavailableRetryCount
      ) {
        return response;
      }
      await delay(this.unavailableRetryDelayMs);
    }

    return { type: "failure", code: "APP_UNAVAILABLE" };
  }

  private async requestOnce(
    parsedRequest: IpcRequest,
    caller?: AgentCallerIdentity
  ): Promise<IpcResponse> {
    let token: CapabilityToken;
    try {
      token = await LocalIpcClient.readCapabilityToken(this.tokenPath);
    } catch (error) {
      if (isUnavailableError(error)) {
        return { type: "failure", code: "APP_UNAVAILABLE" };
      }
      throw error;
    }

    const authenticatedRequest = AuthenticatedIpcRequest.parse({
      capabilityToken: token,
      ...(caller === undefined ? {} : { caller }),
      request: parsedRequest
    });

    try {
      const responseFrame = await sendFramedRequest(
        this.socketPath,
        IpcFrameCodec.encode(authenticatedRequest),
        this.requestTimeoutMs
      );
      return IpcFrameCodec.decode(responseFrame, IpcResponse);
    } catch (error) {
      if (isUnavailableError(error)) {
        return { type: "failure", code: "APP_UNAVAILABLE" };
      }
      throw error;
    }
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function sendFramedRequest(
  socketPath: string,
  requestFrame: Buffer,
  timeoutMs: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks: Buffer[] = [];
    let settled = false;

    const settle = (callback: () => void) => {
      if (!settled) {
        settled = true;
        callback();
      }
      socket.destroy();
    };

    socket.setTimeout(timeoutMs, () => {
      settle(() => reject(new Error("IPC request timed out.")));
    });

    socket.on("connect", () => {
      socket.end(requestFrame);
    });
    socket.on("data", (chunk) => {
      chunks.push(chunk);
    });
    socket.on("end", () => {
      settle(() => resolve(Buffer.concat(chunks)));
    });
    socket.on("error", (error) => {
      settle(() => reject(error));
    });
  });
}

function isUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const errorWithCode = error as NodeJS.ErrnoException;
  return (
    errorWithCode.code === "ENOENT" ||
    errorWithCode.code === "ECONNREFUSED" ||
    errorWithCode.code === "ENOTSOCK" ||
    errorWithCode.code === "EACCES"
  );
}
