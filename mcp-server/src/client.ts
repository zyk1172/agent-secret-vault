import { readFile, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import {
  AuthenticatedIpcRequest,
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
}

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

  constructor(options: LocalIpcClientOptions = {}) {
    const defaults = appSupportIpcPaths();
    this.socketPath = options.socketPath ?? defaults.socket;
    this.tokenPath = options.tokenPath ?? defaults.token;
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

  async request(request: IpcRequest): Promise<IpcResponse> {
    const parsedRequest = IpcRequest.parse(request);
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
      request: parsedRequest
    });

    try {
      const responseFrame = await sendFramedRequest(
        this.socketPath,
        IpcFrameCodec.encode(authenticatedRequest)
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

function sendFramedRequest(socketPath: string, requestFrame: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks: Buffer[] = [];
    let settled = false;

    const settle = (callback: () => void) => {
      if (!settled) {
        settled = true;
        callback();
      }
    };

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
