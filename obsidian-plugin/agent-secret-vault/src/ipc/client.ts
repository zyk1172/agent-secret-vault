import net from "node:net";
import { IpcRequest, IpcResponse } from "./protocol";

const MAX_FRAME_BYTES = 1_048_576;

export class LocalVaultClient {
  constructor(private readonly socketPath: string) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    const payload = Buffer.from(JSON.stringify(request), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = Buffer.alloc(0);
      let settled = false;

      const settle = (callback: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        callback();
        socket.destroy();
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
          const response = IpcResponse.parse(JSON.parse(json));
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
}
