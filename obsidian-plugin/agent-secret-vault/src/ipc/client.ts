import net from "node:net";
import { IpcRequest, IpcResponse } from "./protocol";

export class LocalVaultClient {
  constructor(private readonly socketPath: string) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    const payload = Buffer.from(JSON.stringify(request), "utf8");
    const frame = Buffer.alloc(4 + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    payload.copy(frame, 4);

    return await new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      const chunks: Buffer[] = [];
      socket.on("connect", () => socket.write(frame));
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.on("error", reject);
      socket.on("end", () => {
        const data = Buffer.concat(chunks);
        const length = data.readUInt32BE(0);
        const json = data.subarray(4, 4 + length).toString("utf8");
        resolve(IpcResponse.parse(JSON.parse(json)));
      });
    });
  }
}
