import type { z } from "zod";
import { IpcResponse } from "../ipc/protocol";

export type WorkbenchStatusResponse = Extract<z.infer<typeof IpcResponse>, { type: "workbenchStatus" }>;

export type Reachability =
  | { reachable: false }
  | { reachable: true; status: WorkbenchStatusResponse };

export function interpretWorkbenchStatus(input: Reachability): { canOperate: boolean; message: string } {
  if (!input.reachable) {
    return { canOperate: false, message: "SVLT 服务不可用。" };
  }
  if (input.status.status.locked) {
    return { canOperate: false, message: "请先解锁 SVLT。" };
  }
  if (!input.status.status.ipcAvailable) {
    return { canOperate: false, message: "SVLT 本机通道不可用。" };
  }
  return { canOperate: true, message: "SVLT 已就绪。" };
}
