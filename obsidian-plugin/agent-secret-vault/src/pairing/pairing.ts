import type { z } from "zod";
import { IpcResponse } from "../ipc/protocol";

export type WorkbenchStatusResponse = Extract<z.infer<typeof IpcResponse>, { type: "workbenchStatus" }>;

export type Reachability =
  | { reachable: false }
  | { reachable: true; status: WorkbenchStatusResponse };

export function interpretWorkbenchStatus(input: Reachability): { canOperate: boolean; message: string } {
  if (!input.reachable) {
    return { canOperate: false, message: "Agent Secret Vault is unavailable." };
  }
  if (input.status.status.locked) {
    return { canOperate: false, message: "Unlock Agent Secret Vault to continue." };
  }
  if (!input.status.status.ipcAvailable) {
    return { canOperate: false, message: "Agent Secret Vault IPC is unavailable." };
  }
  return { canOperate: true, message: "Agent Secret Vault is ready." };
}
