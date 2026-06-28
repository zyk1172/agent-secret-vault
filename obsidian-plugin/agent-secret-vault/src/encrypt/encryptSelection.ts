import { replaceRange, type TextRange } from "../editor/selection";
import type { IpcRequest, IpcResponse } from "../ipc/protocol";

export interface VaultClientLike {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export async function encryptTextRange(input: {
  documentText: string;
  range: TextRange;
  label: string | null;
  policy: "credential" | "externalSend" | "read";
  client: VaultClientLike;
}): Promise<{ updatedText: string; reference: string }> {
  const response = await input.client.request({
    type: "encryptText",
    plaintext: input.range.text,
    label: input.label,
    policy: input.policy
  });

  if (response.type !== "created") {
    throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
  }

  return {
    updatedText: replaceRange(input.documentText, input.range, response.reference),
    reference: response.reference
  };
}
