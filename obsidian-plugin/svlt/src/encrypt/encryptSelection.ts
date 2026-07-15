import { replaceRange, type TextRange } from "../editor/selection";
import type { IpcRequest, IpcResponse } from "../ipc/protocol";

export interface VaultClientLike {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export async function encryptTextRange(input: {
  documentText: string;
  range: TextRange;
  label: string | null;
  referenceTitle: string;
  policy: "credential" | "externalSend" | "read";
  client: VaultClientLike;
}): Promise<{ updatedText: string; reference: string; replacementText: string }> {
  const response = await input.client.request({
    type: "encryptText",
    plaintext: input.range.text,
    label: input.label,
    policy: input.policy
  });

  if (response.type !== "created") {
    throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
  }

  const replacementText = formatMarkdownReference(input.referenceTitle, response.reference);
  return { updatedText: replaceRange(input.documentText, input.range, replacementText), reference: response.reference, replacementText };
}

export function inferReferenceTitle(documentText: string, range: TextRange): string {
  const lineStart = documentText.lastIndexOf("\n", Math.max(0, range.start - 1)) + 1;
  const prefix = documentText.slice(lineStart, range.start)
    .replace(/[：:=]\s*$/u, "")
    .replace(/[*_`#>-]/gu, "")
    .trim();
  return prefix.length > 0 ? prefix.slice(-48) : "敏感信息";
}

export function formatMarkdownReference(title: string, reference: string): string {
  const safeTitle = title.replace(/[\[\]\r\n]/gu, " ").trim() || "敏感信息";
  return `[${safeTitle}](${reference})`;
}
