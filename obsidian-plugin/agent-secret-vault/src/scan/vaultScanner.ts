import { createHash } from "node:crypto";
import { detectSensitiveText } from "./detectors";
import type { ScanFindingState } from "./scanState";

function hashMarkdown(text: string): string {
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}

export function scanMarkdownFile(filePath: string, text: string): ScanFindingState[] {
  const contentHash = hashMarkdown(text);

  return detectSensitiveText(text).map((finding) => ({
    ...finding,
    filePath,
    contentHash,
    plaintextForCurrentProcessOnly: text.slice(finding.start, finding.end)
  }));
}
