import { detectSensitiveText } from "./detectors";
import type { ScanFindingState } from "./scanState";

export function hashMarkdown(text: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return `fnv1a32:${(hash >>> 0).toString(16).padStart(8, "0")}`;
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
