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
      plaintextForCurrentProcessOnly: text.slice(finding.start, finding.end),
      sourceExcerptForCurrentProcessOnly: sourceExcerpt(text, finding.start, finding.end)
    }));
}

function sourceExcerpt(text: string, start: number, end: number): string {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const nextLineBreak = text.indexOf("\n", end);
  const lineEnd = nextLineBreak === -1 ? text.length : nextLineBreak;
  const line = text.slice(lineStart, lineEnd);
  if (line.length <= 240) return line;

  const matchStart = start - lineStart;
  const excerptStart = Math.max(0, Math.min(matchStart - 100, line.length - 240));
  const excerptEnd = Math.min(line.length, excerptStart + 240);
  return `${excerptStart > 0 ? "..." : ""}${line.slice(excerptStart, excerptEnd)}${excerptEnd < line.length ? "..." : ""}`;
}
