export interface TextRange {
  start: number;
  end: number;
  text: string;
}

export function extractCurrentParagraph(documentText: string, cursorOffset: number): TextRange {
  const before = documentText.lastIndexOf("\n\n", Math.max(0, cursorOffset - 1));
  const after = documentText.indexOf("\n\n", cursorOffset);
  const start = before === -1 ? 0 : before + 2;
  const end = after === -1 ? documentText.length : after;
  return { start, end, text: documentText.slice(start, end) };
}

export function replaceRange(documentText: string, range: TextRange, replacement: string): string {
  return `${documentText.slice(0, range.start)}${replacement}${documentText.slice(range.end)}`;
}
