export interface TextRange {
  start: number;
  end: number;
  text: string;
}

export function extractCurrentParagraph(documentText: string, cursorOffset: number): TextRange {
  const offset = Math.min(Math.max(cursorOffset, 0), documentText.length);
  const lines: Array<{ start: number; end: number; nextStart: number; blank: boolean }> = [];
  let lineStart = 0;

  while (lineStart <= documentText.length) {
    const newline = documentText.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? documentText.length : newline;
    lines.push({
      start: lineStart,
      end: lineEnd,
      nextStart: newline === -1 ? documentText.length : newline + 1,
      blank: documentText.slice(lineStart, lineEnd).trim().length === 0
    });

    if (newline === -1) {
      break;
    }

    lineStart = newline + 1;
  }

  const currentLineIndex = Math.max(0, lines.findIndex((line, index) => {
    const nextLine = lines[index + 1];
    const lineLimit = nextLine ? nextLine.start : documentText.length + 1;
    return offset >= line.start && offset < lineLimit;
  }));
  const currentLine = lines[currentLineIndex];

  if (currentLine.blank) {
    return {
      start: currentLine.start,
      end: currentLine.end,
      text: documentText.slice(currentLine.start, currentLine.end)
    };
  }

  let previousBlank: { start: number; end: number; nextStart: number; blank: boolean } | undefined;
  for (let index = currentLineIndex - 1; index >= 0; index -= 1) {
    if (lines[index].blank) {
      previousBlank = lines[index];
      break;
    }
  }
  const nextBlank = lines.slice(currentLineIndex + 1).find((line) => line.blank);
  const start = previousBlank ? previousBlank.nextStart : 0;
  const end = nextBlank ? Math.max(start, nextBlank.start - 1) : documentText.length;
  return { start, end, text: documentText.slice(start, end) };
}

export function replaceRange(documentText: string, range: TextRange, replacement: string): string {
  return `${documentText.slice(0, range.start)}${replacement}${documentText.slice(range.end)}`;
}
