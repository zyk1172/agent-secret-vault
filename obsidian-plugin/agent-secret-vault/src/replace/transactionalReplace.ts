export interface PlannedReplacement {
  start: number;
  end: number;
  replacementText: string;
}

function compareFromEnd(left: PlannedReplacement, right: PlannedReplacement): number {
  return right.start - left.start || right.end - left.end;
}

export function applyReplacements(text: string, replacements: PlannedReplacement[]): string {
  return [...replacements]
    .sort(compareFromEnd)
    .reduce((updatedText, replacement) => {
      if (replacement.start < 0 || replacement.end < replacement.start || replacement.end > text.length) {
        throw new RangeError("Replacement range is outside the original text.");
      }

      return `${updatedText.slice(0, replacement.start)}${replacement.replacementText}${updatedText.slice(replacement.end)}`;
    }, text);
}
