export interface PlannedReplacement {
  start: number;
  end: number;
  replacementText: string;
}

function compareFromEnd(left: PlannedReplacement, right: PlannedReplacement): number {
  return right.start - left.start || right.end - left.end;
}

function validateReplacements(text: string, replacements: PlannedReplacement[]): void {
  const ascendingReplacements = [...replacements].sort((left, right) => left.start - right.start || left.end - right.end);

  for (const replacement of ascendingReplacements) {
    if (replacement.start < 0 || replacement.end < replacement.start || replacement.end > text.length) {
      throw new RangeError("Replacement range is outside the original text.");
    }
  }

  for (let index = 1; index < ascendingReplacements.length; index += 1) {
    if (ascendingReplacements[index].start < ascendingReplacements[index - 1].end) {
      throw new RangeError("Replacement ranges overlap.");
    }
  }
}

export function applyReplacements(text: string, replacements: PlannedReplacement[]): string {
  validateReplacements(text, replacements);

  return [...replacements]
    .sort(compareFromEnd)
    .reduce(
      (updatedText, replacement) =>
        `${updatedText.slice(0, replacement.start)}${replacement.replacementText}${updatedText.slice(replacement.end)}`,
      text
    );
}
