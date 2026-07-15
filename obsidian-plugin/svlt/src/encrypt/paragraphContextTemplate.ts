import { extractCurrentParagraph, type TextRange } from "../editor/selection";
import { applyReplacements, type PlannedReplacement } from "../replace/transactionalReplace";
import { detectSensitiveText } from "../scan/detectors";

export const PARAGRAPH_REFERENCE_MARKER = "[[ASV_REFERENCE]]";

export function buildParagraphContextTemplate(
  documentText: string,
  target: TextRange
): string {
  const paragraph = extractCurrentParagraph(documentText, target.start);
  const targetStart = Math.max(0, target.start - paragraph.start);
  const targetEnd = Math.min(paragraph.text.length, Math.max(targetStart, target.end - paragraph.start));
  const replacements: PlannedReplacement[] = [{
    start: targetStart,
    end: targetEnd,
    replacementText: PARAGRAPH_REFERENCE_MARKER
  }];

  for (const finding of detectSensitiveText(paragraph.text)) {
    if (finding.end <= targetStart || finding.start >= targetEnd) {
      replacements.push({ start: finding.start, end: finding.end, replacementText: "已隐藏" });
      continue;
    }

    if (finding.start < targetStart) {
      replacements.push({ start: finding.start, end: targetStart, replacementText: "已隐藏" });
    }
    if (targetEnd < finding.end) {
      replacements.push({ start: targetEnd, end: finding.end, replacementText: "已隐藏" });
    }
  }

  return applyReplacements(paragraph.text, replacements);
}
