import type { IpcRequest } from "../ipc/protocol";

const SECRET_REFERENCE_PATTERN = /secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g;

export function buildParagraphRevealRequest(paragraph: string): IpcRequest {
  const references: string[] = [];
  const ranges: Array<{ index: number; placeholder: string }> = [];
  let referenceIndex = 0;

  const template = paragraph.replace(SECRET_REFERENCE_PATTERN, (reference) => {
    const placeholder = `{{${referenceIndex}}}`;
    references.push(reference);
    ranges.push({ index: referenceIndex, placeholder });
    referenceIndex += 1;
    return placeholder;
  });

  if (references.length === 0) {
    throw new Error("NO_SECRET_REFERENCES");
  }

  return {
    type: "revealReferences",
    references,
    context: {
      reason: "Reveal current paragraph",
      template,
      ranges
    }
  };
}
