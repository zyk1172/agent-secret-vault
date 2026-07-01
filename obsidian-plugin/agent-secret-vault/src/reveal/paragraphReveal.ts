import type { IpcRequest } from "../ipc/protocol";

const SECRET_SCHEME = "secret://";
const SECRET_ID_LENGTH = 26;
const ALLOWED_ID_CHARACTERS = new Set("0123456789ABCDEFGHJKMNPQRSTVWXYZ".split(""));
const TOKEN_BOUNDARY_CHARACTERS = new Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/-".split(""));

interface ReferenceMatch {
  reference: string;
  start: number;
  end: number;
}

function isBoundaryCharacter(text: string, index: number): boolean {
  if (index < 0 || index >= text.length) {
    return true;
  }
  return !TOKEN_BOUNDARY_CHARACTERS.has(text[index] ?? "");
}

function extractReferenceMatches(paragraph: string): ReferenceMatch[] {
  const matches: ReferenceMatch[] = [];
  let searchStart = 0;

  while (searchStart < paragraph.length) {
    const schemeStart = paragraph.indexOf(SECRET_SCHEME, searchStart);
    if (schemeStart === -1) {
      break;
    }
    searchStart = schemeStart + SECRET_SCHEME.length;

    if (!isBoundaryCharacter(paragraph, schemeStart - 1)) {
      continue;
    }

    const idStart = schemeStart + SECRET_SCHEME.length;
    const idEnd = idStart + SECRET_ID_LENGTH;
    if (idEnd > paragraph.length) {
      continue;
    }

    const id = paragraph.slice(idStart, idEnd);
    if (![...id].every((character) => ALLOWED_ID_CHARACTERS.has(character))) {
      continue;
    }

    if (!isBoundaryCharacter(paragraph, idEnd)) {
      continue;
    }

    matches.push({
      reference: `${SECRET_SCHEME}${id}`,
      start: schemeStart,
      end: idEnd
    });
  }

  return matches;
}

function placeholderNonce(): string {
  const randomUUID = globalThis.crypto?.randomUUID;
  if (typeof randomUUID === "function") {
    return randomUUID.call(globalThis.crypto).replace(/-/g, "");
  }
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

function choosePlaceholder(index: number, paragraph: string, usedPlaceholders: Set<string>): string {
  const legacyPlaceholder = `{{${index}}}`;
  if (!paragraph.includes(legacyPlaceholder) && !usedPlaceholders.has(legacyPlaceholder)) {
    return legacyPlaceholder;
  }

  while (true) {
    const candidate = `{{ASV_REVEAL_${index}_${placeholderNonce()}}}`;
    if (!paragraph.includes(candidate) && !usedPlaceholders.has(candidate)) {
      return candidate;
    }
  }
}

export function buildParagraphRevealRequest(paragraph: string): IpcRequest {
  const request = buildReferenceResolutionRequest(paragraph);
  return {
    ...request,
    type: "revealReferences"
  };
}

export function buildParagraphRestoreRequest(paragraph: string): IpcRequest {
  const request = buildReferenceResolutionRequest(paragraph);
  return {
    ...request,
    type: "restoreReferences"
  };
}

function buildReferenceResolutionRequest(paragraph: string): Extract<IpcRequest, { type: "revealReferences" | "restoreReferences" }> {
  const matches = extractReferenceMatches(paragraph);
  if (matches.length === 0) {
    throw new Error("NO_SECRET_REFERENCES");
  }

  const references: string[] = [];
  const ranges: Array<{ index: number; placeholder: string }> = [];
  const usedPlaceholders = new Set<string>();
  let template = "";
  let lastEnd = 0;

  matches.forEach((match, referenceIndex) => {
    const placeholder = choosePlaceholder(referenceIndex, paragraph, usedPlaceholders);
    usedPlaceholders.add(placeholder);
    references.push(match.reference);
    ranges.push({ index: referenceIndex, placeholder });
    template += paragraph.slice(lastEnd, match.start);
    template += placeholder;
    lastEnd = match.end;
  });

  template += paragraph.slice(lastEnd);

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
