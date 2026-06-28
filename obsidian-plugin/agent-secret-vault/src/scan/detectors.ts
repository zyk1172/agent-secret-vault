export type SensitiveConfidence = "high" | "medium";

export interface SensitiveFinding {
  start: number;
  end: number;
  ruleId: "openai-api-key" | "private-key" | "bearer-token" | "password-assignment";
  confidence: SensitiveConfidence;
  redactedPreview: string;
}

interface RuleMatch {
  start: number;
  end: number;
  value: string;
  ruleId: SensitiveFinding["ruleId"];
  confidence: SensitiveConfidence;
}

function redactValue(value: string): string {
  if (value.length <= 10) {
    return "********";
  }
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function collectMatches(text: string, regex: RegExp, ruleId: SensitiveFinding["ruleId"], confidence: SensitiveConfidence): RuleMatch[] {
  const matches: RuleMatch[] = [];

  for (const match of text.matchAll(regex)) {
    const value = match.slice(1).find((capture): capture is string => capture !== undefined) ?? match[0];
    const matchStart = match.index ?? 0;
    const valueOffset = match[0].indexOf(value);
    const start = matchStart + valueOffset;

    matches.push({
      start,
      end: start + value.length,
      value,
      ruleId,
      confidence
    });
  }

  return matches;
}

export function detectSensitiveText(text: string): SensitiveFinding[] {
  const matches = [
    ...collectMatches(text, /sk-proj-[A-Za-z0-9_-]{20,}/g, "openai-api-key", "high"),
    ...collectMatches(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "private-key", "high"),
    ...collectMatches(text, /\bBearer\s+([A-Za-z0-9._~+/=-]{10,})/g, "bearer-token", "high"),
    ...collectMatches(text, /\b(?:password|passwd|pwd)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`]+))/gi, "password-assignment", "medium")
  ];

  return matches
    .sort((left, right) => left.start - right.start || left.end - right.end)
    .map(({ start, end, ruleId, confidence, value }) => ({
      start,
      end,
      ruleId,
      confidence,
      redactedPreview: redactValue(value)
    }));
}
