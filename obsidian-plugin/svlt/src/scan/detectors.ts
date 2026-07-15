export type SensitiveConfidence = "high" | "medium";
export type SensitiveRuleId =
  | "openai-api-key"
  | "private-key"
  | "bearer-token"
  | "password-assignment"
  | "chinese-secret-assignment"
  | "generic-secret-assignment"
  | "github-token"
  | "jwt"
  | "url-secret-parameter"
  | "email-address"
  | "phone-number"
  | "china-id-card"
  | "bank-card";

export interface SensitiveFinding {
  start: number;
  end: number;
  ruleId: SensitiveRuleId;
  confidence: SensitiveConfidence;
  redactedPreview: string;
}

interface RuleMatch {
  start: number;
  end: number;
  value: string;
  ruleId: SensitiveRuleId;
  confidence: SensitiveConfidence;
}

const existingSecretReferencePattern = /^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
const existingSecretReferenceTailPattern = /^\/\/[0-9A-HJKMNP-TV-Z]{26}$/;
const trailingReferencePunctuationPattern = /[.,，。；;:：)）\]}】>]+$/u;

function redactValue(value: string): string {
  if (value.length <= 10) {
    return "********";
  }
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function isExistingSecretReference(value: string): boolean {
  const normalizedValue = value.replace(trailingReferencePunctuationPattern, "");
  return existingSecretReferencePattern.test(normalizedValue)
    || existingSecretReferenceTailPattern.test(normalizedValue);
}

function collectMatches(text: string, regex: RegExp, ruleId: SensitiveRuleId, confidence: SensitiveConfidence): RuleMatch[] {
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

const rulePriority: Record<SensitiveRuleId, number> = {
  "private-key": 0,
  "openai-api-key": 1,
  "github-token": 2,
  "jwt": 3,
  "bearer-token": 4,
  "url-secret-parameter": 5,
  "generic-secret-assignment": 6,
  "chinese-secret-assignment": 7,
  "password-assignment": 8,
  "china-id-card": 9,
  "bank-card": 10,
  "phone-number": 11,
  "email-address": 12
};

function confidencePriority(confidence: SensitiveConfidence): number {
  return confidence === "high" ? 0 : 1;
}

function overlaps(left: RuleMatch, right: RuleMatch): boolean {
  return left.start < right.end && right.start < left.end;
}

function compareFindingPriority(left: RuleMatch, right: RuleMatch): number {
  return confidencePriority(left.confidence) - confidencePriority(right.confidence)
    || (right.end - right.start) - (left.end - left.start)
    || rulePriority[left.ruleId] - rulePriority[right.ruleId]
    || left.start - right.start
    || left.end - right.end;
}

function suppressOverlaps(matches: RuleMatch[]): RuleMatch[] {
  const accepted: RuleMatch[] = [];
  for (const candidate of [...matches].sort(compareFindingPriority)) {
    if (!accepted.some((finding) => overlaps(finding, candidate))) {
      accepted.push(candidate);
    }
  }
  return accepted.sort((left, right) => left.start - right.start || left.end - right.end);
}

export function detectSensitiveText(text: string): SensitiveFinding[] {
  const matches = [
    ...collectMatches(text, /sk-proj-[A-Za-z0-9_-]{20,}/g, "openai-api-key", "high"),
    ...collectMatches(text, /gh[pousr]_[A-Za-z0-9_]{20,}/g, "github-token", "high"),
    ...collectMatches(text, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "private-key", "high"),
    ...collectMatches(text, /\bBearer\s+([A-Za-z0-9._~+/=-]{10,})/g, "bearer-token", "high"),
    ...collectMatches(text, /\b(?:password|passwd|pwd)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`]+))/gi, "password-assignment", "medium"),
    ...collectMatches(text, /(?:密码|口令|令牌|密钥|秘钥|访问密钥|api\s*key|API\s*Key|token|secret)\s*[:：=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"'`，。；;]+))/gi, "chinese-secret-assignment", "medium"),
    ...collectMatches(text, /\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|refresh[_-]?token|token|secret)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([A-Za-z0-9._~+/=-]{10,}))/gi, "generic-secret-assignment", "medium"),
    ...collectMatches(text, /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})\b/g, "jwt", "high"),
    ...collectMatches(text, /[?&](?:token|access_token|refresh_token|api_key|apikey|key|secret|client_secret)=([A-Za-z0-9._~+/=-]{10,})/gi, "url-secret-parameter", "high"),
    ...collectMatches(text, /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, "email-address", "medium"),
    ...collectMatches(text, /(?<!\d)(1[3-9]\d{9})(?!\d)/g, "phone-number", "medium"),
    ...collectMatches(text, /(?<!\d)([1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx])(?![0-9Xx])/g, "china-id-card", "medium"),
    ...collectMatches(text, /(?<!\d)([1-9]\d{15,18})(?!\d)/g, "bank-card", "medium")
  ];

  return suppressOverlaps(matches.filter(({ value }) => !isExistingSecretReference(value)))
    .map(({ start, end, ruleId, confidence, value }) => ({
      start,
      end,
      ruleId,
      confidence,
      redactedPreview: redactValue(value)
    }));
}
