export interface ContextLeakWarning {
  reference: string;
  suggestion: string;
}

const CANONICAL_SECRET_REFERENCE = /\bsecret:\/\/[A-HJ-NP-Z0-9]{26}\b/g;
const RISKY_CONTEXT_WORD = /密码|password|token|api key|root key|银行卡|card number/i;

export function detectContextLeaks(line: string): ContextLeakWarning[] {
  if (!RISKY_CONTEXT_WORD.test(line)) {
    return [];
  }

  return Array.from(line.matchAll(CANONICAL_SECRET_REFERENCE), (match) => {
    const reference = match[0];
    return {
      reference,
      suggestion: `凭据：${reference}`
    };
  });
}
