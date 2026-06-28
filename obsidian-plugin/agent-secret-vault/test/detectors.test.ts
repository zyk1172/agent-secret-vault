import { describe, expect, it } from "vitest";
import { detectSensitiveText } from "../src/scan/detectors";

describe("detectSensitiveText", () => {
  it("detects OpenAI project keys with deterministic redaction", () => {
    expect(detectSensitiveText("OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef")).toEqual([
      {
        start: 15,
        end: 55,
        ruleId: "openai-api-key",
        confidence: "high",
        redactedPreview: "sk-proj-…cdef"
      }
    ]);
  });

  it("returns multiple findings in source order without plaintext values", () => {
    const findings = detectSensitiveText("password = short\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz");

    expect(findings.map((finding) => finding.ruleId)).toEqual(["password-assignment", "bearer-token"]);
    expect(findings[0]).toMatchObject({
      confidence: "medium",
      redactedPreview: "********"
    });
    expect(findings[1]).toMatchObject({
      confidence: "high",
      redactedPreview: "abcdefgh…wxyz"
    });
    expect(JSON.stringify(findings)).not.toContain("short");
    expect(JSON.stringify(findings)).not.toContain("abcdefghijklmnopqrstuvwxyz");
  });

  it("detects quoted password assignments without exposing plaintext", () => {
    const findings = detectSensitiveText('password="hunter2"\npassword: \'correct-horse-battery-staple\'');

    expect(findings).toEqual([
      {
        start: 10,
        end: 17,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "********"
      },
      {
        start: 30,
        end: 58,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "correct-…aple"
      }
    ]);
    expect(JSON.stringify(findings)).not.toContain("hunter2");
    expect(JSON.stringify(findings)).not.toContain("correct-horse-battery-staple");
  });

  it("detects private key blocks and redacts the block preview", () => {
    const text = [
      "before",
      "-----BEGIN PRIVATE KEY-----",
      "abcdefghijklmnopqrstuvwxyz0123456789",
      "-----END PRIVATE KEY-----",
      "after"
    ].join("\n");

    const findings = detectSensitiveText(text);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual({
      start: 7,
      end: 97,
      ruleId: "private-key",
      confidence: "high",
      redactedPreview: "-----BEG…----"
    });
    expect(JSON.stringify(findings)).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
  });
});
