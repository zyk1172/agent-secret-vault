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

  it("detects passwd and pwd assignments with quoted and unquoted values", () => {
    const findings = detectSensitiveText('passwd="hunter2"\npwd=correct-horse-battery-staple');

    expect(findings).toEqual([
      {
        start: 8,
        end: 15,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "********"
      },
      {
        start: 21,
        end: 49,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "correct-…aple"
      }
    ]);
    expect(JSON.stringify(findings)).not.toContain("hunter2");
    expect(JSON.stringify(findings)).not.toContain("correct-horse-battery-staple");
  });

  it("ignores existing encrypted secret references during scans", () => {
    const encryptedReference = "secret://0123456789ABCDEFGHJKMNPQRS";
    const text = [
      `密码：${encryptedReference}`,
      `token="${encryptedReference}"`,
      `password = ${encryptedReference}`,
      `访问令牌：${encryptedReference}。`
    ].join("\n");

    expect(detectSensitiveText(text)).toEqual([]);
  });

  it("detects Chinese secret assignments used in personal knowledge bases", () => {
    const text = "服务器密码：correct-horse-battery-staple\n访问令牌 = ghp_1234567890abcdefghijklmnopqrstuvwxyz";

    const findings = detectSensitiveText(text);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "chinese-secret-assignment",
      "github-token"
    ]);
    expect(findings[0]).toMatchObject({
      start: 6,
      end: 34,
      confidence: "medium",
      redactedPreview: "correct-…aple"
    });
    expect(JSON.stringify(findings)).not.toContain("correct-horse-battery-staple");
  });

  it("detects generic API, token, access key, and client secret assignments", () => {
    const text = [
      "api_key = abcdefghijklmnopqrstuvwxyz123456",
      "client_secret: \"secret-value-1234567890\"",
      "access-key = AKIAIOSFODNN7EXAMPLE"
    ].join("\n");

    const findings = detectSensitiveText(text);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "generic-secret-assignment",
      "generic-secret-assignment",
      "generic-secret-assignment"
    ]);
    expect(JSON.stringify(findings)).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
    expect(JSON.stringify(findings)).not.toContain("secret-value-1234567890");
    expect(JSON.stringify(findings)).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("detects JWT and URL query secret parameters", () => {
    const text = [
      "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
      "https://example.com/callback?token=abcdefghijklmnopqrstuvwxyz123456&safe=ok"
    ].join("\n");

    const findings = detectSensitiveText(text);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "jwt",
      "url-secret-parameter"
    ]);
  });

  it("detects common personal identifiers as medium-confidence review candidates", () => {
    const text = "联系邮箱 user@example.com，手机号 13800138000，身份证 11010519491231002X，银行卡 6222020202020202020";

    const findings = detectSensitiveText(text);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "email-address",
      "phone-number",
      "china-id-card",
      "bank-card"
    ]);
    expect(findings.every((finding) => finding.confidence === "medium")).toBe(true);
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

  it("suppresses overlapping findings with deterministic priority", () => {
    const findings = detectSensitiveText("Authorization: Bearer sk-proj-1234567890abcdef1234567890abcdef");

    expect(findings).toEqual([
      {
        start: 22,
        end: 62,
        ruleId: "openai-api-key",
        confidence: "high",
        redactedPreview: "sk-proj-…cdef"
      }
    ]);
  });
});
