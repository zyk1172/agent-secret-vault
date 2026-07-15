import { describe, expect, it } from "vitest";
import { detectContextLeaks } from "../src/scan/contextLeak";

describe("detectContextLeaks", () => {
  it("warns when a canonical secret reference appears with risky Chinese context", () => {
    expect(detectContextLeaks("我的 Gmail 密码是 secret://0123456789ABCDEFGHJKMNPQRS")).toEqual([
      {
        ruleId: "semantic-secret-label",
        message: "Surrounding text reveals the secret type.",
        suggestion: "凭据：secret://0123456789ABCDEFGHJKMNPQRS"
      }
    ]);
  });

  it("does not warn for a canonical secret reference without risky words", () => {
    expect(detectContextLeaks("请引用 secret://0123456789ABCDEFGHJKMNPQRS 这条记录")).toEqual([]);
  });

  it("does not warn for invalid secret references containing disallowed characters", () => {
    expect(detectContextLeaks("password secret://0123456789ABCDEFGHJKLMNPQRU")).toEqual([]);
  });

  it("warns for English risky context and multiple canonical references", () => {
    expect(
      detectContextLeaks(
        "API key: secret://0123456789ABCDEFGHJKMNPQRS and token secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
      )
    ).toEqual([
      {
        ruleId: "semantic-secret-label",
        message: "Surrounding text reveals the secret type.",
        suggestion: "凭据：secret://0123456789ABCDEFGHJKMNPQRS"
      },
      {
        ruleId: "semantic-secret-label",
        message: "Surrounding text reveals the secret type.",
        suggestion: "凭据：secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
      }
    ]);
  });
});
