import { describe, expect, it } from "vitest";
import { detectContextLeaks } from "../src/scan/contextLeak";

describe("detectContextLeaks", () => {
  it("warns when a canonical secret reference appears with risky Chinese context", () => {
    expect(detectContextLeaks("我的 Gmail 密码是 secret://0123456789ABCDEFGHJKMNPQRS")).toEqual([
      {
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        suggestion: "凭据：secret://0123456789ABCDEFGHJKMNPQRS"
      }
    ]);
  });

  it("does not warn for a canonical secret reference without risky words", () => {
    expect(detectContextLeaks("请引用 secret://0123456789ABCDEFGHJKMNPQRS 这条记录")).toEqual([]);
  });

  it("warns for English risky context and multiple canonical references", () => {
    expect(
      detectContextLeaks(
        "API key: secret://0123456789ABCDEFGHJKMNPQRS and token secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
      )
    ).toEqual([
      {
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        suggestion: "凭据：secret://0123456789ABCDEFGHJKMNPQRS"
      },
      {
        reference: "secret://ABCDEFGHJKMNPQRSTVWXYZ0123",
        suggestion: "凭据：secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
      }
    ]);
  });
});
