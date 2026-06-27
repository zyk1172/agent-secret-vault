import { describe, expect, it } from "vitest";
import { encryptTextRange } from "../src/encrypt/encryptSelection";

describe("encrypt selection", () => {
  it("replaces selected plaintext with returned reference", async () => {
    const result = await encryptTextRange({
      documentText: "token = ASV_CANARY_PLUGIN",
      range: { start: 8, end: 25, text: "ASV_CANARY_PLUGIN" },
      label: null,
      policy: "credential",
      client: {
        request: async () => ({
          type: "created",
          reference: "secret://0123456789ABCDEFGHJKMNPQRS"
        })
      }
    });

    expect(result.updatedText).toBe("token = secret://0123456789ABCDEFGHJKMNPQRS");
    expect(JSON.stringify(result)).not.toContain("ASV_CANARY_PLUGIN");
  });
});
