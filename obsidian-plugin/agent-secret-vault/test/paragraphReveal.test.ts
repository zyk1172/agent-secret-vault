import { describe, expect, it } from "vitest";
import { buildParagraphRevealRequest } from "../src/reveal/paragraphReveal";

describe("paragraph reveal", () => {
  it("sends references and template without asking plugin to receive plaintext", () => {
    const request = buildParagraphRevealRequest("Login with secret://0123456789ABCDEFGHJKMNPQRS now.");
    expect(request).toEqual({
      type: "revealReferences",
      references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
      context: {
        reason: "Reveal current paragraph",
        template: "Login with {{0}} now.",
        ranges: [{ index: 0, placeholder: "{{0}}" }]
      }
    });
    expect(JSON.stringify(request)).not.toContain("plaintext");
  });

  it("rejects paragraphs without references before IPC", () => {
    expect(() => buildParagraphRevealRequest("Login without a secret reference.")).toThrow("NO_SECRET_REFERENCES");
  });
});
