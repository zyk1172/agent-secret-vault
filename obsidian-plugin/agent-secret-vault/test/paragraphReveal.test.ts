import { describe, expect, it } from "vitest";
import type { IpcRequest } from "../src/ipc/protocol";
import { buildParagraphRevealRequest } from "../src/reveal/paragraphReveal";

type RevealReferencesRequest = Extract<IpcRequest, { type: "revealReferences" }>;

function expectRevealReferencesRequest(request: IpcRequest): RevealReferencesRequest {
  expect(request.type).toBe("revealReferences");
  if (request.type !== "revealReferences") {
    throw new Error(`Unexpected request type: ${request.type}`);
  }
  return request;
}

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

  it("builds templates for multiple references", () => {
    const request = expectRevealReferencesRequest(buildParagraphRevealRequest(
      "Login secret://0123456789ABCDEFGHJKMNPQRS then token secret://ABCDEFGHJKMNPQRSTVWXYZ0123 done."
    ));

    expect(request.references).toEqual([
      "secret://0123456789ABCDEFGHJKMNPQRS",
      "secret://ABCDEFGHJKMNPQRSTVWXYZ0123"
    ]);
    expect(request.context.template).toBe("Login {{0}} then token {{1}} done.");
    expect(request.context.ranges).toEqual([
      { index: 0, placeholder: "{{0}}" },
      { index: 1, placeholder: "{{1}}" }
    ]);
  });

  it("keeps duplicate reference occurrences as separate reveal ranges", () => {
    const request = expectRevealReferencesRequest(buildParagraphRevealRequest(
      "Use secret://0123456789ABCDEFGHJKMNPQRS twice: secret://0123456789ABCDEFGHJKMNPQRS done."
    ));

    expect(request.references).toEqual([
      "secret://0123456789ABCDEFGHJKMNPQRS",
      "secret://0123456789ABCDEFGHJKMNPQRS"
    ]);
    expect(request.context.template).toBe("Use {{0}} twice: {{1}} done.");
  });

  it("chooses placeholders absent from the original paragraph when legacy placeholders collide", () => {
    const request = expectRevealReferencesRequest(buildParagraphRevealRequest(
      "Literal {{0}} before secret://0123456789ABCDEFGHJKMNPQRS done."
    ));

    expect(request.context.template).toContain("Literal {{0}} before ");
    expect(request.context.template).not.toBe("Literal {{0}} before {{0}}.");
    expect(request.context.ranges[0]?.placeholder).not.toBe("{{0}}");
    expect(request.context.ranges[0]?.placeholder).toMatch(/^\{\{ASV_REVEAL_0_[^}]+\}\}$/);
    expect("Literal {{0}} before secret://0123456789ABCDEFGHJKMNPQRS.").not.toContain(
      request.context.ranges[0]?.placeholder
    );
  });

  it("ignores embedded and longer secret tokens", () => {
    expect(() => buildParagraphRevealRequest("prefixsecret://0123456789ABCDEFGHJKMNPQRS")).toThrow(
      "NO_SECRET_REFERENCES"
    );
    expect(() => buildParagraphRevealRequest("secret://0123456789ABCDEFGHJKMNPQRSA")).toThrow(
      "NO_SECRET_REFERENCES"
    );
  });

  it("rejects paragraphs without references before IPC", () => {
    expect(() => buildParagraphRevealRequest("Login without a secret reference.")).toThrow("NO_SECRET_REFERENCES");
  });
});
