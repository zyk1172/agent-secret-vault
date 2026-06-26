import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("security documentation", () => {
  it("states every excluded threat and first-release scope exclusion", async () => {
    const threatModel = await readFile(
      path.join(repositoryRoot, "docs/security/threat-model.md"),
      "utf8"
    );

    for (const phrase of [
      "malicious software running as the same macOS user",
      "screen recording or physical observation",
      "administrator or root control",
      "compromise of the signed application binary",
      "developer signing identity",
      "Claude and Hermes integrations",
      "automatic sensitive-information detection",
      "full-note encryption",
      "plaintext rendering inside the original Codex App",
      "iPhone or iPad clients",
      "team sharing and multi-user access control",
      "arbitrary shell execution",
      "bulk plaintext export",
      "defense against same-user malware or root compromise"
    ]) {
      expect(threatModel).toContain(phrase);
    }
  });

  it("lists release checklist acceptance criteria 1 through 12", async () => {
    const checklist = await readFile(
      path.join(repositoryRoot, "docs/security/release-checklist.md"),
      "utf8"
    );

    for (let criterion = 1; criterion <= 12; criterion += 1) {
      expect(checklist).toMatch(new RegExp(`^${criterion}\\.\\s`, "m"));
    }
  });
});
