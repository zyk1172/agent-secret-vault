import { describe, expect, it } from "vitest";
import { hashMarkdown, scanMarkdownFile } from "../src/scan/vaultScanner";
import { serializeScanState, type ScanFindingState } from "../src/scan/scanState";

describe("scan state serialization", () => {
  it("omits plaintext that is only safe for the current process", () => {
    const findings: ScanFindingState[] = [
      {
        filePath: "Secrets.md",
        contentHash: "sha256:test",
        start: 11,
        end: 18,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "********",
        plaintextForCurrentProcessOnly: "hunter2"
      }
    ];

    const serialized = serializeScanState(findings);

    expect(serialized).toContain("Secrets.md");
    expect(serialized).toContain("********");
    expect(serialized).not.toContain("hunter2");
    expect(JSON.parse(serialized)).toEqual([
      {
        filePath: "Secrets.md",
        contentHash: "sha256:test",
        start: 11,
        end: 18,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "********"
      }
    ]);
  });
});

describe("scanMarkdownFile", () => {
  it("adds file metadata, content hash, and in-memory plaintext to detector findings", () => {
    const text = "password = hunter2\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz";

    const findings = scanMarkdownFile("Daily.md", text);

    expect(findings).toEqual([
      {
        filePath: "Daily.md",
        contentHash: hashMarkdown(text),
        start: 11,
        end: 18,
        ruleId: "password-assignment",
        confidence: "medium",
        redactedPreview: "********",
        plaintextForCurrentProcessOnly: "hunter2"
      },
      {
        filePath: "Daily.md",
        contentHash: hashMarkdown(text),
        start: 41,
        end: 67,
        ruleId: "bearer-token",
        confidence: "high",
        redactedPreview: "abcdefgh…wxyz",
        plaintextForCurrentProcessOnly: "abcdefghijklmnopqrstuvwxyz"
      }
    ]);
  });
});
