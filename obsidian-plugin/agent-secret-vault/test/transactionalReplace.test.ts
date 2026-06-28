import { describe, expect, it } from "vitest";
import { applyReplacements } from "../src/replace/transactionalReplace";

describe("applyReplacements", () => {
  it("applies planned replacements from the end so earlier offsets remain valid", () => {
    const text = "alpha hunter2 beta sk-proj-1234567890abcdef1234567890abcdef gamma";

    expect(
      applyReplacements(text, [
        {
          start: 6,
          end: 13,
          replacementText: "secret://PASSWORD"
        },
        {
          start: 19,
          end: 59,
          replacementText: "secret://OPENAI"
        }
      ])
    ).toBe("alpha secret://PASSWORD beta secret://OPENAI gamma");
  });

  it("throws when planned replacements overlap", () => {
    const text = "alpha hunter2 beta";

    expect(() =>
      applyReplacements(text, [
        {
          start: 6,
          end: 13,
          replacementText: "secret://PASSWORD"
        },
        {
          start: 10,
          end: 16,
          replacementText: "secret://OVERLAP"
        }
      ])
    ).toThrow("Replacement ranges overlap.");
  });
});
