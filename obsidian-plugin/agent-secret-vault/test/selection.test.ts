import { describe, expect, it } from "vitest";
import { extractCurrentParagraph } from "../src/editor/selection";

describe("selection helpers", () => {
  it("extracts paragraph around cursor", () => {
    const text = "alpha\n\npassword = hunter2\napi token here\n\nomega";
    expect(extractCurrentParagraph(text, text.indexOf("token"))).toEqual({
      start: 7,
      end: 40,
      text: "password = hunter2\napi token here"
    });
  });
});
