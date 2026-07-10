import { describe, expect, it } from "vitest";
import {
  buildParagraphContextTemplate,
  PARAGRAPH_REFERENCE_MARKER
} from "../src/encrypt/paragraphContextTemplate";

describe("buildParagraphContextTemplate", () => {
  it("keeps the containing paragraph and replaces the target range with the reference marker", () => {
    const text = "NAS 用户名：demo-user\nNAS 密码：demo-password\n\n下一段";
    const start = text.indexOf("demo-password");

    expect(buildParagraphContextTemplate(text, {
      start,
      end: start + "demo-password".length,
      text: "demo-password"
    })).toBe(`NAS 用户名：demo-user\nNAS 密码：${PARAGRAPH_REFERENCE_MARKER}`);
  });

  it("hides other detector-recognized values in the same paragraph", () => {
    const text = "NAS 密码：demo-password\nAPI token：abcdefghijklmnop";
    const start = text.indexOf("demo-password");

    expect(buildParagraphContextTemplate(text, {
      start,
      end: start + "demo-password".length,
      text: "demo-password"
    })).toBe(`NAS 密码：${PARAGRAPH_REFERENCE_MARKER}\nAPI token：已隐藏`);
  });

  it("hides unselected portions of a detected match", () => {
    const text = "NAS 密码：demo-password";
    const start = text.indexOf("password");

    expect(buildParagraphContextTemplate(text, {
      start,
      end: start + "password".length,
      text: "password"
    })).toBe(`NAS 密码：已隐藏${PARAGRAPH_REFERENCE_MARKER}`);
  });
});
