import { describe, expect, it, vi } from "vitest";
import type { ScanFindingState } from "../src/scan/scanState";

class FakeElement {
  textContent = "";
  disabled = false;
  type = "";
  checked = false;
  children: FakeElement[] = [];
  listeners = new Map<string, () => void>();

  constructor(readonly tagName: string, text = "") {
    this.textContent = text;
  }

  empty(): void {
    this.children = [];
    this.textContent = "";
  }

  createEl(tagName: string, options?: { text?: string }): FakeElement {
    const child = new FakeElement(tagName, options?.text ?? "");
    this.children.push(child);
    return child;
  }

  addEventListener(name: string, listener: () => void): void {
    this.listeners.set(name, listener);
  }

  allText(): string[] {
    return [
      this.textContent,
      ...this.children.flatMap((child) => child.allText())
    ].filter((text) => text.length > 0);
  }
}

const modalMock = vi.hoisted(() => ({
  latestContentEl: undefined as FakeElement | undefined
}));

vi.mock("obsidian", () => ({
  Modal: class ModalTestDouble {
    contentEl = new FakeElement("root");

    constructor(_app: unknown) {
      modalMock.latestContentEl = this.contentEl;
    }

    close(): void {}
  }
}));

import { ReviewModal } from "../src/ui/reviewModal";

function finding(overrides: Partial<ScanFindingState>): ScanFindingState {
  return {
    start: 0,
    end: 5,
    ruleId: "password-assignment",
    confidence: "medium",
    redactedPreview: "********",
    filePath: "a.md",
    contentHash: "fnv1a32:00000000",
    plaintextForCurrentProcessOnly: "secret",
    ...overrides
  };
}

describe("ReviewModal", () => {
  it("shows actionable Chinese guidance when a scan finds nothing", () => {
    const modal = new ReviewModal({} as never, []);

    modal.onOpen();

    expect(modalMock.latestContentEl?.allText()).toContain("没有发现可自动识别的敏感信息。");
    expect(modalMock.latestContentEl?.allText().join("\n")).toContain("仍然可以手动选中文字后使用“加密选中文本”。");
  });

  it("summarizes findings and exposes a Chinese encrypt action", () => {
    const modal = new ReviewModal({} as never, [
      finding({ filePath: "a.md", ruleId: "chinese-secret-assignment", redactedPreview: "correct-…aple" }),
      finding({ filePath: "b.md", ruleId: "email-address", redactedPreview: "user@exa…com" })
    ], async () => {});

    modal.onOpen();

    const text = modalMock.latestContentEl?.allText() ?? [];
    expect(text).toContain("敏感信息扫描结果");
    expect(text).toContain("命中 2 项，涉及 2 个文件。请勾选要加密的项目。");
    expect(text).toContain("加密选中项");
    expect(text).toContain("规则：chinese-secret-assignment");
    expect(text).toContain("置信度：medium");
  });

  it("shows process-local exact text and clears it on close", () => {
    const candidate = finding({
      plaintextForCurrentProcessOnly: "hunter2",
      sourceExcerptForCurrentProcessOnly: "NAS 密码：hunter2"
    });
    const modal = new ReviewModal({} as never, [candidate]);

    modal.onOpen();

    expect(modalMock.latestContentEl?.allText()).toContain("命中内容：hunter2");
    expect(modalMock.latestContentEl?.allText()).toContain("所在内容：NAS 密码：hunter2");
    modal.onClose();
    expect(candidate.plaintextForCurrentProcessOnly).toBeUndefined();
    expect(candidate.sourceExcerptForCurrentProcessOnly).toBeUndefined();
  });
});
