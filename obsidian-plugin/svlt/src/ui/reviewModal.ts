import { Modal, type App } from "obsidian";
import type { ScanFindingState } from "../scan/scanState";

export class ReviewModal extends Modal {
  constructor(
    app: App,
    private findings: ScanFindingState[],
    private readonly applyFindings?: (findings: ScanFindingState[]) => Promise<void>
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "敏感信息扫描结果" });

    if (this.findings.length === 0) {
      contentEl.createEl("p", { text: "没有发现可自动识别的敏感信息。" });
      contentEl.createEl("p", { text: "当前会扫描密码、令牌、API Key、私钥、JWT、URL 密钥参数、邮箱、手机号、身份证、银行卡等常见模式。仍然可以手动选中文字后使用“加密选中文本”。" });
      return;
    }

    const fileCount = new Set(this.findings.map((finding) => finding.filePath)).size;
    contentEl.createEl("p", { text: `命中 ${this.findings.length} 项，涉及 ${fileCount} 个文件。请勾选要加密的项目。` });

    const list = contentEl.createEl("ul");
    const selected = new Set(this.findings);
    for (const finding of this.findings) {
      const item = list.createEl("li");
      const checkbox = item.createEl("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selected.add(finding);
        } else {
          selected.delete(finding);
        }
      });
      item.createEl("div", { text: `文件：${finding.filePath}` });
      item.createEl("div", { text: `规则：${finding.ruleId}` });
      item.createEl("div", { text: `置信度：${finding.confidence}` });
      item.createEl("div", { text: `命中内容：${finding.plaintextForCurrentProcessOnly ?? finding.redactedPreview}` });
      item.createEl("div", { text: `所在内容：${finding.sourceExcerptForCurrentProcessOnly ?? finding.redactedPreview}` });
    }

    if (this.applyFindings) {
      const button = contentEl.createEl("button", { text: "加密选中项" });
      button.addEventListener("click", async () => {
        button.disabled = true;
        await this.applyFindings?.([...selected]);
        this.close();
      });
    }
  }

  override onClose(): void {
    for (const finding of this.findings) {
      finding.plaintextForCurrentProcessOnly = undefined;
      finding.sourceExcerptForCurrentProcessOnly = undefined;
    }
    this.findings = [];
    this.contentEl.empty();
  }
}
