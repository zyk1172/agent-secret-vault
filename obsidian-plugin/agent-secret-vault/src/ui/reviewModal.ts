import { Modal, type App } from "obsidian";
import type { ScanFindingState } from "../scan/scanState";

export class ReviewModal extends Modal {
  constructor(
    app: App,
    private readonly findings: ScanFindingState[],
    private readonly applyFindings?: (findings: ScanFindingState[]) => Promise<void>
  ) {
    super(app);
  }

  override onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Agent Secret Vault review queue" });

    if (this.findings.length === 0) {
      contentEl.createEl("p", { text: "No sensitive text findings in this scan." });
      return;
    }

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
      item.createEl("div", { text: finding.filePath });
      item.createEl("div", { text: `Rule: ${finding.ruleId}` });
      item.createEl("div", { text: `Confidence: ${finding.confidence}` });
      item.createEl("code", { text: finding.redactedPreview });
    }

    if (this.applyFindings) {
      const button = contentEl.createEl("button", { text: "Encrypt selected findings" });
      button.addEventListener("click", async () => {
        button.disabled = true;
        await this.applyFindings?.([...selected]);
        this.close();
      });
    }
  }
}
