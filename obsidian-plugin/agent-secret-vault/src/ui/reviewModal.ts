import { Modal, type App } from "obsidian";
import type { ScanFindingState } from "../scan/scanState";

export class ReviewModal extends Modal {
  constructor(app: App, private readonly findings: ScanFindingState[]) {
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
    for (const finding of this.findings) {
      const item = list.createEl("li");
      item.createEl("div", { text: finding.filePath });
      item.createEl("div", { text: `Rule: ${finding.ruleId}` });
      item.createEl("div", { text: `Confidence: ${finding.confidence}` });
      item.createEl("code", { text: finding.redactedPreview });
    }
  }
}
