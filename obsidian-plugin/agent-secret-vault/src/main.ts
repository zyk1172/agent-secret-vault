import { Plugin } from "obsidian";
import { updateStatusBar } from "./ui/statusBar";

export const commandDefinitions = [
  { id: "encrypt-selection", name: "Encrypt selection" },
  { id: "encrypt-current-paragraph", name: "Encrypt current paragraph" },
  { id: "scan-current-note", name: "Scan current note for sensitive text" },
  { id: "scan-vault", name: "Scan vault for sensitive text" },
  { id: "reveal-current-paragraph", name: "Reveal current paragraph in Agent Secret Vault" }
] as const;

export default class AgentSecretVaultPlugin extends Plugin {
  async onload(): Promise<void> {
    const status = this.addStatusBarItem();
    updateStatusBar(status, { connected: false, locked: true });

    for (const definition of commandDefinitions) {
      this.addCommand({
        id: definition.id,
        name: definition.name,
        callback: () => {
          console.log(`Agent Secret Vault command pending implementation: ${definition.id}`);
        }
      });
    }
  }
}
