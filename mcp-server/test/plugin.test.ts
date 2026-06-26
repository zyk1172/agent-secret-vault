import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const pluginRoot = path.join(repositoryRoot, "plugins", "agent-secret-vault");
const marketplacePath = path.join(repositoryRoot, ".agents", "plugins", "marketplace.json");

describe("Codex plugin package", () => {
  it("declares a repo-local marketplace entry", async () => {
    const marketplace = await readJson(marketplacePath);
    const entry = marketplace.plugins.find((candidate: { name?: string }) => {
      return candidate.name === "agent-secret-vault";
    });

    expect(marketplace.name).toBe("personal");
    expect(entry).toEqual({
      name: "agent-secret-vault",
      source: {
        source: "local",
        path: "./plugins/agent-secret-vault"
      },
      policy: {
        installation: "AVAILABLE",
        authentication: "ON_INSTALL"
      },
      category: "Productivity"
    });
  });

  it("keeps manifest component paths under the plugin root", async () => {
    const manifestPath = path.join(pluginRoot, ".codex-plugin", "plugin.json");
    const manifest = await readJson(manifestPath);

    expect(manifest.name).toBe("agent-secret-vault");
    expect(manifest.skills).toBe("./skills/");
    expect(manifest.mcpServers).toBe("./.mcp.json");
    expect(manifest).not.toHaveProperty("hooks");

    for (const field of ["skills", "mcpServers", "apps"] as const) {
      if (manifest[field] !== undefined) {
        expectResolvesUnderPluginRoot(manifest[field]);
      }
    }
  });

  it("configures the MCP server through PLUGIN_ROOT", async () => {
    const mcp = await readJson(path.join(pluginRoot, ".mcp.json"));
    const server = mcp.mcpServers["agent-secret-vault"];

    expect(server.command).toBe("node");
    expect(server.args.join(" ")).toContain("${PLUGIN_ROOT}");
    expect(server.args.join(" ")).toContain("mcp-server/dist/server.js");
  });

  it("documents the non-plaintext operating rules in the bundled skill and hook", async () => {
    const skill = await readFile(
      path.join(pluginRoot, "skills", "agent-secret-vault", "SKILL.md"),
      "utf8"
    );
    const hookConfig = await readFile(path.join(pluginRoot, "hooks", "hooks.json"), "utf8");
    const hookScript = await readFile(
      path.join(pluginRoot, "hooks", "validate_secret_output.js"),
      "utf8"
    );
    const combined = `${skill}\n${hookConfig}\n${hookScript}`.toLowerCase();

    expect(combined).toContain("never request plaintext from mcp");
    expect(combined).toContain("never echo resolved credentials");
    expect(combined).toContain("use `secret://` references");
    expect(combined).toMatch(/plaintext|secretvalue|resolvedarguments|masterkey/);
  });
});

async function readJson(filePath: string) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function expectResolvesUnderPluginRoot(relativePath: string): void {
  expect(relativePath.startsWith("./")).toBe(true);
  const resolved = path.resolve(pluginRoot, relativePath);
  expect(resolved === pluginRoot || resolved.startsWith(`${pluginRoot}${path.sep}`)).toBe(true);
}
