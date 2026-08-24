import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const pluginRoot = path.join(repositoryRoot, "plugins", "svlt");
const marketplacePath = path.join(repositoryRoot, ".agents", "plugins", "marketplace.json");
const hookScriptPath = path.join(pluginRoot, "hooks", "validate_secret_output.js");

describe("Codex plugin package", () => {
  it("declares a repo-local marketplace entry", async () => {
    const marketplace = await readJson(marketplacePath);
    const entry = marketplace.plugins.find((candidate: { name?: string }) => {
      return candidate.name === "svlt";
    });

    expect(marketplace.name).toBe("personal");
    expect(entry).toEqual({
      name: "svlt",
      source: {
        source: "local",
        path: "./plugins/svlt"
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

    expect(manifest.name).toBe("svlt");
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
    const server = mcp.mcpServers.SVLT;

    expect(server.command).toBe("node");
    expect(server.args.join(" ")).toContain("${PLUGIN_ROOT}");
    expect(server.args.join(" ")).toContain("mcp-server/dist/server.js");
  });

  it("documents the non-plaintext operating rules in the bundled skill and hook", async () => {
    const skill = await readFile(
      path.join(pluginRoot, "skills", "svlt", "SKILL.md"),
      "utf8"
    );
    const hookConfig = await readFile(path.join(pluginRoot, "hooks", "hooks.json"), "utf8");
    const hookScript = await readFile(hookScriptPath, "utf8");
    const combined = `${skill}\n${hookConfig}\n${hookScript}`.toLowerCase();

    expect(combined).toContain("never request plaintext from mcp");
    expect(combined).toContain("never echo resolved credentials");
    expect(combined).toContain("use `secret://` references");
    expect(combined).toMatch(/plaintext|secretvalue|resolvedarguments|masterkey/);
    expect(skill).toContain("SVLT is opt-in");
    expect(skill).toContain("USER_EXPLICIT_PLAINTEXT");
    expect(skill).toContain("do not force conversion to `secret://`");
    expect(skill).not.toContain("only safe representation");
    expect(hookScript).toContain("isSVLTManagedEvent");
    expect(hookScript).toContain("Unknown-origin events are therefore fail-open");
    expect(hookScript).toContain("USER_EXPLICIT_PLAINTEXT");
    expect(hookScript).toContain("SVLT_TOOL_NAMES");
    expect(hookScript).not.toContain('startsWith("secret_")');
  });

  it("requires explicit SVLT provenance before blocking a tool result", async () => {
    const unknownThirdPartyTool = await runHook(hookScriptPath, {
      tool_name: "secret_manager_query",
      result: { plaintext: true }
    });
    const nearSVLTIdentity = await runHook(hookScriptPath, {
      mcpServer: "svltish",
      result: { plaintext: true }
    });
    const explicitUserPlaintext = await runHook(hookScriptPath, {
      credentialScope: "USER_EXPLICIT_PLAINTEXT",
      tool_name: "secret_search",
      result: { plaintext: true }
    });
    const explicitSVLTIdentity = await runHook(hookScriptPath, {
      mcpServer: "SVLT",
      toolName: "secret_search",
      result: { plaintext: true }
    });
    const explicitSVLTScope = await runHook(hookScriptPath, {
      credentialScope: "SVLT_MANAGED_OPERATION",
      toolName: "third_party_tool",
      result: { plaintext: true }
    });

    expect(unknownThirdPartyTool).toBe(0);
    expect(nearSVLTIdentity).toBe(0);
    expect(explicitUserPlaintext).toBe(0);
    expect(explicitSVLTIdentity).toBe(1);
    expect(explicitSVLTScope).toBe(1);
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

function runHook(scriptPath: string, payload: unknown): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath], {
      stdio: ["pipe", "ignore", "ignore"]
    });
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? -1));
    child.stdin.end(JSON.stringify(payload));
  });
}
