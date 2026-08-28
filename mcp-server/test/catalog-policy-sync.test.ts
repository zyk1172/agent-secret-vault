import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const policySurfaces = [
  "Sources/VaultCore/Models/SVLTAgentCatalogPolicy.swift",
  "mcp-server/src/server.ts",
  "docs/svlt-agent-policy-zh-CN.md",
  "docs/agent-integration.md",
  "docs/universal-agent-usage.md",
  "plugins/svlt/skills/svlt/SKILL.md"
];

const requiredPolicyTokens = [
  "secret_catalog_list_indices",
  "secret_catalog_create_structure",
  "secret_catalog_request_secure_inputs",
  "secret_catalog_secure_input_status",
  "PENDING",
  "requestID",
  "sidecar",
  "敏感信息.md",
  "device-owner authentication",
  "plaintext"
];

describe("Catalog policy synchronization", () => {
  it("keeps the required discovery, layout, and secure-input rules on every surface", async () => {
    const contents = await Promise.all(
      policySurfaces.map(async (relativePath) => {
        const content = await readFile(path.join(repositoryRoot, relativePath), "utf8");
        return { relativePath, content };
      })
    );

    for (const { relativePath, content } of contents) {
      for (const token of requiredPolicyTokens) {
        expect(content, `${relativePath} is missing ${token}`).toContain(token);
      }
    }
  });

  it("keeps the new embedded policy rules aligned between Swift and MCP", async () => {
    const swift = await readFile(
      path.join(repositoryRoot, "Sources/VaultCore/Models/SVLTAgentCatalogPolicy.swift"),
      "utf8"
    );
    const mcp = await readFile(path.join(repositoryRoot, "mcp-server/src/server.ts"), "utf8");

    for (const rule of [
      "39. SVLT 自己生成或受控插入的 managed Catalog 使用",
      "40. 新建 Index 必须插入最后一个合法 SVLT-INDEX 之后、尾部非托管 Markdown 之前",
      "41. 新生成 Index 之间使用 renderer 的标准 Markdown 分隔",
      "42. 同一 Index 内的 Entry 之间使用统一的双空行视觉间距",
      "43. Catalog 写入遵守最小修改原则",
      "44. Agent 浏览必须使用 secret_catalog_list_indices、secret_catalog_list_entries、secret_catalog_get",
      "45. 需要用户输入秘密时使用 secret_catalog_request_secure_inputs"
    ]) {
      expect(swift).toContain(rule);
      expect(mcp).toContain(rule);
    }
  });
});
