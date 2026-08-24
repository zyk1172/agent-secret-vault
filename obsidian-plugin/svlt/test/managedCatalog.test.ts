import { describe, expect, it } from "vitest";
import {
  classifyCatalogText,
  isManagedCatalogText,
  isManagedV3CatalogText
} from "../src/catalog/managedCatalog";

describe("managed catalog classification", () => {
  it("recognizes an Obsidian-native v3 document with ordinary Markdown", () => {
    const text = [
      '<!-- SVLT-CATALOG schema="3" -->',
      "# 敏感信息",
      "",
      "[[QNAP]]",
      "## QNAP",
      "### 管理后台",
      "- 备注：[[服务器配置]]"
    ].join("\n");

    expect(classifyCatalogText(text)).toBe("managedV3");
    expect(isManagedCatalogText(text)).toBe(true);
    expect(isManagedV3CatalogText(text)).toBe(true);
  });

  it("keeps v2 and legacy documents on the guarded upgrade path", () => {
    expect(classifyCatalogText('<meta>\n<!-- SVLT-CATALOG schema="3" -->')).toBe("unmanaged");
    expect(classifyCatalogText('<!-- SVLT-MANAGED-CATALOG schema="2" -->\n# 敏感信息')).toBe("managedV2");
    expect(classifyCatalogText("prefix agent-secret-vault-sensitive-information: 1")).toBe("legacy");
    expect(isManagedV3CatalogText('<!-- SVLT-MANAGED-CATALOG schema="2" -->')).toBe(false);
  });
});
