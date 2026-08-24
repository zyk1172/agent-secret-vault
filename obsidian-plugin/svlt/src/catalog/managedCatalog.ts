/**
 * The plugin only classifies the document. Parsing, semantic reconciliation
 * and writes stay in the macOS Catalog coordinator so Obsidian never
 * canonicalizes a user's Markdown.
 */
export type ManagedCatalogFormat = "unmanaged" | "legacy" | "managedV2" | "managedV3";

export const MANAGED_CATALOG_V3_MARKER = '<!-- SVLT-CATALOG schema="3" -->';
export const MANAGED_CATALOG_V2_MARKER = '<!-- SVLT-MANAGED-CATALOG schema="2" -->';
export const LEGACY_CATALOG_MARKER = "agent-secret-vault-sensitive-information: 1";

export const MANAGED_CATALOG_MARKERS = [
  MANAGED_CATALOG_V3_MARKER,
  MANAGED_CATALOG_V2_MARKER,
  LEGACY_CATALOG_MARKER
] as const;

export function classifyCatalogText(text: string): ManagedCatalogFormat {
  const normalized = text.replace(/\r\n?/g, "\n");
  if (normalized.startsWith(MANAGED_CATALOG_V3_MARKER)) return "managedV3";
  if (normalized.startsWith(MANAGED_CATALOG_V2_MARKER)) return "managedV2";
  if (normalized.includes(LEGACY_CATALOG_MARKER)) return "legacy";
  return "unmanaged";
}

export function isManagedCatalogText(text: string): boolean {
  return classifyCatalogText(text) !== "unmanaged";
}

export function isManagedV3CatalogText(text: string): boolean {
  return classifyCatalogText(text) === "managedV3";
}
