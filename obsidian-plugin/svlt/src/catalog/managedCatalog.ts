/**
 * Managed catalog detection is intentionally marker-based.  The Obsidian
 * plugin must not parse, infer, or rewrite the catalog document; the App's
 * Catalog Store is the only authority for its Markdown/JSON representation.
 */
export const MANAGED_CATALOG_MARKERS = [
  '<!-- SVLT-MANAGED-CATALOG schema="2" -->',
  "<!-- agent-secret-vault-sensitive-information: 1 -->"
] as const;

export function isManagedCatalogText(text: string): boolean {
  return MANAGED_CATALOG_MARKERS.some((marker) => text.includes(marker));
}
