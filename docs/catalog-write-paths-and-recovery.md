# Catalog write paths and recovery

## Supported write paths

SVLT has three supported paths into the same Catalog v3 authority:

1. **App writes.** The user acts in SVLT; AppControl calls `VaultAppServices`;
   the mutation enters `SensitiveCatalogDocumentStore`. App actions do not
   require the separate Agent safe-write grant, but secret-bearing semantic
   changes still require local high-risk approval.
2. **Agent/MCP writes.** An Agent calls a purpose-built MCP tool. Safe semantic
   mutations first require a bounded user-approved Agent write grant. The
   existing semantic risk engine remains authoritative.
3. **Direct Markdown writes.** Obsidian, editors, scripts, or an Agent file tool
   may edit `敏感信息.md` directly. On validation SVLT parses the source map,
   computes `CatalogSemanticDiff`, classifies the change, then automatically
   accepts safe changes or holds high-risk changes for approval. Direct file
   access grants no additional authority.

The mutation source is diagnostic only. Risk is derived from semantic change,
not transport.

## Agent write access requests

Agent write starts disabled. `secret_catalog_request_write_access` creates a
structured request containing only source, finite reason category, and bounded
duration (`single-use`, 10 minutes, or 30 minutes). Free-form reason text is not
accepted, logged, audited, or persisted.

SVLT notifies the App and activates it. The user can approve or reject. Approval
grants only safe catalog mutations for the requested bound. Revoke takes effect
on the next mutation. The grant never bypasses plaintext rejection, secretRef
bind/replace/delete approval, or deletion of secret-bearing objects.

## Recovery

Every successful controlled document commit captures the previous verified raw
Markdown as an HMAC-authenticated recovery snapshot. At least the last ten
snapshots are retained. Snapshots store raw Markdown plus revision, timestamp,
raw SHA-256, and semantic SHA-256; they never store decrypted plaintext.

Repair is explicit and requires local approval. Before restore, the current raw
file is copied to an emergency backup that is never treated as trusted state.
Restore validates every opaque reference against a local encrypted record,
writes through the Store's atomic path, and rebuilds verified accepted state.
Missing references fail closed.
