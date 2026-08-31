#!/usr/bin/env node
"use strict";

// Safety contract:
// - Never request plaintext from MCP for SVLT-managed credentials.
// - Never echo resolved credentials from an SVLT-managed operation.
// - Use `secret://` references for credentials the user chose to manage.
// - This hook is opt-in too: it must not globally police another provider or
//   user-selected plaintext. Unknown-origin events are therefore fail-open.

const forbiddenKeyPattern = /plaintext|secretValue|resolvedArguments|masterKey/i;
const SVLT_IDENTITIES = new Set([
  "SVLT",
  "svlt",
  "svlt-mcp",
  "agent-secret-vault",
  "agent-secret-vault-mcp",
  "com.agent-secret-vault.svlt"
]);
const SVLT_TOOL_NAMES = new Set([
  "vault_status",
  "agent_secret_usage_policy",
  "secret_search",
  "secret_catalog_search",
  "secret_catalog_get",
  "secret_catalog_create_draft",
  "secret_catalog_patch_metadata",
  "secret_catalog_commit",
  "secret_catalog_add_secret_placeholder",
  "secret_catalog_bind_existing_secret",
  "secret_catalog_validate",
  "secret_action_router",
  "secret_auto_handle_text",
  "secret_inspect_reference",
  "secret_reveal_request",
  "paragraph_reveal_request",
  "export_resolved_text_to_local_file",
  "secret_create_request",
  "ssh_command_with_secret",
  "local_http_request_with_secret",
  "api_request_with_token",
  "database_query_with_secret",
  "sftp_transfer_with_secret",
  "ftp_transfer_with_secret",
  "browser_web_login_with_secret",
  "local_app_form_fill_with_secret"
]);
const IDENTITY_KEYS = [
  "provider",
  "server",
  "serverName",
  "server_name",
  "mcpServer",
  "mcp_server",
  "mcpServerName"
];
const TOOL_KEYS = ["tool", "toolName", "tool_name"];

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  if (input.trim().length === 0) {
    process.exit(0);
  }

  let payload;
  try {
    payload = JSON.parse(input);
  } catch {
    process.exit(0);
  }

  if (!isSVLTManagedEvent(payload)) {
    process.exit(0);
  }

  const forbiddenKeys = collectForbiddenKeys(payload);
  if (forbiddenKeys.length > 0) {
    process.stderr.write("Blocked SVLT output with disallowed sensitive fields.\n");
    process.exit(1);
  }

  process.exit(0);
});

function isSVLTManagedEvent(payload) {
  if (payload === null || typeof payload !== "object") {
    return false;
  }

  const scope = firstString(payload, ["credentialScope", "scope"]);
  if (scope === "USER_EXPLICIT_PLAINTEXT" || scope === "EXTERNAL_PROVIDER_OPERATION") {
    return false;
  }
  if (scope === "SVLT_MANAGED_OPERATION") {
    return true;
  }

  if (hasExactString(payload, IDENTITY_KEYS, SVLT_IDENTITIES)) {
    return true;
  }

  return hasExactString(payload, TOOL_KEYS, SVLT_TOOL_NAMES);
}

function normalize(value) {
  return value.trim().toLowerCase();
}

function firstString(value, keys) {
  for (const key of keys) {
    if (typeof value[key] === "string") {
      return value[key];
    }
  }
  return undefined;
}

function hasExactString(value, keys, allowedValues) {
  return keys.some((key) => {
    return typeof value[key] === "string" && allowedValues.has(normalize(value[key]));
  });
}

function collectForbiddenKeys(value) {
  if (Array.isArray(value)) {
    return value.flatMap(collectForbiddenKeys);
  }

  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, nestedValue]) => {
      const matches = forbiddenKeyPattern.test(key) ? [key] : [];
      return matches.concat(collectForbiddenKeys(nestedValue));
    });
  }

  return [];
}
