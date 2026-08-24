#!/usr/bin/env node
"use strict";

// Safety contract:
// - Never request plaintext from MCP for SVLT-managed credentials.
// - Never echo resolved credentials from an SVLT-managed operation.
// - Use `secret://` references for credentials the user chose to manage.
// - This hook is opt-in too: it must not globally police another provider or
//   user-selected plaintext. Unknown-origin events are therefore fail-open.

const forbiddenKeyPattern = /plaintext|secretValue|resolvedArguments|masterKey/i;

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

  const origin = firstString(payload, [
    "provider",
    "server",
    "serverName",
    "server_name",
    "mcpServer",
    "mcp_server",
    "tool",
    "toolName",
    "tool_name"
  ]);
  if (!origin) {
    return false;
  }

  return origin.toLowerCase().includes("svlt") || origin.toLowerCase().startsWith("secret_");
}

function firstString(value, keys) {
  for (const key of keys) {
    if (typeof value[key] === "string") {
      return value[key];
    }
  }
  return undefined;
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
