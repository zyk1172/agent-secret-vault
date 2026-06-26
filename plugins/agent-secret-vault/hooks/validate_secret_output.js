#!/usr/bin/env node
"use strict";

// Safety contract:
// - Never request plaintext from MCP.
// - Never echo resolved credentials.
// - Use `secret://` references.

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

  const forbiddenKeys = collectForbiddenKeys(payload);
  if (forbiddenKeys.length > 0) {
    process.stderr.write("Blocked Agent Secret Vault output with disallowed sensitive fields.\n");
    process.exit(1);
  }

  process.exit(0);
});

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
