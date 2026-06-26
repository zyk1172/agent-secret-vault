---
name: agent-secret-vault
description: Use Agent Secret Vault MCP tools to work with encrypted secret references while keeping plaintext inside the local macOS app boundary.
---

# Agent Secret Vault

Use this skill whenever a task involves sensitive local values, credentials, tokens, API keys, or other secret material that should not appear in the conversation.

## Required rules

- Never request plaintext from MCP.
- Never echo resolved credentials.
- Use `secret://` references for sensitive values.
- Treat reveal as a local user-display action only. `secret_reveal_request` returns `DISPLAYED_TO_USER`; it does not return the secret.
- For execution, put normal typed parameters in `values` and put only `secret://` references in `secrets`.
- If a tool result is quarantined or returns a failure status, report the non-sensitive status and ask the user how to proceed.

## Tool usage

- `vault_status`: check whether the app is reachable and whether the vault is locked.
- `secret_create_request`: ask the app to encrypt local selected text and return a `secret://` reference.
- `secret_reveal_request`: ask the app to display a referenced secret locally to the user.
- `secure_execute`: ask the app to execute an allowlisted local template with secrets resolved inside the app boundary.

Do not paste secrets into tool inputs. If a value is sensitive and no `secret://` reference exists, ask the user to create one with the app first.
