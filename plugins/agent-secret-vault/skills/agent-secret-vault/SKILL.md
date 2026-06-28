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
- Treat `secret://` references as opaque handles. Do not infer, classify, summarize, transform, or otherwise describe the hidden value behind a reference.
- Treat reveal as a local user-display action only. `secret_reveal_request` returns `DISPLAYED_TO_USER`; it does not return the secret.
- For paragraph reveal, use `paragraph_reveal_request`; never ask the user to paste plaintext in chat.
- It is OK to discuss visible surrounding context around a reference, but state when that context may leak the likely meaning or use of the hidden value.
- Warn the user when visible surrounding text says password, token, API key, credential, private key, secret, or similar sensitive labels.
- For execution, put normal typed parameters in `values` and put only `secret://` references in `secrets`.
- If a tool result is quarantined or returns a failure status, report the non-sensitive status and ask the user how to proceed.

## Tool usage

- `vault_status`: check whether the app is reachable and whether the vault is locked.
- `secret_create_request`: ask the app to encrypt local selected text and return a `secret://` reference.
- `secret_reveal_request`: ask the app to display a referenced secret locally to the user.
- `paragraph_reveal_request`: ask the app to display a paragraph locally with referenced secrets filled into placeholders; it returns only `DISPLAYED_TO_USER`.
- `secure_execute`: ask the app to execute an allowlisted local template with secrets resolved inside the app boundary.

Do not paste secrets into tool inputs. If a value is sensitive and no `secret://` reference exists, ask the user to create one with the app first.
