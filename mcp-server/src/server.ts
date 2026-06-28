#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { LocalIpcClient } from "./client.js";
import {
  ExecutionRequest,
  IpcRequest,
  IpcResponse,
  SecretPolicy,
  SecretReference
} from "./protocol.js";

export interface VaultIpcClient {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export interface VaultToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodType;
  outputSchema: z.ZodType;
  handler(input: unknown): Promise<CallToolResult>;
}

const StatusOutput = z
  .union([
    z.object({ locked: z.boolean() }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Vault lock status or non-sensitive status code");

const RevealOutput = z
  .object({ status: z.string().min(1) })
  .strict()
  .describe("Reveal request status. Plaintext is shown only inside the macOS app.");

const CreateOutput = z
  .union([
    z.object({ reference: SecretReference }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("New secret reference or non-sensitive status code");

const ExecuteOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        exitCode: z.number().int(),
        stdout: z.string(),
        stderr: z.string()
      })
      .strict(),
    z
      .object({
        status: z.literal("QUARANTINED"),
        reason: z.string().min(1)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Sanitized execution result or non-sensitive status code");

const EmptyInput = z.object({}).strict();

const RevealInput = z
  .object({
    reference: SecretReference,
    reason: z.string().min(1)
  })
  .strict();

const ParagraphRevealInput = z
  .object({
    references: z.array(SecretReference).min(1),
    template: z.string().min(1),
    reason: z.string().min(1)
  })
  .strict();

const CreateInput = z
  .object({
    label: z.string().nullable().optional(),
    policy: SecretPolicy
  })
  .strict();

const ExecuteInput = ExecutionRequest.describe(
  "Execution request with secret slots restricted to secret:// references"
);

export function createVaultToolDefinitions(client: VaultIpcClient): VaultToolDefinition[] {
  return [
    {
      name: "vault_status",
      title: "Vault Status",
      description:
        "Checks whether Agent Secret Vault is available and locked. Plaintext is never returned.",
      inputSchema: EmptyInput,
      outputSchema: StatusOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "status" });
        if (response.type === "status") {
          return structuredResult({ locked: response.locked });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_reveal_request",
      title: "Request Secret Reveal",
      description:
        "Asks the macOS app to reveal a secret to the user locally. Plaintext is never returned.",
      inputSchema: RevealInput,
      outputSchema: RevealOutput,
      async handler(input) {
        const parsed = RevealInput.parse(input);
        const response = await client.request({
          type: "reveal",
          reference: parsed.reference,
          reason: parsed.reason
        });
        if (response.type === "displayedToUser") {
          return structuredResult({ status: "DISPLAYED_TO_USER" });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "paragraph_reveal_request",
      title: "Request Paragraph Reveal",
      description:
        "Asks the macOS app to display a paragraph locally with referenced secrets filled in. Plaintext is never returned.",
      inputSchema: ParagraphRevealInput,
      outputSchema: RevealOutput,
      async handler(input) {
        const parsed = ParagraphRevealInput.parse(input);
        const response = await client.request({
          type: "revealReferences",
          references: parsed.references,
          context: {
            reason: parsed.reason,
            template: parsed.template,
            ranges: parsed.references.map((_, index) => ({
              index,
              placeholder: `{{${index}}}`
            }))
          }
        });
        if (response.type === "revealSessionOpened") {
          return structuredResult({ status: "DISPLAYED_TO_USER" });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_create_request",
      title: "Create Secret From App Selection",
      description:
        "First-release compatibility endpoint for app-side selection encryption. It may return SELECTION_ENCRYPT_UNAVAILABLE until the macOS selection bridge is enabled. Plaintext is never returned.",
      inputSchema: CreateInput,
      outputSchema: CreateOutput,
      async handler(input) {
        const parsed = CreateInput.parse(input);
        const response = await client.request({
          type: "encrypt",
          label: parsed.label,
          policy: parsed.policy
        });
        if (response.type === "created") {
          return structuredResult({ reference: response.reference });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secure_execute",
      title: "Secure Execute",
      description:
        "First-release compatibility endpoint for allowlisted local execution. It may return EXECUTE_UNAVAILABLE until the execution bridge is enabled. Plaintext is never returned.",
      inputSchema: ExecuteInput,
      outputSchema: ExecuteOutput,
      async handler(input) {
        const parsed = ExecuteInput.parse(input);
        const response = await client.request({
          type: "execute",
          request: parsed
        });

        if (response.type !== "execution") {
          return structuredResult(statusOnly(response));
        }

        if (response.result.type === "completed") {
          return structuredResult({
            status: "COMPLETED",
            exitCode: response.result.exitCode,
            stdout: response.result.stdout,
            stderr: response.result.stderr
          });
        }

        return structuredResult({
          status: "QUARANTINED",
          reason: response.result.reason
        });
      }
    }
  ];
}

export function createMcpServer(client: VaultIpcClient = new LocalIpcClient()): McpServer {
  const server = new McpServer({
    name: "agent-secret-vault",
    version: "0.1.0"
  });

  registerVaultTools(server, client);
  return server;
}

export function registerVaultTools(server: McpServer, client: VaultIpcClient): void {
  for (const tool of createVaultToolDefinitions(client)) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        outputSchema: tool.outputSchema
      },
      async (input) => tool.handler(input)
    );
  }
}

export async function runStdioServer(client: VaultIpcClient = new LocalIpcClient()): Promise<void> {
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}

function structuredResult(structuredContent: Record<string, unknown>): CallToolResult {
  return {
    structuredContent,
    content: [
      {
        type: "text",
        text: JSON.stringify(structuredContent)
      }
    ]
  };
}

function statusOnly(response: IpcResponse): Record<string, string> {
  if (response.type === "failure") {
    return { status: response.code };
  }
  return { status: "UNEXPECTED_RESPONSE" };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runStdioServer();
}
