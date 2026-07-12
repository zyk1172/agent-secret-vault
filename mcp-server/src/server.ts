#!/usr/bin/env node
import { spawn } from "node:child_process";
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
  SecretReference,
  SecretReferenceMetadata
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

export interface SafeHttpResponse {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export type SafeHttpFetch = (
  url: string,
  init: {
    method: "GET" | "HEAD" | "POST";
    headers: Record<string, string>;
    signal: AbortSignal;
    redirect: "manual";
    body?: string;
  }
) => Promise<SafeHttpResponse>;

export interface SshCommandRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  command: string;
  timeoutMs: number;
}

export interface SshCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type SecretSshRunner = (request: SshCommandRequest) => Promise<SshCommandResult>;

export interface DatabaseQueryRequest {
  engine: "postgres" | "mysql";
  host: string;
  port?: number;
  database: string;
  username: string;
  password: string;
  query: string;
  timeoutMs: number;
  maxRows: number;
}

export interface DatabaseQueryResult {
  rowCount?: number;
  rowsPreview?: string;
  stderr?: string;
}

export type SecretDatabaseRunner = (request: DatabaseQueryRequest) => Promise<DatabaseQueryResult>;

export interface FileTransferRequest {
  protocol: "sftp" | "scp";
  operation: "list" | "download" | "upload";
  host: string;
  port: number;
  username: string;
  password: string;
  remotePath: string;
  localPath?: string;
  timeoutMs: number;
}

export interface FileTransferResult {
  listingPreview?: string;
  localPath?: string;
  remotePath?: string;
  stderr?: string;
}

export type SecretFileTransferRunner = (request: FileTransferRequest) => Promise<FileTransferResult>;

export interface BrowserLoginRequest {
  browser: "Safari" | "Chrome";
  url: string;
  username?: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  submit: boolean;
  timeoutMs: number;
}

export interface BrowserLoginResult {
  url?: string;
  note?: string;
}

export type SecretBrowserLoginRunner = (request: BrowserLoginRequest) => Promise<BrowserLoginResult>;

export interface LocalAppFillRequest {
  appName?: string;
  bundleId?: string;
  fields: Array<{ name: string; value: string }>;
  submitButton?: string;
  timeoutMs: number;
}

export interface LocalAppFillResult {
  filledFields?: string[];
  note?: string;
}

export type SecretLocalAppFillRunner = (request: LocalAppFillRequest) => Promise<LocalAppFillResult>;

export interface SecretLocalActionPolicy {
  hosts: {
    allowLocalhost: boolean;
    allowDotLocal: boolean;
    allowPrivateIPv4: boolean;
    allowedHosts: string[];
  };
  ssh: {
    allowedRisks: Array<"read">;
    blockedCommandNames: string[];
    blockShellSubstitution: boolean;
    blockRedirection: boolean;
    maxCommandLength: number;
    defaultTimeoutMs: number;
  };
  output: {
    maxChars: number;
  };
}

export interface VaultToolOptions {
  fetch?: SafeHttpFetch;
  sshRunner?: SecretSshRunner;
  databaseRunner?: SecretDatabaseRunner;
  fileTransferRunner?: SecretFileTransferRunner;
  browserLoginRunner?: SecretBrowserLoginRunner;
  localAppFillRunner?: SecretLocalAppFillRunner;
  policy?: SecretLocalActionPolicy;
}

export const defaultSecretLocalActionPolicy: SecretLocalActionPolicy = {
  hosts: {
    allowLocalhost: true,
    allowDotLocal: true,
    allowPrivateIPv4: true,
    allowedHosts: []
  },
  ssh: {
    allowedRisks: ["read"],
    blockedCommandNames: [
      "rm",
      "rmdir",
      "mv",
      "dd",
      "mkfs",
      "mount",
      "umount",
      "reboot",
      "shutdown",
      "poweroff",
      "halt",
      "init",
      "sudo",
      "su",
      "passwd",
      "chpasswd",
      "useradd",
      "userdel",
      "groupadd",
      "groupdel",
      "chmod",
      "chown",
      "kill",
      "killall",
      "pkill"
    ],
    blockShellSubstitution: true,
    blockRedirection: true,
    maxCommandLength: 2_000,
    defaultTimeoutMs: 15_000
  },
  output: {
    maxChars: 16_384
  }
};

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

const ExportOutput = z
  .union([
    z.object({ status: z.literal("EXPORTED"), path: z.string().min(1) }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local file export status. Plaintext is never returned.");

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

const InspectOutput = z
  .union([
    z
      .object({
        reference: SecretReference,
        policy: SecretPolicy,
        label: z.string().nullable(),
        createdAt: z.union([z.string(), z.number()]),
        updatedAt: z.union([z.string(), z.number()])
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Non-sensitive metadata for a secret reference. Plaintext is never returned.");

const LocalHttpOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        httpStatus: z.number().int(),
        contentType: z.string().nullable(),
        redacted: z.literal(true),
        bodyPreview: z.string().optional()
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local HTTP result. Secret material is used only inside the MCP process and is never returned.");

const LocalSshOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        exitCode: z.number().int(),
        stdout: z.string(),
        stderr: z.string(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local SSH result. Secret material is used only inside the MCP process and plaintext is never returned.");

const ApiRequestOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        httpStatus: z.number().int(),
        contentType: z.string().nullable(),
        redacted: z.literal(true),
        bodyPreview: z.string().optional()
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("API request result. Token material is used only inside the MCP process and plaintext is never returned.");

const DatabaseQueryOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        rowCount: z.number().int().min(0).optional(),
        rowsPreview: z.string().optional(),
        stderr: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Database query result. Secret material is used only inside the MCP process and plaintext is never returned.");

const FileTransferOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        listingPreview: z.string().optional(),
        localPath: z.string().optional(),
        remotePath: z.string().optional(),
        stderr: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("SFTP/SCP result. Secret material is used only inside the MCP process and plaintext is never returned.");

const BrowserLoginOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        url: z.string().optional(),
        note: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Browser login fill result. Secret material is used only inside the MCP process and plaintext is never returned.");

const LocalAppFillOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        filledFields: z.array(z.string()).optional(),
        note: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local app form fill result. Secret material is used only inside the MCP process and plaintext is never returned.");

const AgentPolicyOutput = z
  .object({
    status: z.literal("OK"),
    intendedClients: z.array(z.string().min(1)),
    conversationRule: z.string().min(1),
    referenceRule: z.string().min(1),
    safeWorkflow: z.array(z.string().min(1)),
    forbidden: z.array(z.string().min(1)),
    safeTools: z.array(z.string().min(1))
  })
  .strict()
  .describe("Non-sensitive usage policy for MCP-capable agents. Plaintext is never returned.");

const AutoHandleOutput = z
  .object({
    status: z.string().min(1),
    action: z.string().min(1),
    referenceCount: z.number().int().min(0),
    references: z.array(SecretReference),
    redactedText: z.string().optional()
  })
  .strict()
  .describe("Automatic secret:// text handling result. Plaintext is never returned.");

const EmptyInput = z.object({}).strict();

const RevealInput = z
  .object({
    reference: SecretReference,
    reason: z.string().min(1)
  })
  .strict();

const ParagraphRevealInput = z
  .object({
    text: z.string().min(1).optional(),
    references: z.array(SecretReference).min(1).optional(),
    template: z.string().min(1).optional(),
    reason: z.string().min(1)
  })
  .strict()
  .refine((value) => value.text !== undefined || (value.references !== undefined && value.template !== undefined), {
    message: "Provide either text containing secret:// references, or references plus a {{0}} template."
  });

const ExportResolvedTextInput = z
  .object({
    text: z.string().min(1).optional(),
    references: z.array(SecretReference).min(1).optional(),
    template: z.string().min(1).optional(),
    reason: z.string().min(1),
    destinationPath: z.string().min(1)
  })
  .strict()
  .refine((value) => value.text !== undefined || (value.references !== undefined && value.template !== undefined), {
    message: "Provide either text containing secret:// references, or references plus a {{0}} template."
  });

const CreateInput = z
  .object({
    label: z.string().nullable().optional(),
    policy: SecretPolicy
  })
  .strict();

const ExecuteInput = ExecutionRequest.describe(
  "Execution request with secret slots restricted to secret:// references"
);

const InspectInput = z
  .object({
    reference: SecretReference.describe("The secret:// reference to inspect. Do not pass metadata or label.")
  })
  .strict();

const LocalHttpInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD"]).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference.optional(),
    includeBodyPreview: z.boolean().optional(),
    timeoutMs: z.number().int().min(100).max(10_000).optional()
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const SshCommandInput = z
  .object({
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    command: z.string().min(1).max(2_000),
    risk: z.enum(["read"]).optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional()
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const ApiRequestInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD", "POST"]).optional(),
    tokenRef: SecretReference,
    headerName: z.string().min(1).max(128).optional(),
    headerScheme: z.string().min(1).max(64).optional(),
    body: z.string().max(65_536).optional(),
    includeBodyPreview: z.boolean().optional(),
    timeoutMs: z.number().int().min(100).max(10_000).optional()
  })
  .strict();

const DatabaseQueryInput = z
  .object({
    engine: z.enum(["postgres", "mysql"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    database: z.string().min(1).max(256),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    query: z.string().min(1).max(20_000),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    maxRows: z.number().int().min(1).max(100).optional()
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const FileTransferInput = z
  .object({
    protocol: z.enum(["sftp", "scp"]).optional(),
    operation: z.enum(["list", "download", "upload"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    remotePath: z.string().min(1).max(4_096),
    localPath: z.string().min(1).max(4_096).optional(),
    timeoutMs: z.number().int().min(1_000).max(60_000).optional()
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const BrowserLoginInput = z
  .object({
    browser: z.enum(["Safari", "Chrome"]).optional(),
    url: z.string().url(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    usernameSelector: z.string().min(1).max(1_024).optional(),
    passwordSelector: z.string().min(1).max(1_024),
    submitSelector: z.string().min(1).max(1_024).optional(),
    submit: z.boolean().optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional()
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .refine((value) => value.submit !== true || value.submitSelector !== undefined, {
    message: "submitSelector is required when submit is true."
  });

const LocalAppFillInput = z
  .object({
    appName: z.string().min(1).max(256).optional(),
    bundleId: z.string().min(1).max(256).optional(),
    fields: z.array(z
      .object({
        name: z.string().min(1).max(256),
        value: z.string().max(4_096).optional(),
        valueRef: SecretReference.optional()
      })
      .strict()
      .refine((value) => value.value === undefined || value.valueRef === undefined, {
        message: "Use either value or valueRef, not both."
      })
      .refine((value) => value.value !== undefined || value.valueRef !== undefined, {
        message: "Each field requires value or valueRef."
      })).min(1).max(20),
    submitButton: z.string().min(1).max(256).optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional()
  })
  .strict()
  .refine((value) => value.appName !== undefined || value.bundleId !== undefined, {
    message: "appName or bundleId is required."
  });

const SecretActionRouterInput = z
  .discriminatedUnion("intent", [
    SshCommandInput.extend({
      intent: z.literal("ssh_command")
    }).strict(),
    LocalHttpInput.extend({
      intent: z.literal("local_http_request")
    }).strict(),
    ExportResolvedTextInput.extend({
      intent: z.literal("export_resolved_text")
    }).strict(),
    ApiRequestInput.extend({
      intent: z.literal("api_request")
    }).strict(),
    DatabaseQueryInput.extend({
      intent: z.literal("database_query")
    }).strict(),
    FileTransferInput.extend({
      intent: z.literal("sftp_transfer")
    }).strict(),
    BrowserLoginInput.extend({
      intent: z.literal("browser_web_login")
    }).strict(),
    LocalAppFillInput.extend({
      intent: z.literal("local_app_form_fill")
    }).strict()
  ]);

const AutoHandleTextInput = z
  .object({
    text: z.string().min(1),
    intent: z.enum(["inspect", "reveal_to_user"]).optional(),
    reason: z.string().min(1).optional()
  })
  .strict();

export function createVaultToolDefinitions(
  client: VaultIpcClient,
  options: VaultToolOptions = {}
): VaultToolDefinition[] {
  const safeFetch = options.fetch ?? defaultSafeFetch;
  const sshRunner = options.sshRunner ?? defaultSshRunner;
  const databaseRunner = options.databaseRunner ?? defaultDatabaseRunner;
  const fileTransferRunner = options.fileTransferRunner ?? defaultFileTransferRunner;
  const browserLoginRunner = options.browserLoginRunner;
  const localAppFillRunner = options.localAppFillRunner;
  const policy = options.policy ?? defaultSecretLocalActionPolicy;

  return [
    {
      name: "secret_action_router",
      title: "Secret Local Action Router",
      description:
        "Routes secret:// references to allowlisted local actions such as SSH, HTTP/API, SFTP/SCP, database, browser login, app form fill, or local file export. Plaintext is never returned.",
      inputSchema: SecretActionRouterInput,
      outputSchema: z.union([
        LocalSshOutput,
        LocalHttpOutput,
        ExportOutput,
        ApiRequestOutput,
        DatabaseQueryOutput,
        FileTransferOutput,
        BrowserLoginOutput,
        LocalAppFillOutput
      ]),
      async handler(input) {
        const parsed = SecretActionRouterInput.parse(input);
        if (parsed.intent === "ssh_command") {
          return handleSshCommandWithSecret(client, sshRunner, policy, parsed);
        }
        if (parsed.intent === "local_http_request") {
          return handleLocalHttpRequest(client, safeFetch, policy, parsed);
        }
        if (parsed.intent === "export_resolved_text") {
          return handleExportResolvedText(client, parsed);
        }
        if (parsed.intent === "api_request") {
          return handleApiRequestWithToken(client, safeFetch, policy, parsed);
        }
        if (parsed.intent === "database_query") {
          return handleDatabaseQueryWithSecret(client, databaseRunner, policy, parsed);
        }
        if (parsed.intent === "sftp_transfer") {
          return handleFileTransferWithSecret(client, fileTransferRunner, policy, parsed);
        }
        if (parsed.intent === "browser_web_login") {
          return handleBrowserLoginWithSecret(client, browserLoginRunner, policy, parsed);
        }
        return handleLocalAppFillWithSecret(client, localAppFillRunner, policy, parsed);
      }
    },
    {
      name: "agent_secret_usage_policy",
      title: "Agent Secret Usage Policy",
      description:
        "Returns non-sensitive rules for using Agent Secret Vault from Codex, Claude, Hermes, or other MCP-capable agents. Plaintext is never returned.",
      inputSchema: EmptyInput,
      outputSchema: AgentPolicyOutput,
      async handler(input) {
        EmptyInput.parse(input);
        return structuredResult(agentSecretUsagePolicy());
      }
    },
    {
      name: "secret_auto_handle_text",
      title: "Auto Handle Secret References In Text",
      description:
        "Automatically detects secret:// references in text and either reports safe reference handling or opens a local app-owned reveal session. Plaintext is never returned.",
      inputSchema: AutoHandleTextInput,
      outputSchema: AutoHandleOutput,
      async handler(input) {
        const parsed = AutoHandleTextInput.parse(input);
        const references = extractSecretReferences(parsed.text);
        const redactedText = redactSecretReferences(parsed.text);
        if (references.length === 0) {
          return structuredResult({
            status: "NO_REFERENCES",
            action: "NO_ACTION",
            referenceCount: 0,
            references: [],
            redactedText
          });
        }

        if ((parsed.intent ?? "inspect") === "inspect") {
          return structuredResult({
            status: "REFERENCES_DETECTED",
            action: "KEEP_REFERENCES_OPAQUE",
            referenceCount: references.length,
            references,
            redactedText
          });
        }

        const revealRequest = buildRevealRequestFromText(parsed.text);
        const response = await client.request({
          type: "revealReferences",
          references: revealRequest.references,
          context: {
            reason: parsed.reason ?? "Automatic local reveal for secret:// references",
            template: revealRequest.context.template,
            ranges: revealRequest.context.ranges
          }
        });

        if (response.type === "revealSessionOpened") {
          return structuredResult({
            status: "DISPLAYED_TO_USER",
            action: "LOCAL_APP_REVEAL",
            referenceCount: references.length,
            references,
            redactedText
          });
        }
        return structuredResult({
          ...statusOnly(response),
          action: "LOCAL_APP_REVEAL_FAILED",
          referenceCount: references.length,
          references,
          redactedText
        });
      }
    },
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
      name: "secret_inspect_reference",
      title: "Inspect Secret Reference",
      description:
        "Returns only non-sensitive metadata for one secret:// reference. Input must be { reference }. Do not pass metadata or label. Plaintext is never returned.",
      inputSchema: InspectInput,
      outputSchema: InspectOutput,
      async handler(input) {
        const parsed = InspectInput.parse(input);
        const response = await client.request({
          type: "inspectReference",
          reference: parsed.reference
        });
        if (response.type === "referenceMetadata") {
          return structuredResult(metadataResult(response.metadata));
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
        "Asks the macOS app to display a paragraph locally with referenced secrets filled in. Prefer input { text, reason } where text contains secret:// references; advanced callers may pass { references, template, reason } with {{0}} placeholders. Plaintext is never returned.",
      inputSchema: ParagraphRevealInput,
      outputSchema: RevealOutput,
      async handler(input) {
        const parsed = ParagraphRevealInput.parse(input);
        const revealRequest = revealRequestFromParagraphInput(parsed);
        const response = await client.request({
          type: "revealReferences",
          references: revealRequest.references,
          context: {
            reason: parsed.reason,
            template: revealRequest.context.template,
            ranges: revealRequest.context.ranges
          }
        });
        if (response.type === "revealSessionOpened") {
          return structuredResult({ status: "DISPLAYED_TO_USER" });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "export_resolved_text_to_local_file",
      title: "Export Resolved Text To Local File",
      description:
        "Asks the macOS app to resolve secret:// references and write the filled text to a new .md or .txt file on the user's Desktop. Prefer input { text, reason, destinationPath }. Plaintext is never returned.",
      inputSchema: ExportResolvedTextInput,
      outputSchema: ExportOutput,
      async handler(input) {
        return handleExportResolvedText(client, ExportResolvedTextInput.parse(input));
      }
    },
    {
      name: "ssh_command_with_secret",
      title: "SSH Command With Secret",
      description:
        "Uses a secret:// password inside the MCP process for a restricted local/private-network SSH command. Plaintext is never returned.",
      inputSchema: SshCommandInput,
      outputSchema: LocalSshOutput,
      async handler(input) {
        return handleSshCommandWithSecret(client, sshRunner, policy, SshCommandInput.parse(input));
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
    },
    {
      name: "local_http_request_with_secret",
      title: "Local HTTP Request With Secret",
      description:
        "Uses secret:// credentials inside the MCP process for a restricted local GET/HEAD HTTP request. Plaintext is never returned.",
      inputSchema: LocalHttpInput,
      outputSchema: LocalHttpOutput,
      async handler(input) {
        return handleLocalHttpRequest(client, safeFetch, policy, LocalHttpInput.parse(input));
      }
    },
    {
      name: "api_request_with_token",
      title: "API Request With Token",
      description:
        "Uses a secret:// API token inside the MCP process for a restricted allowlisted GET/HEAD/POST API request. Plaintext is never returned.",
      inputSchema: ApiRequestInput,
      outputSchema: ApiRequestOutput,
      async handler(input) {
        return handleApiRequestWithToken(client, safeFetch, policy, ApiRequestInput.parse(input));
      }
    },
    {
      name: "database_query_with_secret",
      title: "Database Query With Secret",
      description:
        "Uses secret:// database credentials inside a purpose-built local runner for a restricted read-only query. Plaintext is never returned.",
      inputSchema: DatabaseQueryInput,
      outputSchema: DatabaseQueryOutput,
      async handler(input) {
        return handleDatabaseQueryWithSecret(client, databaseRunner, policy, DatabaseQueryInput.parse(input));
      }
    },
    {
      name: "sftp_transfer_with_secret",
      title: "SFTP/SCP Transfer With Secret",
      description:
        "Uses secret:// credentials inside a purpose-built local runner for restricted SFTP/SCP list/download/upload actions. Plaintext is never returned.",
      inputSchema: FileTransferInput,
      outputSchema: FileTransferOutput,
      async handler(input) {
        return handleFileTransferWithSecret(client, fileTransferRunner, policy, FileTransferInput.parse(input));
      }
    },
    {
      name: "browser_web_login_with_secret",
      title: "Browser Web Login With Secret",
      description:
        "Uses secret:// credentials inside a browser automation runner to fill a specific local/private web login form. Plaintext is never returned.",
      inputSchema: BrowserLoginInput,
      outputSchema: BrowserLoginOutput,
      async handler(input) {
        return handleBrowserLoginWithSecret(client, browserLoginRunner, policy, BrowserLoginInput.parse(input));
      }
    },
    {
      name: "local_app_form_fill_with_secret",
      title: "Local App Form Fill With Secret",
      description:
        "Uses secret:// values inside a local app automation runner to fill a specific macOS app form. Plaintext is never returned.",
      inputSchema: LocalAppFillInput,
      outputSchema: LocalAppFillOutput,
      async handler(input) {
        return handleLocalAppFillWithSecret(client, localAppFillRunner, policy, LocalAppFillInput.parse(input));
      }
    }
  ];
}

export function createMcpServer(client: VaultIpcClient = new LocalIpcClient()): McpServer {
  const server = new McpServer({
    name: "agent-secret-vault",
    version: "0.1.10"
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
        inputSchema: tool.inputSchema
      },
      async (input) => {
        const result = await tool.handler(input);
        if (!result.isError) {
          if (result.structuredContent === undefined) {
            throw new Error(`Tool ${tool.name} returned no structuredContent`);
          }
          await tool.outputSchema.parseAsync(result.structuredContent);
        }
        return result;
      }
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

function statusFromError(error: unknown, fallback: string): string {
  if (error instanceof Error && /^[A-Z0-9_]+$/.test(error.message)) {
    return error.message;
  }
  return fallback;
}

function metadataResult(metadata: SecretReferenceMetadata): Record<string, unknown> {
  return {
    reference: metadata.reference,
    policy: metadata.policy,
    label: metadata.label,
    createdAt: metadata.createdAt,
    updatedAt: metadata.updatedAt
  };
}

async function handleExportResolvedText(
  client: VaultIpcClient,
  parsed: z.infer<typeof ExportResolvedTextInput>
): Promise<CallToolResult> {
  const revealRequest = revealRequestFromExportInput(parsed);
  const response = await client.request({
    type: "exportResolvedText",
    references: revealRequest.references,
    destinationPath: parsed.destinationPath,
    context: {
      reason: parsed.reason,
      template: revealRequest.context.template,
      ranges: revealRequest.context.ranges
    }
  });
  if (response.type === "exported") {
    return structuredResult({ status: "EXPORTED", path: response.path });
  }
  return structuredResult(statusOnly(response));
}

async function handleLocalHttpRequest(
  client: VaultIpcClient,
  safeFetch: SafeHttpFetch,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof LocalHttpInput>
): Promise<CallToolResult> {
  const method = parsed.method ?? "GET";
  const parsedUrl = new URL(parsed.url);

  if (!isAllowedLocalUrl(parsedUrl, policy)) {
    return structuredResult({ status: "URL_NOT_ALLOWED" });
  }
  if (parsedUrl.username !== "" || parsedUrl.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  const hasUsernameInput = parsed.username !== undefined || parsed.usernameRef !== undefined;
  const hasPasswordInput = parsed.passwordRef !== undefined;
  if (hasUsernameInput !== hasPasswordInput) {
    return structuredResult({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
  }

  const secretsUsed: string[] = [];
  let username: string | undefined;
  let password: string | undefined;
  try {
    username = parsed.usernameRef === undefined
      ? parsed.username
      : await resolveSingleSecret(client, parsed.usernameRef, "Use local device username");
    password = parsed.passwordRef === undefined
      ? undefined
      : await resolveSingleSecret(client, parsed.passwordRef, "Use local device password");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "REQUEST_FAILED") });
  }
  if (parsed.usernameRef !== undefined && username !== undefined) {
    secretsUsed.push(username);
  }
  if (password !== undefined) {
    secretsUsed.push(password);
  }

  const headers: Record<string, string> = {};
  if (username !== undefined && password !== undefined) {
    const basicToken = Buffer.from(`${username}:${password}`, "utf8").toString("base64");
    headers.Authorization = `Basic ${basicToken}`;
    secretsUsed.push(basicToken);
    secretsUsed.push(encodeURIComponent(username));
    secretsUsed.push(encodeURIComponent(password));
  } else if (username !== undefined || password !== undefined) {
    return structuredResult({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), parsed.timeoutMs ?? 5_000);
  try {
    const response = await safeFetch(parsedUrl.toString(), {
      method,
      headers,
      signal: controller.signal,
      redirect: "manual"
    });
    const rawContentType = response.headers.get("content-type");
    const contentType = rawContentType === null
      ? null
      : sanitizeSecretText(rawContentType, secretsUsed, policy);
    if (method === "HEAD" || parsed.includeBodyPreview !== true) {
      return structuredResult({
        status: "COMPLETED",
        httpStatus: response.status,
        contentType,
        redacted: true
      });
    }
    const body = await response.text();
    return structuredResult({
      status: "COMPLETED",
      httpStatus: response.status,
      contentType,
      redacted: true,
      bodyPreview: sanitizeSecretText(body, secretsUsed, policy)
    });
  } catch {
    return structuredResult({ status: "REQUEST_FAILED" });
  } finally {
    clearTimeout(timeout);
  }
}

async function handleSshCommandWithSecret(
  client: VaultIpcClient,
  sshRunner: SecretSshRunner,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof SshCommandInput>
): Promise<CallToolResult> {
  if (!isAllowedLocalHost(parsed.host, policy)) {
    return structuredResult({ status: "HOST_NOT_ALLOWED" });
  }
  if (!isAllowedSshRisk(parsed.risk ?? "read", policy)) {
    return structuredResult({ status: "RISK_NOT_ALLOWED" });
  }
  if (!isAllowedSshCommand(parsed.command, policy)) {
    return structuredResult({ status: "COMMAND_NOT_ALLOWED" });
  }

  const secretsUsed: string[] = [];
  let username: string | undefined;
  try {
    username = parsed.usernameRef === undefined
      ? parsed.username
      : await resolveSingleSecret(client, parsed.usernameRef, "Use SSH username for local device");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "SSH_REQUEST_FAILED") });
  }
  if (parsed.usernameRef !== undefined && username !== undefined) {
    secretsUsed.push(username);
  }
  if (username === undefined) {
    return structuredResult({ status: "SSH_USERNAME_REQUIRED" });
  }

  let password: string;
  try {
    password = await resolveSingleSecret(client, parsed.passwordRef, "Use SSH password for local device");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "SSH_REQUEST_FAILED") });
  }
  secretsUsed.push(password);

  try {
    const result = await sshRunner({
      host: parsed.host,
      port: parsed.port ?? 22,
      username,
      password,
      command: parsed.command,
      timeoutMs: parsed.timeoutMs ?? policy.ssh.defaultTimeoutMs
    });

    return structuredResult({
      status: "COMPLETED",
      exitCode: result.exitCode,
      stdout: sanitizeSecretText(result.stdout, secretsUsed, policy),
      stderr: sanitizeSecretText(result.stderr, secretsUsed, policy),
      redacted: true
    });
  } catch {
    return structuredResult({ status: "SSH_REQUEST_FAILED" });
  }
}

async function handleApiRequestWithToken(
  client: VaultIpcClient,
  safeFetch: SafeHttpFetch,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof ApiRequestInput>
): Promise<CallToolResult> {
  const parsedUrl = new URL(parsed.url);
  if (!isAllowedLocalUrl(parsedUrl, policy)) {
    return structuredResult({ status: "URL_NOT_ALLOWED" });
  }
  if (parsedUrl.username !== "" || parsedUrl.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  if (hasCredentialQueryParameter(parsedUrl)) {
    return structuredResult({ status: "URL_TOKEN_NOT_ALLOWED" });
  }

  const method = parsed.method ?? "GET";
  const headerName = parsed.headerName ?? "Authorization";
  const headerScheme = parsed.headerScheme ?? "Bearer";

  let token: string;
  try {
    token = await resolveSingleSecret(client, parsed.tokenRef, "Use API token for restricted local/API request");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "REQUEST_FAILED") });
  }
  const headerValue = headerScheme.length === 0 ? token : `${headerScheme} ${token}`;
  const secretsUsed = [
    token,
    encodeURIComponent(token),
    headerValue,
    Buffer.from(token, "utf8").toString("base64")
  ];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), parsed.timeoutMs ?? 5_000);
  try {
    const response = await safeFetch(parsedUrl.toString(), {
      method,
      headers: { [headerName]: headerValue },
      signal: controller.signal,
      redirect: "manual",
      body: parsed.body
    });
    const rawContentType = response.headers.get("content-type");
    const contentType = rawContentType === null
      ? null
      : sanitizeSecretText(rawContentType, secretsUsed, policy);
    if (method === "HEAD" || parsed.includeBodyPreview !== true) {
      return structuredResult({
        status: "COMPLETED",
        httpStatus: response.status,
        contentType,
        redacted: true
      });
    }
    const body = await response.text();
    return structuredResult({
      status: "COMPLETED",
      httpStatus: response.status,
      contentType,
      redacted: true,
      bodyPreview: sanitizeSecretText(body, secretsUsed, policy)
    });
  } catch {
    return structuredResult({ status: "REQUEST_FAILED" });
  } finally {
    clearTimeout(timeout);
  }
}

async function handleDatabaseQueryWithSecret(
  client: VaultIpcClient,
  databaseRunner: SecretDatabaseRunner | undefined,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof DatabaseQueryInput>
): Promise<CallToolResult> {
  if (!isAllowedLocalHost(parsed.host, policy)) {
    return structuredResult({ status: "HOST_NOT_ALLOWED" });
  }
  if (!isReadOnlySingleStatement(parsed.query)) {
    return structuredResult({ status: "QUERY_NOT_ALLOWED" });
  }
  if (databaseRunner === undefined) {
    return structuredResult({ status: "DATABASE_RUNNER_UNAVAILABLE" });
  }

  const secretsUsed: string[] = [];
  const usernameResult = await resolveOptionalUsername(
    client,
    parsed.username,
    parsed.usernameRef,
    "Use database username for local/private database"
  );
  if (!usernameResult.ok) {
    return structuredResult({ status: usernameResult.status });
  }
  if (usernameResult.wasSecret && usernameResult.value !== undefined) {
    secretsUsed.push(usernameResult.value);
  }
  if (usernameResult.value === undefined) {
    return structuredResult({ status: "DATABASE_USERNAME_REQUIRED" });
  }

  let password: string;
  try {
    password = await resolveSingleSecret(client, parsed.passwordRef, "Use database password for local/private database");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "DATABASE_REQUEST_FAILED") });
  }
  secretsUsed.push(password);

  try {
    const result = await databaseRunner({
      engine: parsed.engine,
      host: parsed.host,
      port: parsed.port,
      database: parsed.database,
      username: usernameResult.value,
      password,
      query: parsed.query,
      timeoutMs: parsed.timeoutMs ?? 10_000,
      maxRows: parsed.maxRows ?? 20
    });
    return structuredResult({
      status: "COMPLETED",
      ...(result.rowCount === undefined ? {} : { rowCount: result.rowCount }),
      ...(result.rowsPreview === undefined ? {} : { rowsPreview: sanitizeSecretText(result.rowsPreview, secretsUsed, policy) }),
      ...(result.stderr === undefined ? {} : { stderr: sanitizeSecretText(result.stderr, secretsUsed, policy) }),
      redacted: true
    });
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "DATABASE_REQUEST_FAILED") });
  }
}

async function handleFileTransferWithSecret(
  client: VaultIpcClient,
  fileTransferRunner: SecretFileTransferRunner | undefined,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof FileTransferInput>
): Promise<CallToolResult> {
  if (!isAllowedLocalHost(parsed.host, policy)) {
    return structuredResult({ status: "HOST_NOT_ALLOWED" });
  }
  if (!isSafeTransferPath(parsed.remotePath) || (parsed.localPath !== undefined && !isSafeTransferPath(parsed.localPath))) {
    return structuredResult({ status: "PATH_NOT_ALLOWED" });
  }
  if ((parsed.operation === "download" || parsed.operation === "upload") && parsed.localPath === undefined) {
    return structuredResult({ status: "LOCAL_PATH_REQUIRED" });
  }
  if ((parsed.protocol ?? "sftp") === "scp" && parsed.operation === "list") {
    return structuredResult({ status: "OPERATION_NOT_ALLOWED" });
  }
  if (fileTransferRunner === undefined) {
    return structuredResult({ status: "FILE_TRANSFER_RUNNER_UNAVAILABLE" });
  }

  const secretsUsed: string[] = [];
  const usernameResult = await resolveOptionalUsername(
    client,
    parsed.username,
    parsed.usernameRef,
    "Use SFTP/SCP username for local/private device"
  );
  if (!usernameResult.ok) {
    return structuredResult({ status: usernameResult.status });
  }
  if (usernameResult.wasSecret && usernameResult.value !== undefined) {
    secretsUsed.push(usernameResult.value);
  }
  if (usernameResult.value === undefined) {
    return structuredResult({ status: "FILE_TRANSFER_USERNAME_REQUIRED" });
  }

  let password: string;
  try {
    password = await resolveSingleSecret(client, parsed.passwordRef, "Use SFTP/SCP password for local/private device");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "FILE_TRANSFER_REQUEST_FAILED") });
  }
  secretsUsed.push(password);

  try {
    const result = await fileTransferRunner({
      protocol: parsed.protocol ?? "sftp",
      operation: parsed.operation,
      host: parsed.host,
      port: parsed.port ?? 22,
      username: usernameResult.value,
      password,
      remotePath: parsed.remotePath,
      localPath: parsed.localPath,
      timeoutMs: parsed.timeoutMs ?? 30_000
    });
    return structuredResult({
      status: "COMPLETED",
      ...(result.listingPreview === undefined ? {} : { listingPreview: sanitizeSecretText(result.listingPreview, secretsUsed, policy) }),
      ...(result.localPath === undefined ? {} : { localPath: result.localPath }),
      ...(result.remotePath === undefined ? {} : { remotePath: result.remotePath }),
      ...(result.stderr === undefined ? {} : { stderr: sanitizeSecretText(result.stderr, secretsUsed, policy) }),
      redacted: true
    });
  } catch {
    return structuredResult({ status: "FILE_TRANSFER_REQUEST_FAILED" });
  }
}

async function handleBrowserLoginWithSecret(
  client: VaultIpcClient,
  browserLoginRunner: SecretBrowserLoginRunner | undefined,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof BrowserLoginInput>
): Promise<CallToolResult> {
  const parsedUrl = new URL(parsed.url);
  if (!isAllowedLocalUrl(parsedUrl, policy)) {
    return structuredResult({ status: "URL_NOT_ALLOWED" });
  }
  if (parsedUrl.username !== "" || parsedUrl.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  if (browserLoginRunner === undefined) {
    return structuredResult({ status: "SAFE_AUTOFILL_UNAVAILABLE" });
  }

  const secretsUsed: string[] = [];
  const usernameResult = await resolveOptionalUsername(
    client,
    parsed.username,
    parsed.usernameRef,
    "Use browser login username for local/private web form"
  );
  if (!usernameResult.ok) {
    return structuredResult({ status: usernameResult.status });
  }
  if (usernameResult.wasSecret && usernameResult.value !== undefined) {
    secretsUsed.push(usernameResult.value);
  }

  let password: string;
  try {
    password = await resolveSingleSecret(client, parsed.passwordRef, "Use browser login password for local/private web form");
  } catch (error) {
    return structuredResult({ status: statusFromError(error, "BROWSER_LOGIN_FAILED") });
  }
  secretsUsed.push(password);

  try {
    const result = await browserLoginRunner({
      browser: parsed.browser ?? "Safari",
      url: parsed.url,
      username: usernameResult.value,
      password,
      usernameSelector: parsed.usernameSelector,
      passwordSelector: parsed.passwordSelector,
      submitSelector: parsed.submitSelector,
      submit: parsed.submit ?? false,
      timeoutMs: parsed.timeoutMs ?? 15_000
    });
    return structuredResult({
      status: "COMPLETED",
      ...(result.url === undefined ? {} : { url: sanitizeSecretText(result.url, secretsUsed, policy) }),
      ...(result.note === undefined ? {} : { note: sanitizeSecretText(result.note, secretsUsed, policy) }),
      redacted: true
    });
  } catch {
    return structuredResult({ status: "BROWSER_LOGIN_FAILED" });
  }
}

async function handleLocalAppFillWithSecret(
  client: VaultIpcClient,
  localAppFillRunner: SecretLocalAppFillRunner | undefined,
  policy: SecretLocalActionPolicy,
  parsed: z.infer<typeof LocalAppFillInput>
): Promise<CallToolResult> {
  if (localAppFillRunner === undefined) {
    return structuredResult({ status: "SAFE_AUTOFILL_UNAVAILABLE" });
  }

  const secretsUsed: string[] = [];
  const fields: Array<{ name: string; value: string }> = [];
  for (const field of parsed.fields) {
    if (field.valueRef === undefined) {
      fields.push({ name: field.name, value: field.value ?? "" });
      continue;
    }
    try {
      const value = await resolveSingleSecret(client, field.valueRef, `Use local app form field ${field.name}`);
      secretsUsed.push(value);
      fields.push({ name: field.name, value });
    } catch (error) {
      return structuredResult({ status: statusFromError(error, "LOCAL_APP_FILL_FAILED") });
    }
  }

  try {
    const result = await localAppFillRunner({
      appName: parsed.appName,
      bundleId: parsed.bundleId,
      fields,
      submitButton: parsed.submitButton,
      timeoutMs: parsed.timeoutMs ?? 15_000
    });
    return structuredResult({
      status: "COMPLETED",
      ...(result.filledFields === undefined ? {} : { filledFields: result.filledFields }),
      ...(result.note === undefined ? {} : { note: sanitizeSecretText(result.note, secretsUsed, policy) }),
      redacted: true
    });
  } catch {
    return structuredResult({ status: "LOCAL_APP_FILL_FAILED" });
  }
}

function agentSecretUsagePolicy(): Record<string, unknown> {
  return {
    status: "OK",
    intendedClients: ["Codex", "Claude", "Hermes", "Other MCP-capable agents"],
    conversationRule:
      "Keep secret:// references in the conversation. Do not ask the user to paste decrypted values into chat.",
    referenceRule:
      "Treat every secret:// reference as an opaque handle. Do not infer, classify, summarize, or transform the hidden value.",
    safeWorkflow: [
      "When text contains secret:// references, call secret_auto_handle_text first unless a narrower safe tool is clearly required.",
      "Call vault_status before work that depends on the app.",
      "Use secret_inspect_reference for non-sensitive metadata only.",
      "Use secret_reveal_request or paragraph_reveal_request when the user needs to see plaintext locally.",
      "Use secret_action_router for local actions that need decrypted material without exposing it to the agent.",
      "Use ssh_command_with_secret for restricted local/private-network SSH commands that need a password reference.",
      "Use local_http_request_with_secret for restricted local/private HTTP checks that need basic auth.",
      "Use api_request_with_token for restricted allowlisted API requests that need a token reference.",
      "Use database_query_with_secret for restricted read-only database queries through a purpose-built runner.",
      "Use sftp_transfer_with_secret for restricted SFTP/SCP list/download/upload actions through a purpose-built runner.",
      "Use browser_web_login_with_secret for specific local/private web login form fills.",
      "Use local_app_form_fill_with_secret for specific macOS app form fills through a purpose-built runner.",
      "Use export_resolved_text_to_local_file when the user explicitly wants the app to write resolved sensitive text into a local file without returning it to the agent.",
      "Use a purpose-built MCP tool that resolves references internally when a local operation needs the real value.",
      "If no safe tool exists for the requested operation, stop and ask for a new allowlisted tool instead of requesting plaintext."
    ],
    forbidden: [
      "Do not request plaintext from the app or user in chat.",
      "Do not echo, log, summarize, or store decrypted values.",
      "Do not put raw credentials into MCP inputs; use secret:// references.",
      "Do not treat encrypted reference text as if it revealed the secret value.",
      "Do not send a secret to public networks unless the user explicitly approved that policy and an allowlisted tool enforces it."
    ],
    safeTools: [
      "secret_action_router",
      "secret_auto_handle_text",
      "vault_status",
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
      "browser_web_login_with_secret",
      "local_app_form_fill_with_secret",
      "secure_execute"
    ]
  };
}

function extractSecretReferences(text: string): string[] {
  return [...new Set(Array.from(text.matchAll(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g), (match) => match[0]))];
}

function redactSecretReferences(text: string): string {
  return text.replace(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g, "[SECRET_REFERENCE]");
}

function buildRevealRequestFromText(text: string): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  const references: string[] = [];
  const ranges: Array<{ index: number; placeholder: string }> = [];
  const template = text.replace(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g, (reference) => {
    const index = references.length;
    const placeholder = `{{${index}}}`;
    references.push(reference);
    ranges.push({ index, placeholder });
    return placeholder;
  });
  return {
    references,
    context: { template, ranges }
  };
}

function revealRequestFromParagraphInput(parsed: z.infer<typeof ParagraphRevealInput>): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  return parsed.text !== undefined
    ? buildRevealRequestFromText(parsed.text)
    : buildRevealRequestFromTemplate(parsed.references ?? [], parsed.template ?? "");
}

function revealRequestFromExportInput(parsed: z.infer<typeof ExportResolvedTextInput>): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  return parsed.text !== undefined
    ? buildRevealRequestFromText(parsed.text)
    : buildRevealRequestFromTemplate(parsed.references ?? [], parsed.template ?? "");
}

function buildRevealRequestFromTemplate(references: string[], template: string): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  const rawTextRequest = buildRevealRequestFromText(template);
  if (rawTextRequest.references.length > 0) {
    return rawTextRequest;
  }
  return {
    references,
    context: {
      template,
      ranges: references.map((_, index) => ({
        index,
        placeholder: `{{${index}}}`
      }))
    }
  };
}

async function resolveSingleSecret(
  client: VaultIpcClient,
  reference: string,
  reason: string
): Promise<string> {
  const response = await client.request({
    type: "restoreReferences",
    references: [reference],
    context: {
      reason,
      template: "{{0}}",
      ranges: [{ index: 0, placeholder: "{{0}}" }]
    }
  });

  if (response.type !== "restoredText") {
    throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
  }
  return response.text;
}

type ResolveOptionalUsernameResult =
  | { ok: true; value: string | undefined; wasSecret: boolean }
  | { ok: false; status: string };

async function resolveOptionalUsername(
  client: VaultIpcClient,
  username: string | undefined,
  usernameRef: string | undefined,
  reason: string
): Promise<ResolveOptionalUsernameResult> {
  if (usernameRef === undefined) {
    return { ok: true, value: username, wasSecret: false };
  }
  try {
    return {
      ok: true,
      value: await resolveSingleSecret(client, usernameRef, reason),
      wasSecret: true
    };
  } catch (error) {
    return { ok: false, status: statusFromError(error, "REQUEST_FAILED") };
  }
}

function hasCredentialQueryParameter(url: URL): boolean {
  for (const key of url.searchParams.keys()) {
    if (/password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie/i.test(key)) {
      return true;
    }
  }
  return false;
}

function isAllowedLocalUrl(url: URL, policy: SecretLocalActionPolicy): boolean {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return false;
  }
  return isAllowedLocalHost(url.hostname, policy);
}

function isAllowedLocalHost(hostname: string, policy: SecretLocalActionPolicy): boolean {
  const normalized = hostname.toLowerCase();
  return hostMatchesPolicy(normalized, policy.hosts.allowedHosts) ||
    (policy.hosts.allowLocalhost && (normalized === "localhost" || normalized === "::1" || normalized === "[::1]")) ||
    (policy.hosts.allowDotLocal && normalized.endsWith(".local")) ||
    (policy.hosts.allowPrivateIPv4 && isAllowedPrivateIPv4(normalized));
}

function hostMatchesPolicy(hostname: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern.startsWith("*.")) {
      return hostname.endsWith(normalizedPattern.slice(1));
    }
    return hostname === normalizedPattern;
  });
}

function isAllowedPrivateIPv4(hostname: string): boolean {
  const parts = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [first, second] = parts;
  return first === 10 ||
    first === 127 ||
    (first === 192 && second === 168) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 169 && second === 254);
}

function isAllowedSshRisk(risk: "read", policy: SecretLocalActionPolicy): boolean {
  return policy.ssh.allowedRisks.includes(risk);
}

function isAllowedSshCommand(command: string, policy: SecretLocalActionPolicy): boolean {
  if (command.length > policy.ssh.maxCommandLength) {
    return false;
  }
  if (/[\r\n\0]/.test(command)) {
    return false;
  }
  if (policy.ssh.blockShellSubstitution && (/[`]/.test(command) || /\$\(/.test(command))) {
    return false;
  }
  if (policy.ssh.blockRedirection && /(^|\s)(>|>>|<|2>|2>>|&>)/.test(command)) {
    return false;
  }
  const blocked = policy.ssh.blockedCommandNames
    .map(escapeRegExp)
    .join("|");
  if (blocked.length > 0 && new RegExp(`\\b(${blocked})\\b`, "i").test(command)) {
    return false;
  }
  return true;
}

function isReadOnlySingleStatement(query: string): boolean {
  const trimmed = query.trim();
  if (trimmed.length === 0) {
    return false;
  }
  const withoutTrailingSemicolon = trimmed.endsWith(";") ? trimmed.slice(0, -1) : trimmed;
  if (withoutTrailingSemicolon.includes(";")) {
    return false;
  }
  if (!/^(select|with|show|describe|explain)\b/i.test(withoutTrailingSemicolon)) {
    return false;
  }
  if (/\b(insert|update|delete|drop|alter|create|truncate|copy|grant|revoke|replace|merge|attach|detach|load|call|execute|do)\b/i.test(withoutTrailingSemicolon)) {
    return false;
  }
  if (/--|\/\*|\*\//.test(withoutTrailingSemicolon)) {
    return false;
  }
  return true;
}

function isSafeTransferPath(path: string): boolean {
  if (/[\0\r\n]/.test(path)) {
    return false;
  }
  if (path.includes("..")) {
    return false;
  }
  if (/[*?[\]{};$`|&<>"\\]/.test(path)) {
    return false;
  }
  return true;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sanitizeSecretText(
  text: string,
  secretsUsed: string[],
  policy: SecretLocalActionPolicy
): string {
  let sanitized = text.slice(0, policy.output.maxChars);
  for (const secret of secretsUsed.filter((value) => value.length > 0)) {
    sanitized = sanitized.split(secret).join("[REDACTED_SECRET]");
  }
  sanitized = sanitized
    .replace(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g, "[REDACTED_REFERENCE]")
    .replace(/(["']?(?:password|passwd|pwd|token|secret|api[_-]?key|credential|cookie|authorization)["']?\s*:\s*["'])[^"']+/gi, "$1[REDACTED_SECRET]")
    .replace(/(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*["']?[^"',\s}]+/gi, "$1=[REDACTED_SECRET]")
    .replace(/Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/gi, "Authorization: Basic [REDACTED_SECRET]")
    .replace(/Authorization:\s*Bearer\s+[^"',\s}]+/gi, "Authorization: Bearer [REDACTED_SECRET]")
    .replace(/(["']?authorization["']?\s*[:=]\s*["']?)Basic\s+[A-Za-z0-9+/=]+/gi, "$1Basic [REDACTED_SECRET]")
    .replace(/(["']?authorization["']?\s*[:=]\s*["']?)Bearer\s+[^"',\s}]+/gi, "$1Bearer [REDACTED_SECRET]")
    .replace(/(set-cookie|cookie)\s*[:=]\s*["']?[^"',\n\r}]+/gi, "$1=[REDACTED_SECRET]");
  return sanitized;
}

const defaultSafeFetch: SafeHttpFetch = async (url, init) => fetch(url, init);

const defaultDatabaseRunner: SecretDatabaseRunner = async (request) => {
  if (request.engine === "postgres") {
    const pg = await import("pg");
    const client = new pg.Client({
      host: request.host,
      port: request.port ?? 5432,
      database: request.database,
      user: request.username,
      password: request.password,
      connectionTimeoutMillis: request.timeoutMs,
      statement_timeout: request.timeoutMs
    });
    await client.connect();
    try {
      const result = await client.query(request.query);
      const rows = Array.isArray(result.rows) ? result.rows.slice(0, request.maxRows) : [];
      return {
        rowCount: typeof result.rowCount === "number" ? result.rowCount : rows.length,
        rowsPreview: JSON.stringify(rows)
      };
    } finally {
      await client.end();
    }
  }

  const mysql = await import("mysql2/promise");
  const connection = await mysql.createConnection({
    host: request.host,
    port: request.port ?? 3306,
    database: request.database,
    user: request.username,
    password: request.password,
    connectTimeout: request.timeoutMs
  });
  try {
    const [rows] = await connection.query({
      sql: request.query,
      timeout: request.timeoutMs,
      rowsAsArray: false
    });
    const rowArray = Array.isArray(rows) ? rows.slice(0, request.maxRows) : [];
    return {
      rowCount: Array.isArray(rows) ? rows.length : 0,
      rowsPreview: JSON.stringify(rowArray)
    };
  } finally {
    await connection.end();
  }
};

function buildExpectPasswordScript(timeoutSeconds: number, transferArgs: string[], commands: string[]): string {
  return `
set timeout ${timeoutSeconds}
set transferArgs [list ${transferArgs.map(tclWord).join(" ")}]
set commands [list ${commands.map(tclWord).join(" ")}]
set commandIndex 0
if {[gets stdin password] < 0} {
  exit 125
}
log_user 0
spawn {*}$transferArgs
expect {
  -re "(?i)are you sure you want to continue connecting" {
    send -- "yes\\r"
    exp_continue
  }
  -re "(?i)(password|passcode).*:" {
    send -- "$password\\r"
    log_user 1
    exp_continue
  }
  -re "sftp> $" {
    if {$commandIndex < [llength $commands]} {
      send -- "[lindex $commands $commandIndex]\\r"
      incr commandIndex
      exp_continue
    }
  }
  eof {}
  timeout {
    exit 124
  }
}
set waitResult [wait]
set exitCode [lindex $waitResult 3]
exit $exitCode
`;
}

function sftpPath(value: string): string {
  return `"${value.replaceAll('"', '\\"')}"`;
}

function fileTransferArgsAndCommands(request: FileTransferRequest): {
  args: string[];
  commands: string[];
} {
  const timeoutSeconds = Math.max(1, Math.ceil(request.timeoutMs / 1_000));
  const commonOptions = [
    "-o", "BatchMode=no",
    "-o", "PubkeyAuthentication=no",
    "-o", "KbdInteractiveAuthentication=yes",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", `ConnectTimeout=${timeoutSeconds}`,
    "-o", "StrictHostKeyChecking=accept-new"
  ];
  if (request.protocol === "sftp") {
    const commands = request.operation === "list"
      ? [`ls -la ${sftpPath(request.remotePath)}`, "bye"]
      : request.operation === "download"
        ? [`get ${sftpPath(request.remotePath)} ${sftpPath(request.localPath ?? "")}`, "bye"]
        : [`put ${sftpPath(request.localPath ?? "")} ${sftpPath(request.remotePath)}`, "bye"];
    return {
      args: [
        "sftp",
        ...commonOptions,
        "-P", String(request.port),
        `${request.username}@${request.host}`
      ],
      commands
    };
  }

  if (request.operation === "download") {
    return {
      args: [
        "scp",
        ...commonOptions,
        "-P", String(request.port),
        `${request.username}@${request.host}:${request.remotePath}`,
        request.localPath ?? ""
      ],
      commands: []
    };
  }
  return {
    args: [
      "scp",
      ...commonOptions,
      "-P", String(request.port),
      request.localPath ?? "",
      `${request.username}@${request.host}:${request.remotePath}`
    ],
    commands: []
  };
}

const defaultFileTransferRunner: SecretFileTransferRunner = async (request) => new Promise((resolve, reject) => {
  const timeoutSeconds = Math.max(1, Math.ceil(request.timeoutMs / 1_000));
  const { args, commands } = fileTransferArgsAndCommands(request);
  const child = spawn("/usr/bin/expect", [
    "-c",
    buildExpectPasswordScript(timeoutSeconds, args, commands)
  ], {
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let settled = false;
  const settle = (callback: () => void) => {
    if (!settled) {
      settled = true;
      callback();
    }
  };
  const timer = setTimeout(() => {
    child.kill("SIGKILL");
    settle(() => reject(new Error("FILE_TRANSFER_TIMEOUT")));
  }, request.timeoutMs + 1_000);

  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  child.on("error", (error) => {
    clearTimeout(timer);
    settle(() => reject(error));
  });
  child.on("close", (code) => {
    clearTimeout(timer);
    settle(() => {
      if (code === 0) {
        resolve({
          ...(request.operation === "list" ? { listingPreview: stdout } : {}),
          ...(request.localPath === undefined ? {} : { localPath: request.localPath }),
          remotePath: request.remotePath,
          stderr
        });
        return;
      }
      reject(new Error(`FILE_TRANSFER_EXIT_${code ?? "UNKNOWN"}`));
    });
  });

  child.stdin.write(request.password);
  child.stdin.write("\n");
  child.stdin.end();
});

function buildExpectSshScript(timeoutSeconds: number, sshArgs: string[]): string {
  return `
set timeout ${timeoutSeconds}
set sshArgs [list ${sshArgs.map(tclWord).join(" ")}]
if {[gets stdin password] < 0} {
  exit 125
}
log_user 0
spawn {*}$sshArgs
expect {
  -re "(?i)are you sure you want to continue connecting" {
    send -- "yes\\r"
    exp_continue
  }
  -re "(?i)(password|passcode).*:" {
    send -- "$password\\r"
    log_user 1
    exp_continue
  }
  eof {}
  timeout {
    exit 124
  }
}
set waitResult [wait]
set exitCode [lindex $waitResult 3]
exit $exitCode
`;
}

function tclWord(value: string): string {
  return `{${value.replaceAll("\\", "\\\\").replaceAll("}", "\\}")}}`;
}

const defaultSshRunner: SecretSshRunner = async (request) => new Promise((resolve, reject) => {
  const timeoutSeconds = Math.max(1, Math.ceil(request.timeoutMs / 1_000));
  const sshArgs = [
    "ssh",
    "-o", "BatchMode=no",
    "-o", "PubkeyAuthentication=no",
    "-o", "KbdInteractiveAuthentication=yes",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", `ConnectTimeout=${timeoutSeconds}`,
    "-o", "StrictHostKeyChecking=accept-new",
    "-p", String(request.port),
    `${request.username}@${request.host}`,
    request.command
  ];
  const child = spawn("/usr/bin/expect", [
    "-c",
    buildExpectSshScript(timeoutSeconds, sshArgs)
  ], {
    stdio: ["pipe", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let settled = false;
  const settle = (callback: () => void) => {
    if (!settled) {
      settled = true;
      callback();
    }
  };

  const killTimer = setTimeout(() => {
    child.kill("SIGTERM");
  }, request.timeoutMs + 1_000);

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  child.on("error", (error) => {
    clearTimeout(killTimer);
    settle(() => reject(error));
  });
  child.on("close", (code) => {
    clearTimeout(killTimer);
    settle(() => resolve({
      exitCode: code ?? -1,
      stdout,
      stderr
    }));
  });
  child.stdin.end(`${request.password}\n`);
});

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runStdioServer();
}
