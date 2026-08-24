#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { LocalIpcClient } from "./client.js";
import { credentialSourcePriority } from "./credential-scope.js";
import {
  AgentRiskAssessment,
  CatalogDraft,
  CatalogDraftRequest,
  CatalogMetadataPatch,
  CatalogWriteResult,
  CatalogValidationResult,
  IpcRequest,
  IpcResponse,
  SecretCatalogField,
  SecretCatalogMatch,
  SecretCatalogSearchResult,
  SecretPolicy,
  SecretOperationDescriptor,
  SecretOperationOutput,
  SecretOperationProtocol,
  SecretReference,
  SecretReferenceMetadata
} from "./protocol.js";

const optionalAgentRiskAssessment = AgentRiskAssessment.optional();

// Keep this text aligned with SVLTAgentCatalogPolicy.text.  The Swift value
// is the App's embedded source of truth; this copy is returned by the
// cross-language MCP policy contract and is covered by policy tests.
const SVLT_AGENT_CATALOG_POLICY = `SVLT 敏感信息目录写入规范

SVLT 是 opt-in 的秘密保护工具，只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

1. “敏感信息.md”是由 SVLT 管理的结构化目录，不得使用 shell、编辑器、Python、sed、echo、文件 API 或其他方式直接修改。
2. 只有用户选择使用 SVLT、提供 secret://，或没有指定来源且需要发现 SVLT 记录时，才查询敏感信息：secret_catalog_search / secret_catalog_get。
3. 新增、修改、移动或删除目录数据必须使用 SVLT 提供的 catalog MCP 工具，不得自行拼接或覆盖 Markdown/JSON。
4. 每条数据必须属于一个一级 Index 和一个 Entry/SubIndex。Secret 只能以合法 secret:// 引用存在，禁止在 JSON 中写入密码、Token、API Key、Cookie、私钥或其他秘密明文。
5. 普通元数据只有在字段明确允许 agentVisible 时才可读取或写入；searchable=true 且 agentVisible=false 的字段允许内部命中，但不得返回字段值或命中原因。
6. 不得修改 schema、id、indexId、revision、完整性标记或 SVLT 管理标记。
7. 如果需要的字段或结构当前 MCP 不支持，应停止并告诉用户，不得通过直接修改“敏感信息.md”绕过 SVLT。该规则不阻止用户在本次操作中选择其他明确允许的凭据工具或直接提供明文。
8. 如果用户要求新增记录，应优先通过 Catalog Draft 创建结构；Secret 字段使用 placeholder 或已有 secret:// 引用，需要新秘密时让用户在 SVLT 本机安全表单中填写。
9. 修改后必须调用 secret_catalog_validate；验证失败时不得继续使用或尝试自行修复文件结构。
10. 即使用户要求修改目录，也不代表允许绕过 SVLT；用户授权的是目标操作，不是直接文件写权限。另一方面，用户明确选择本次直接使用明文时，不需要导入、转换、检索、SVLT 授权或 Touch ID。
11. 遇到 LEGACY_CATALOG_UNSUPPORTED 时必须停止；SVLT 不提供旧版目录自动升级，Agent 不得自行转换或修改旧文件。合法的 v2 文件只能由 App 的“验证并接管 v2 文件”流程接管，MCP 不得调用接管操作。
12. Catalog 写入必须使用 App 当前有效的 Agent 编辑授权；授权最长 10 分钟并自动过期。MCP 不携带、生成、延长或伪造 lease/nonce；无授权或授权过期时只能读取和报告状态。

范围与来源优先级：
- SVLT_MANAGED_OPERATION：用户明确要求使用 SVLT、Entry 或 secret://；秘密仍只能在 SVLT 批准的专用操作内解析。
- USER_EXPLICIT_PLAINTEXT：用户在当前请求中亲自提供明文并明确要求本次使用，或明确选择“不使用 SVLT”。即使 SVLT 可能存在相同凭据，本次也不得搜索、比较、替换、阻断或要求审批。
- EXTERNAL_PROVIDER_OPERATION：用户明确选择设备 MCP、GitHub connector、已登录 CLI、环境变量或其他凭据提供方；SVLT 不得抢占。
- UNMANAGED_CREDENTIAL：用户没有选择 SVLT，且没有可用的明确外部来源；不得把它自动升级为 SVLT 管理。
- 来源优先级为：用户当前明确凭据/来源 → 用户明确选择的外部 provider → 用户明确选择的 SVLT → 无明确选择时才自动发现。
- 以上判断只对当前 operation 有效；不得从上一轮对话、旧 provider 选择或 Agent 状态继承来源。每个 operation 只能产生一个最终 credential source decision。
- 不比较用户明文与 SVLT secret 的值，也不因值可能相同而改变 provenance。

用户明文覆盖规则：用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。不要自动创建 Secret、替换为 secret://、要求用户删除明文、打开 SVLT、触发 Touch ID，或仅因 Catalog 中可能已有对应 Secret 而拒绝本次操作。其他工作区、仓库、工具的日志、持久化和外发规则仍然有效。

SVLT 派生明文边界：不得把 secret:// 经 SVLT 解密得到的明文转交普通 shell、curl、URL、header、环境变量、日志或聊天。禁止的是 Agent 自己洗出 SVLT 明文绕过专用操作，不是用户独立重新提供明文。

SVLT 范围之外：设备 MCP 自持凭据、GitHub connector 自有授权、已登录 CLI、环境变量、第三方密码管理器和用户明确提供的当前明文由其各自工具/项目安全规则负责，SVLT 不得自动劫持。`;

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
    z
      .object({
        status: z.string().min(1),
        available: z.boolean().optional(),
        ready: z.boolean().optional(),
        approvalPending: z.boolean().optional()
      })
      .strict(),
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

const InspectOutput = z
  .union([
    z
      .object({
        reference: SecretReference,
        policy: SecretPolicy,
        label: z.string().nullable(),
        allowedDestinations: z.array(z.string()),
        allowedProtocols: z.array(z.string()),
        createdAt: z.union([z.string(), z.number()]),
        updatedAt: z.union([z.string(), z.number()])
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Non-sensitive metadata for a secret reference. Plaintext is never returned.");

const SecretSearchInput = z
  .object({
    query: z.string().trim().min(1).max(256),
    field: SecretCatalogField.optional(),
    limit: z.number().int().min(1).max(20).default(10)
  })
  .strict();

const SecretSearchOutput = z
  .union([
    z
      .object({
        status: z.enum([
          "FOUND",
          "NOT_FOUND",
          "INVALID_QUERY",
          "CATALOG_UNAVAILABLE",
          "LEGACY_CATALOG_UNSUPPORTED",
          "INTEGRITY_MISSING",
          "EXTERNAL_CATALOG_MODIFICATION",
          "CATALOG_INVALID"
        ]),
        matches: z.array(SecretCatalogMatch)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Opaque secret catalog matches. Plaintext and catalog file locations are never returned.");

const CatalogGetInput = z.object({ entryID: z.string().length(26) }).strict();

const CatalogCreateDraftInput = z
  .object({ request: CatalogDraftRequest })
  .strict();

const CatalogPatchMetadataInput = z
  .object({
    entryID: z.string().length(26),
    patch: CatalogMetadataPatch,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogCommitInput = z
  .object({
    draft: CatalogDraft,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogPlaceholderInput = z
  .object({
    entryID: z.string().length(26),
    key: z.string().min(1),
    label: z.string().min(1),
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogBindInput = z
  .object({
    entryID: z.string().length(26),
    key: z.string().min(1),
    secretRef: SecretReference,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogWriteOutput = z
  .union([
    CatalogWriteResult,
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Catalog write result. Secret plaintext is never accepted or returned.");

const CatalogDraftOutput = z
  .union([CatalogDraft, z.object({ status: z.string().min(1) }).strict()])
  .describe("Catalog draft containing only visible metadata and opaque secret references.");

const CatalogValidationOutput = z
  .union([
    z.object({ status: z.string().min(1), revision: z.number().int().nonnegative().nullable().optional() }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Catalog validation status; it never returns document content.");

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
  .describe("Local HTTP result. Secret material is used only inside SVLTAgent and is never returned.");

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
  .describe("Local SSH result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

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
  .describe("API request result. Token material is used only inside SVLTAgent and plaintext is never returned.");

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
  .describe("Database query result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

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
  .describe("SFTP/SCP result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

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
  .describe("Browser login fill result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

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
  .describe("Local app form fill result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const AgentPolicyOutput = z
  .object({
    status: z.literal("OK"),
    intendedClients: z.array(z.string().min(1)),
    conversationRule: z.string().min(1),
    referenceRule: z.string().min(1),
    catalogPolicy: z.string().min(1),
    scopeRule: z.object({
      managed: z.string().min(1),
      unmanaged: z.string().min(1),
      explicitPlaintext: z.string().min(1),
      externalProvider: z.string().min(1)
    }).strict(),
    userOverrideRule: z.string().min(1),
    outOfScopeRule: z.array(z.string().min(1)),
    credentialSourcePriority: z.array(z.string().min(1)),
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
    reason: z.string().min(1),
    agentAssessment: optionalAgentRiskAssessment
  })
  .strict();

const ParagraphRevealInput = z
  .object({
    text: z.string().min(1).optional(),
    references: z.array(SecretReference).min(1).optional(),
    template: z.string().min(1).optional(),
    reason: z.string().min(1),
    agentAssessment: optionalAgentRiskAssessment
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
    destinationPath: z.string().min(1),
    agentAssessment: optionalAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.text !== undefined || (value.references !== undefined && value.template !== undefined), {
    message: "Provide either text containing secret:// references, or references plus a {{0}} template."
  });

const CreateInput = z
  .object({
    label: z.string().nullable().optional(),
    policy: SecretPolicy,
    allowedDestinations: z.array(z.string().min(1)).max(32).optional(),
    allowedProtocols: z.array(SecretOperationProtocol).max(16).optional()
  })
  .strict();

const InspectInput = z
  .object({
    reference: SecretReference.describe("The secret:// reference to inspect. Do not pass metadata or label.")
  })
  .strict();

const LocalHttpInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference.optional(),
    includeBodyPreview: z.boolean().optional(),
    timeoutMs: z.number().int().min(100).max(10_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
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
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const ApiRequestInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    tokenRef: SecretReference,
    headerName: z.string().min(1).max(128).optional(),
    headerScheme: z.string().min(1).max(64).optional(),
    body: z.string().max(65_536).optional(),
    includeBodyPreview: z.boolean().optional(),
    timeoutMs: z.number().int().min(100).max(10_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
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
    maxRows: z.number().int().min(1).max(100).optional(),
    agentAssessment: optionalAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  });

const FileTransferInput = z
  .object({
    protocol: z.enum(["sftp", "scp"]).optional(),
    operation: z.enum(["list", "download", "upload", "overwrite", "delete"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    remotePath: z.string().min(1).max(4_096),
    localPath: z.string().min(1).max(4_096).optional(),
    timeoutMs: z.number().int().min(1_000).max(60_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
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
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
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
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: optionalAgentRiskAssessment
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

export function createVaultToolDefinitions(client: VaultIpcClient): VaultToolDefinition[] {
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
          return handleSshCommandWithSecret(client, parsed);
        }
        if (parsed.intent === "local_http_request") {
          return handleLocalHttpRequest(client, parsed);
        }
        if (parsed.intent === "export_resolved_text") {
          return handleExportResolvedText(client, parsed);
        }
        if (parsed.intent === "api_request") {
          return handleApiRequestWithToken(client, parsed);
        }
        if (parsed.intent === "database_query") {
          return handleDatabaseQueryWithSecret(client, parsed);
        }
        if (parsed.intent === "sftp_transfer") {
          return handleFileTransferWithSecret(client, parsed);
        }
        if (parsed.intent === "browser_web_login") {
          return handleBrowserLoginWithSecret(client, parsed);
        }
        return handleLocalAppFillWithSecret(client, parsed);
      }
    },
    {
      name: "agent_secret_usage_policy",
      title: "SVLT Usage Policy",
      description:
        "Returns non-sensitive rules for using SVLT from Codex, Claude, Hermes, or other MCP-capable agents. Plaintext is never returned.",
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
            ranges: revealRequest.context.ranges,
            agentAssessment: {
              declaredRisk: "silent",
              reason: "Automatic local reveal request",
              intendedEffect: "display to local user"
            }
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
        "Checks whether SVLT is available and the local operation policy engine is ready; locked is compatibility-only. Plaintext is never returned.",
      inputSchema: EmptyInput,
      outputSchema: StatusOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "workbenchStatus" });
        if (response.type === "workbenchStatus") {
          return structuredResult({
            status: response.status.ready ? "READY" : "UNAVAILABLE",
            available: response.status.available,
            ready: response.status.ready,
            approvalPending: response.status.approvalPending
          });
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
      name: "secret_search",
      title: "Search Secret Catalog",
      description:
        "Finds Entry-centric SVLT catalog records by index, entry, alias, tag, endpoint, note, or searchable metadata. It returns visible context and opaque secret:// references; it never returns plaintext or the catalog file path.",
      inputSchema: SecretSearchInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = SecretSearchInput.parse(input);
        const response = await client.request({
          type: "catalogSearch",
          query: parsed.query,
          field: parsed.field,
          limit: parsed.limit
        });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_search",
      title: "Search SVLT Catalog (Entry)",
      description:
        "Entry-centric alias of secret_search. Searches the managed Index→Entry→Field catalog and returns only allowed metadata plus opaque secret:// references.",
      inputSchema: SecretSearchInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = SecretSearchInput.parse(input);
        const response = await client.request({
          type: "catalogSearch",
          query: parsed.query,
          field: parsed.field,
          limit: parsed.limit
        });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_get",
      title: "Get SVLT Catalog Entry",
      description:
        "Gets one Entry by opaque catalog ID. It returns visible metadata and secret:// references only; it never returns plaintext.",
      inputSchema: CatalogGetInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = CatalogGetInput.parse(input);
        const response = await client.request({ type: "catalogGet", entryID: parsed.entryID });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_create_draft",
      title: "Create Catalog Draft",
      description:
        "Creates an Index Entry draft under the current App-controlled Agent write authorization. Secret fields may only be placeholders; binding an existing secret:// reference is a separate App-approved operation, and plaintext is never accepted.",
      inputSchema: CatalogCreateDraftInput,
      outputSchema: CatalogDraftOutput,
      async handler(input) {
        const parsed = CatalogCreateDraftInput.parse(input);
        const response = await client.request({
          type: "catalogCreateDraft",
          request: parsed.request
        });
        if (response.type === "catalogDraft") {
          return structuredResult(response.draft);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_patch_metadata",
      title: "Patch Catalog Metadata",
      description:
        "Patches ordinary Entry metadata under the current App-controlled Agent write authorization and expected revision. Secret transitions and secret replacement remain App-approved operations.",
      inputSchema: CatalogPatchMetadataInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogPatchMetadataInput.parse(input);
        const response = await client.request({
          type: "catalogPatchMetadata",
          entryID: parsed.entryID,
          patch: parsed.patch,
          expectedRevision: parsed.expectedRevision
        });
        if (response.type === "catalogWriteResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_commit",
      title: "Commit Catalog Draft",
      description:
        "Commits a previously created catalog draft under the current App-controlled structure authorization and optimistic revision. The Agent cannot self-issue or extend authorization.",
      inputSchema: CatalogCommitInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogCommitInput.parse(input);
        const response = await client.request({
          type: "catalogCommit",
          draft: parsed.draft,
          expectedRevision: parsed.expectedRevision
        });
        if (response.type === "catalogWriteResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_add_secret_placeholder",
      title: "Add Secret Placeholder",
      description:
        "Adds a secret field placeholder under the current App-controlled structure authorization. The user must fill the secret in SVLT App secure input; plaintext is never accepted here.",
      inputSchema: CatalogPlaceholderInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogPlaceholderInput.parse(input);
        const response = await client.request({
          type: "catalogAddSecretPlaceholder",
          entryID: parsed.entryID,
          key: parsed.key,
          label: parsed.label,
          agentVisible: parsed.agentVisible,
          searchable: parsed.searchable,
          expectedRevision: parsed.expectedRevision
        });
        if (response.type === "catalogWriteResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_bind_existing_secret",
      title: "Bind Existing Secret",
      description:
        "Requests binding an existing opaque secret:// reference to a catalog field. SVLT applies local policy and may require App approval; this tool never accepts plaintext.",
      inputSchema: CatalogBindInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogBindInput.parse(input);
        const response = await client.request({
          type: "catalogBindExistingSecret",
          entryID: parsed.entryID,
          key: parsed.key,
          secretRef: parsed.secretRef,
          expectedRevision: parsed.expectedRevision
        });
        if (response.type === "catalogWriteResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_validate",
      title: "Validate SVLT Catalog",
      description:
        "Validates the selected managed catalog, including integrity and revision state. It never returns catalog content or plaintext.",
      inputSchema: EmptyInput,
      outputSchema: CatalogValidationOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "catalogValidate" });
        if (response.type === "catalogValidation") {
          return structuredResult({
            status: response.catalogStatus,
            revision: response.revision ?? null
          });
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
          type: "revealReferences",
          references: [parsed.reference],
          context: {
            reason: parsed.reason,
            template: "{{0}}",
            ranges: [{ index: 0, placeholder: "{{0}}" }],
            agentAssessment: parsed.agentAssessment ?? {
              declaredRisk: "silent",
              reason: "Local reveal request",
              intendedEffect: "display to local user"
            }
          }
        });
        if (response.type === "revealSessionOpened") {
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
            ranges: revealRequest.context.ranges,
            agentAssessment: parsed.agentAssessment ?? {
              declaredRisk: "silent",
              reason: "Local reveal request",
              intendedEffect: "display to local user"
            }
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
        "Uses a secret:// password inside SVLTAgent for a restricted local/private-network SSH command. Plaintext is never returned.",
      inputSchema: SshCommandInput,
      outputSchema: LocalSshOutput,
      async handler(input) {
        return handleSshCommandWithSecret(client, SshCommandInput.parse(input));
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
          type: "encryptBound",
          label: parsed.label,
          policy: parsed.policy,
          allowedDestinations: parsed.allowedDestinations ?? [],
          allowedProtocols: parsed.allowedProtocols ?? []
        });
        if (response.type === "created") {
          return structuredResult({ reference: response.reference });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "local_http_request_with_secret",
      title: "Local HTTP Request With Secret",
      description:
        "Uses secret:// credentials inside SVLTAgent for a restricted HTTP request. Plaintext is never returned.",
      inputSchema: LocalHttpInput,
      outputSchema: LocalHttpOutput,
      async handler(input) {
        return handleLocalHttpRequest(client, LocalHttpInput.parse(input));
      }
    },
    {
      name: "api_request_with_token",
      title: "API Request With Token",
      description:
        "Uses a secret:// API token inside SVLTAgent for a restricted allowlisted API request. Plaintext is never returned.",
      inputSchema: ApiRequestInput,
      outputSchema: ApiRequestOutput,
      async handler(input) {
        return handleApiRequestWithToken(client, ApiRequestInput.parse(input));
      }
    },
    {
      name: "database_query_with_secret",
      title: "Database Query With Secret",
      description:
        "Submits an opaque descriptor for a restricted database query; the purpose-built local runner never returns credentials. Plaintext is never returned.",
      inputSchema: DatabaseQueryInput,
      outputSchema: DatabaseQueryOutput,
      async handler(input) {
        return handleDatabaseQueryWithSecret(client, DatabaseQueryInput.parse(input));
      }
    },
    {
      name: "sftp_transfer_with_secret",
      title: "SFTP/SCP Transfer With Secret",
      description:
        "Submits an opaque descriptor for restricted SFTP/SCP actions; the purpose-built local runner never returns credentials. Plaintext is never returned.",
      inputSchema: FileTransferInput,
      outputSchema: FileTransferOutput,
      async handler(input) {
        return handleFileTransferWithSecret(client, FileTransferInput.parse(input));
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
        return handleBrowserLoginWithSecret(client, BrowserLoginInput.parse(input));
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
        return handleLocalAppFillWithSecret(client, LocalAppFillInput.parse(input));
      }
    }
  ];
}

export function createMcpServer(client: VaultIpcClient = new LocalIpcClient()): McpServer {
  const server = new McpServer({
    name: "svlt",
    version: "0.1.16"
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
    allowedDestinations: metadata.allowedDestinations,
    allowedProtocols: metadata.allowedProtocols,
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
      ranges: revealRequest.context.ranges,
      agentAssessment: parsed.agentAssessment ?? {
        declaredRisk: "silent",
        reason: "Local file export request",
        intendedEffect: "write local file"
      }
    }
  });
  if (response.type === "exported") {
    return structuredResult({ status: "EXPORTED", path: response.path });
  }
  return structuredResult(statusOnly(response));
}

type AgentRiskInput = { agentAssessment?: z.infer<typeof AgentRiskAssessment> };

function agentAssessment(input: AgentRiskInput): z.infer<typeof AgentRiskAssessment> {
  return input.agentAssessment ?? {
    declaredRisk: "silent",
    reason: "No additional agent risk hint",
    intendedEffect: "purpose-built local secret operation"
  };
}

async function executeOpaqueOperation(
  client: VaultIpcClient,
  descriptor: z.infer<typeof SecretOperationDescriptor>
): Promise<z.infer<typeof SecretOperationOutput> | { status: string }> {
  const response = await client.request({
    type: "executeSecretOperation",
    descriptor
  });
  if (response.type === "secretOperation") {
    return response.output;
  }
  return { status: response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE" };
}

function isSecretOperationOutput(
  value: z.infer<typeof SecretOperationOutput> | { status: string }
): value is z.infer<typeof SecretOperationOutput> {
  return "redacted" in value;
}

async function handleSshCommandWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof SshCommandInput>
): Promise<CallToolResult> {
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const parameters: Record<string, string> = {
    passwordRef: parsed.passwordRef,
    ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
    ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "sshCommand",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: "ssh",
    command: parsed.command,
    requestedEffects: ["read-only"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    exitCode: output.exitCode ?? -1,
    stdout: output.stdout ?? "",
    stderr: output.stderr ?? "",
    redacted: true
  });
}

async function handleLocalHttpRequest(
  client: VaultIpcClient,
  parsed: z.infer<typeof LocalHttpInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    ...(parsed.passwordRef === undefined ? [] : [parsed.passwordRef])
  ];
  if ((parsed.username !== undefined || parsed.usernameRef !== undefined) !== (parsed.passwordRef !== undefined)) {
    return structuredResult({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
  }
  if (url.username !== "" || url.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  const parameters: Record<string, string> = {
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
    ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
    ...(parsed.passwordRef === undefined ? {} : { passwordRef: parsed.passwordRef }),
    ...(parsed.includeBodyPreview === undefined ? {} : { includeBodyPreview: String(parsed.includeBodyPreview) }),
    ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "httpRequest",
    secretReferences: refs,
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: url.protocol === "https:" ? "https" : "http",
    httpMethod: parsed.method ?? "GET",
    url: parsed.url,
    requestedEffects: [(parsed.method ?? "GET") === "GET" || (parsed.method ?? "GET") === "HEAD" ? "read-only" : "remote-write"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    httpStatus: output.httpStatus ?? 0,
    contentType: output.contentType ?? null,
    ...(output.bodyPreview === undefined ? {} : { bodyPreview: output.bodyPreview }),
    redacted: true
  });
}

async function handleApiRequestWithToken(
  client: VaultIpcClient,
  parsed: z.infer<typeof ApiRequestInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  if (url.username !== "" || url.password !== "" || hasCredentialQueryParameter(url)) {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  if (parsed.body?.includes("secret://") === true) {
    return structuredResult({ status: "PLAINTEXT_REFERENCE_NOT_ALLOWED" });
  }
  const parameters: Record<string, string> = {
    tokenRef: parsed.tokenRef,
    headerName: parsed.headerName ?? "Authorization",
    headerScheme: parsed.headerScheme ?? "Bearer",
    ...(parsed.body === undefined ? {} : { body: parsed.body }),
    ...(parsed.includeBodyPreview === undefined ? {} : { includeBodyPreview: String(parsed.includeBodyPreview) }),
    ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "apiRequest",
    secretReferences: [parsed.tokenRef],
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: url.protocol === "https:" ? "https" : "http",
    httpMethod: parsed.method ?? "GET",
    url: parsed.url,
    requestedEffects: [(parsed.method ?? "GET") === "GET" || (parsed.method ?? "GET") === "HEAD" ? "read-only" : "remote-write"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    httpStatus: output.httpStatus ?? 0,
    contentType: output.contentType ?? null,
    ...(output.bodyPreview === undefined ? {} : { bodyPreview: output.bodyPreview }),
    redacted: true
  });
}

async function handleDatabaseQueryWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof DatabaseQueryInput>
): Promise<CallToolResult> {
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType: "databaseQuery",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? (parsed.engine === "postgres" ? 5432 : 3306),
    protocolType: parsed.engine,
    databaseStatement: parsed.query,
    requestedEffects: ["database-read"],
    parameters: {
      database: parsed.database,
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.maxRows === undefined ? {} : { maxRows: String(parsed.maxRows) }),
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    ...(output.rowCount === undefined ? {} : { rowCount: output.rowCount }),
    ...(output.rowsPreview === undefined ? {} : { rowsPreview: output.rowsPreview }),
    ...(output.stderr === undefined ? {} : { stderr: output.stderr }),
    redacted: true
  });
}

async function handleFileTransferWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof FileTransferInput>
): Promise<CallToolResult> {
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType: "sftpTransfer",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: parsed.protocol ?? "sftp",
    fileOperation: parsed.operation,
    fileTarget: parsed.localPath ?? null,
    requestedEffects: [parsed.operation === "list" || parsed.operation === "download" ? "read-only" : "remote-write"],
    parameters: {
      remotePath: parsed.remotePath,
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.localPath === undefined ? {} : { localPath: parsed.localPath }),
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    ...(output.listingPreview === undefined ? {} : { listingPreview: output.listingPreview }),
    ...(output.localPath === undefined ? {} : { localPath: output.localPath }),
    ...(output.remotePath === undefined ? {} : { remotePath: output.remotePath }),
    ...(output.stderr === undefined ? {} : { stderr: output.stderr }),
    redacted: true
  });
}

async function handleBrowserLoginWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof BrowserLoginInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType: "browserLogin",
    secretReferences: refs,
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: url.protocol === "https:" ? "https" : "http",
    url: parsed.url,
    requestedEffects: [parsed.submit === true ? "submit-form" : "fill-form"],
    parameters: {
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.browser === undefined ? {} : { browser: parsed.browser }),
      ...(parsed.usernameSelector === undefined ? {} : { usernameSelector: parsed.usernameSelector }),
      passwordSelector: parsed.passwordSelector,
      ...(parsed.submitSelector === undefined ? {} : { submitSelector: parsed.submitSelector }),
      submit: String(parsed.submit ?? false),
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({ status: "COMPLETED", redacted: true });
}

async function handleLocalAppFillWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof LocalAppFillInput>
): Promise<CallToolResult> {
  const refs = parsed.fields.flatMap((field) => field.valueRef === undefined ? [] : [field.valueRef]);
  const output = await executeOpaqueOperation(client, {
    actionType: "localAppFill",
    secretReferences: refs,
    destination: parsed.bundleId ?? parsed.appName ?? null,
    protocolType: "localApp",
    localAppBundleID: parsed.bundleId ?? null,
    requestedEffects: ["fill-local-app"],
    parameters: {
      fields: JSON.stringify(parsed.fields),
      ...(parsed.appName === undefined ? {} : { appName: parsed.appName }),
      ...(parsed.submitButton === undefined ? {} : { submitButton: parsed.submitButton }),
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: String(parsed.timeoutMs) })
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({ status: "COMPLETED", redacted: true });
}

function agentSecretUsagePolicy(): Record<string, unknown> {
  return {
    status: "OK",
    intendedClients: ["Codex", "Claude", "Hermes", "Other MCP-capable agents"],
    conversationRule:
      "Keep secret:// references in the conversation. Do not ask the user to paste decrypted values into chat.",
    referenceRule:
      "Treat every secret:// reference as an opaque handle. Do not infer, classify, summarize, or transform the hidden value.",
    catalogPolicy: SVLT_AGENT_CATALOG_POLICY,
    scopeRule: {
      managed:
        "SVLT_MANAGED_OPERATION: use SVLT only when the user explicitly selects SVLT, an Entry, or a secret:// reference; resolve values only inside an approved SVLT operation.",
      unmanaged:
        "UNMANAGED_CREDENTIAL: if the user has not selected SVLT or another provider, automatic discovery is allowed but SVLT is not the only credential source.",
      explicitPlaintext:
        "USER_EXPLICIT_PLAINTEXT: the user supplied plaintext for this operation or explicitly chose not to use SVLT; do not search, compare, substitute, import, block, or require SVLT approval.",
      externalProvider:
        "EXTERNAL_PROVIDER_OPERATION: the user selected another MCP, connector, logged-in CLI, environment variable, or password manager; SVLT must not take over."
    },
    userOverrideRule:
      "Explicit user choice of plaintext overrides SVLT's default preference for secret:// on that operation. Do not force import, conversion, lookup, substitution, or SVLT authorization. Other repository, tool, logging, persistence, and network-safety rules still apply.",
    outOfScopeRule: [
      "SVLT does not own device MCP credentials, GitHub connector authorization, logged-in CLI credentials, environment variables, third-party password managers, or user-supplied plaintext.",
      "Do not treat user-supplied plaintext as SVLT-managed unless the user explicitly asks to store it in or use it through SVLT.",
      "Do not compare user plaintext with an SVLT secret or infer shared provenance from equal values."
    ],
    credentialSourcePriority: [...credentialSourcePriority],
    safeWorkflow: [
      "Before invoking SVLT, determine whether the user explicitly selected SVLT or explicitly supplied plaintext for this operation.",
      "When the user explicitly supplied plaintext and requested its use, continue with that supplied value under the active tool/workspace rules; do not search for or substitute an SVLT reference unless requested.",
      "Credential source selection is per operation; a later user choice replaces previous SVLT or provider context and is never inherited as sticky authorization.",
      "When text contains secret:// references, call secret_auto_handle_text first unless a narrower safe tool is clearly required and the user did not select another source.",
      "Call vault_status before work that depends on the app.",
      "Treat AgentRiskAssessment as a hint only; SVLT recomputes the effective risk locally for every operation.",
      "A locked compatibility field never replaces per-operation policy evaluation.",
      "When a task names a service, device, host, account, or purpose but no credential source is specified, call secret_search before asking the user for anything; this is automatic discovery, not forced SVLT ownership.",
      "Use the Index, Entry, endpoint, visible metadata, and opaque secretRef returned by secret_search or secret_catalog_search to choose compatible references; do not ask the user to copy reference IDs.",
      "Use secret_catalog_get for one Entry, and use secret_catalog_validate after every catalog write.",
      "Catalog writes require the current App-controlled Agent authorization; never invent, extend, or self-approve authorization.",
      "A search is silent and metadata-only; it never grants permission to reveal or export plaintext.",
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
      "If no SVLT-safe tool exists for an explicitly SVLT-managed operation, stop and ask for a new allowlisted tool instead of requesting decrypted plaintext.",
      "If the user explicitly selected another provider or current plaintext, do not redirect the operation to SVLT merely because a catalog match exists."
    ],
    forbidden: [
      "Do not expose plaintext obtained by decrypting an SVLT-managed secret outside the approved SVLT operation.",
      "Do not echo, log, summarize, or store plaintext obtained by decrypting an SVLT-managed secret.",
      "Do not put SVLT-derived plaintext into ordinary shell, curl, URL, header, environment variable, log, audit, or chat inputs; use the approved SVLT operation instead.",
      "Do not treat encrypted reference text as if it revealed the secret value.",
      "Do not send a secret to public networks unless the user explicitly approved that policy and an allowlisted tool enforces it."
    ],
    safeTools: [
      "secret_action_router",
      "secret_auto_handle_text",
      "vault_status",
      "secret_search",
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
      "local_app_form_fill_with_secret"
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

function hasCredentialQueryParameter(url: URL): boolean {
  for (const key of url.searchParams.keys()) {
    if (/password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie/i.test(key)) {
      return true;
    }
  }
  return false;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runStdioServer();
}
