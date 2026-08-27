import { z } from "zod";

export const MAX_FRAME_BYTES = 1_048_576;

const secretReferencePattern = /^secret:\/\/[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$/;

export const CapabilityToken = z
  .string()
  .refine((value) => {
    const decoded = Buffer.from(value, "base64");
    return decoded.byteLength === 32 && decoded.toString("base64") === value;
  }, "capability token must be base64 encoded 256-bit data");

export type CapabilityToken = z.infer<typeof CapabilityToken>;

export const SecretReference = z.string().regex(secretReferencePattern);
export type SecretReference = z.infer<typeof SecretReference>;

export const SecretPolicy = z.enum(["read", "externalSend", "credential"]);
export type SecretPolicy = z.infer<typeof SecretPolicy>;

export const SecretCatalogField = z.enum([
  "username",
  "password",
  "token",
  "apiKey",
  "cookie",
  "privateKey",
  "other"
]);
export type SecretCatalogField = z.infer<typeof SecretCatalogField>;

export const OperationRisk = z.enum(["silent", "approvalRequired", "denied"]);
export type OperationRisk = z.infer<typeof OperationRisk>;

export const AgentRiskAssessment = z
  .object({
    declaredRisk: OperationRisk,
    reason: z.string().min(1).max(512),
    intendedEffect: z.string().min(1).max(256)
  })
  .strict();
export type AgentRiskAssessment = z.infer<typeof AgentRiskAssessment>;

export const WorkbenchStatus = z.object({
  locked: z.boolean(),
  ipcAvailable: z.boolean(),
  available: z.boolean().default(true),
  ready: z.boolean().default(true),
  approvalPending: z.boolean().default(false),
  activeKnowledgeBaseRoot: z.string().nullable(),
  pluginConnected: z.boolean()
}).strict();
export type WorkbenchStatus = z.infer<typeof WorkbenchStatus>;

export const ReferenceRange = z.object({
  index: z.number().int(),
  placeholder: z.string().min(1)
}).strict();
export type ReferenceRange = z.infer<typeof ReferenceRange>;

export const RevealContext = z.object({
  reason: z.string().min(1),
  template: z.string().min(1),
  ranges: z.array(ReferenceRange),
  destination: z.string().min(1).optional(),
  agentAssessment: AgentRiskAssessment.optional()
}).strict();
export type RevealContext = z.infer<typeof RevealContext>;

export const OrphanScanResult = z.object({
  missingRecords: z.array(z.string()),
  unreferencedRecords: z.array(z.string())
}).strict();
export type OrphanScanResult = z.infer<typeof OrphanScanResult>;

export const SecretReferenceMetadata = z.object({
  reference: SecretReference,
  policy: SecretPolicy,
  label: z.string().nullable(),
  allowedDestinations: z.array(z.string()).default([]),
  allowedProtocols: z.array(z.string()).default([]),
  createdAt: z.union([z.string().min(1), z.number()]),
  updatedAt: z.union([z.string().min(1), z.number()])
}).strict();
export type SecretReferenceMetadata = z.infer<typeof SecretReferenceMetadata>;

export const SecretCatalogFieldType = z.enum([
  "text",
  "multiline",
  "url",
  "host",
  "port",
  "number",
  "boolean",
  "date",
  "list",
  "secret"
]);
export type SecretCatalogFieldType = z.infer<typeof SecretCatalogFieldType>;

export const SecretCatalogValue = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.array(z.string())
]);
export type SecretCatalogValue = z.infer<typeof SecretCatalogValue>;

export const CatalogEndpoint = z.object({
  type: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(0).max(65535).nullable().optional()
}).strict();
export type CatalogEndpoint = z.infer<typeof CatalogEndpoint>;

function validateCatalogFieldSafety(
  value: {
    type: SecretCatalogFieldType;
    value?: SecretCatalogValue;
    secretRef?: string;
  },
  context: z.RefinementCtx
): void {
  if (value.value !== undefined && value.secretRef !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "value and secretRef are mutually exclusive" });
  }
  if (value.type === "secret" && value.value !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "secret fields cannot contain plaintext values" });
  }
  if (value.type !== "secret" && value.secretRef !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "only secret fields may contain secretRef" });
  }
}

function validateUniqueFieldKeys(
  fields: Array<{ key: string }>,
  context: z.RefinementCtx,
  pathPrefix: Array<string | number> = ["fields"]
): void {
  const firstIndexByKey = new Map<string, number>();
  fields.forEach((field, index) => {
    const firstIndex = firstIndexByKey.get(field.key);
    if (firstIndex === undefined) {
      firstIndexByKey.set(field.key, index);
      return;
    }
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: [...pathPrefix, index, "key"],
      message: `duplicate field key; the first occurrence is at ${[...pathPrefix, firstIndex, "key"].join(".")}`
    });
  });
}

export const SecretCatalogFieldMatch = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    value: SecretCatalogValue.optional(),
    secretRef: SecretReference.optional()
  })
  .strict()
  .superRefine(validateCatalogFieldSafety);
export type SecretCatalogFieldMatch = z.infer<typeof SecretCatalogFieldMatch>;

export const SecretCatalogIndexMatch = z.object({
  id: z.string().length(26),
  title: z.string().min(1),
  aliases: z.array(z.string()),
  tags: z.array(z.string())
}).strict();
export type SecretCatalogIndexMatch = z.infer<typeof SecretCatalogIndexMatch>;

export const SecretCatalogEntryMatch = z.object({
  id: z.string().length(26),
  indexId: z.string().length(26),
  title: z.string().min(1),
  type: z.string().min(1),
  aliases: z.array(z.string()),
  endpoints: z.array(CatalogEndpoint),
  fields: z.array(SecretCatalogFieldMatch),
  notes: z.string().nullable().optional(),
  tags: z.array(z.string())
}).strict();
export type SecretCatalogEntryMatch = z.infer<typeof SecretCatalogEntryMatch>;

export const SecretCatalogMatch = z.object({
  index: SecretCatalogIndexMatch,
  entry: SecretCatalogEntryMatch
}).strict();
export type SecretCatalogMatch = z.infer<typeof SecretCatalogMatch>;

export const SecretCatalogSearchResult = z.object({
  status: z.enum([
    "FOUND",
    "NOT_FOUND",
    "INVALID_QUERY",
    "CATALOG_UNAVAILABLE",
    "LEGACY_CATALOG_UNSUPPORTED",
    "INTEGRITY_MISSING",
    "EXTERNAL_CATALOG_MODIFICATION",
    "PENDING_EXTERNAL_CHANGE",
    "CATALOG_INVALID"
  ]),
  matches: z.array(SecretCatalogMatch)
}).strict();
export type SecretCatalogSearchResult = z.infer<typeof SecretCatalogSearchResult>;

const CatalogFieldValue = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    value: SecretCatalogValue.optional(),
    secretRef: SecretReference.optional()
  })
  .strict()
  .superRefine(validateCatalogFieldSafety);

export const CatalogDraftRequest = z.object({
  indexID: z.string().length(26),
  title: z.string().min(1).max(2000),
  type: z.string().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});
export type CatalogDraftRequest = z.infer<typeof CatalogDraftRequest>;

// Direct creation is intentionally narrower than a draft. A safe Agent
// mutation may provide ordinary metadata and an empty secret placeholder, but
// it cannot carry an existing secretRef or any secret value.
export const CatalogSafeFieldValue = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    value: SecretCatalogValue.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.type === "secret" && value.value !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "secret fields must be empty placeholders" });
    }
  });

export const CatalogCreateEntryRequest = z.object({
  indexID: z.string().length(26),
  title: z.string().min(1).max(2000),
  type: z.string().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogSafeFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});
export type CatalogCreateEntryRequest = z.infer<typeof CatalogCreateEntryRequest>;

export const CatalogMetadataPatch = z.object({
  title: z.string().min(1).max(2000).optional(),
  aliases: z.array(z.string()).max(64).optional(),
  tags: z.array(z.string()).max(64).optional(),
  endpoints: z.array(CatalogEndpoint).max(64).optional(),
  notes: z.string().max(2000).optional(),
  fields: z.array(CatalogFieldValue).max(128).optional()
}).strict().superRefine((value, context) => {
  if (value.fields !== undefined) {
    validateUniqueFieldKeys(value.fields, context);
  }
});
export type CatalogMetadataPatch = z.infer<typeof CatalogMetadataPatch>;

const CatalogStructureIndexRequest = z.object({
  title: z.string().trim().min(1).max(2000),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([])
}).strict();

const CatalogStructureEntryRequest = z.object({
  clientKey: z.string().trim().min(1).max(200),
  title: z.string().trim().min(1).max(2000),
  type: z.string().trim().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogSafeFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});

export const CatalogCreateStructureRequest = z.object({
  index: CatalogStructureIndexRequest,
  entries: z.array(CatalogStructureEntryRequest).max(128).default([]),
  expectedRevision: z.number().int().nonnegative().optional()
}).strict().superRefine((value, context) => {
  const firstIndexByClientKey = new Map<string, number>();
  value.entries.forEach((entry, index) => {
    const firstIndex = firstIndexByClientKey.get(entry.clientKey);
    if (firstIndex === undefined) {
      firstIndexByClientKey.set(entry.clientKey, index);
      return;
    }
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["entries", index, "clientKey"],
      message: `duplicate clientKey; the first occurrence is at entries.${firstIndex}.clientKey`
    });
  });
});
export type CatalogCreateStructureRequest = z.infer<typeof CatalogCreateStructureRequest>;

export const CatalogDraft = z.object({
  draftID: z.string().length(26),
  baseRevision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch
}).strict();
export type CatalogDraft = z.infer<typeof CatalogDraft>;

export const CatalogFilePreflight = z.object({
  read: z.string().min(1).max(128),
  parentTempCreate: z.string().min(1).max(128),
  parentTempFsync: z.string().min(1).max(128),
  parentRename: z.string().min(1).max(128),
  parentFsync: z.string().min(1).max(128)
}).strict();
export type CatalogFilePreflight = z.infer<typeof CatalogFilePreflight>;

export const CatalogAgentWriteIntent = z.object({
  requestID: z.string().uuid().nullable().optional(),
  operation: z.enum([
    "createIndex",
    "createEntry",
    "createStructure",
    "patchMetadata",
    "commitDraft",
    "addSecretPlaceholder",
    "batchMutation"
  ]),
  indexID: z.string().nullable().optional(),
  entryID: z.string().nullable().optional(),
  fieldKey: z.string().nullable().optional(),
  acceptedRevision: z.number().int().nonnegative(),
  candidateSemanticSHA256: z.string().regex(/^[0-9a-f]{64}$/)
}).strict();
export type CatalogAgentWriteIntent = z.infer<typeof CatalogAgentWriteIntent>;

export const CatalogAgentWriteAccessRequest = z.object({
  id: z.string().uuid(),
  source: z.enum(["codex", "claude", "openclaw", "mcp-client"]),
  reasonCategory: z.enum(["knowledge-maintenance", "catalog-repair", "bulk-import", "other"]),
  duration: z.enum(["single-use", "10-minutes", "30-minutes"]),
  createdAt: z.string().datetime(),
  intent: CatalogAgentWriteIntent.nullable().optional(),
  expiresAt: z.string().datetime().nullable().optional(),
  verifiedSource: z.string().nullable().optional()
}).strict();
export type CatalogAgentWriteAccessRequest = z.infer<typeof CatalogAgentWriteAccessRequest>;

export const CatalogValidationDiagnostic = z.object({
  id: z.string().min(1),
  severity: z.enum(["error", "warning"]),
  code: z.string().min(1),
  line: z.number().int().positive(),
  column: z.number().int().positive().nullable().optional(),
  endLine: z.number().int().positive().nullable().optional(),
  endColumn: z.number().int().positive().nullable().optional(),
  scope: z.enum(["document", "policy", "index", "entry", "field", "unmanaged"]),
  message: z.string().min(1),
  hint: z.string().nullable().optional()
}).strict();
export type CatalogValidationDiagnostic = z.infer<typeof CatalogValidationDiagnostic>;

export const CatalogValidationResult = z.object({
  status: z.enum([
    "FOUND",
    "NOT_FOUND",
    "INVALID_QUERY",
    "CATALOG_UNAVAILABLE",
    "LEGACY_CATALOG_UNSUPPORTED",
    "INTEGRITY_MISSING",
    "EXTERNAL_CATALOG_MODIFICATION",
    "PENDING_EXTERNAL_CHANGE",
    "CATALOG_INVALID"
  ]),
  revision: z.number().int().nonnegative().nullable().optional(),
  rawSHA256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
  diagnostics: z.array(CatalogValidationDiagnostic).default([]),
  filePreflight: CatalogFilePreflight.nullable().optional()
}).strict();
export type CatalogValidationResult = z.infer<typeof CatalogValidationResult>;

export const CatalogWriteResult = z.object({
  revision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch.nullable().optional(),
  indexID: z.string().length(26).optional(),
  entryID: z.string().length(26).optional(),
  validation: CatalogValidationResult.optional()
}).strict();
export type CatalogWriteResult = z.infer<typeof CatalogWriteResult>;

export const CatalogStructureWriteResult = z.object({
  indexID: z.string().length(26),
  entries: z.array(z.object({
    clientKey: z.string().min(1),
    entryID: z.string().length(26)
  }).strict()),
  revision: z.number().int().nonnegative(),
  validation: CatalogValidationResult
}).strict();
export type CatalogStructureWriteResult = z.infer<typeof CatalogStructureWriteResult>;

export const CatalogIndexSummary = z.object({
  id: z.string().length(26),
  title: z.string().min(1),
  aliases: z.array(z.string()),
  tags: z.array(z.string()),
  entryCount: z.number().int().nonnegative()
}).strict();
export type CatalogIndexSummary = z.infer<typeof CatalogIndexSummary>;

export const CatalogIndexListResult = z.object({
  status: SecretCatalogSearchResult.shape.status,
  revision: z.number().int().nonnegative(),
  indices: z.array(CatalogIndexSummary)
}).strict();
export type CatalogIndexListResult = z.infer<typeof CatalogIndexListResult>;

export const CatalogEntryListResult = z.object({
  status: SecretCatalogSearchResult.shape.status,
  revision: z.number().int().nonnegative(),
  indexID: z.string().length(26),
  entries: z.array(SecretCatalogEntryMatch)
}).strict();
export type CatalogEntryListResult = z.infer<typeof CatalogEntryListResult>;

const CatalogBatchIndex = z
  .object({
    schema: z.literal("svlt.catalog.index/v3"),
    id: z.string().length(26),
    title: z.string().min(1).max(2000),
    aliases: z.array(z.string()).max(64),
    tags: z.array(z.string()).max(64)
  })
  .strict();

const CatalogBatchEntry = z
  .object({
    schema: z.literal("svlt.catalog.entry/v3"),
    id: z.string().length(26),
    indexId: z.string().length(26),
    title: z.string().min(1).max(2000),
    type: z.string().min(1).max(2000),
    aliases: z.array(z.string()).max(64),
    endpoints: z.array(CatalogEndpoint).max(64),
    fields: z.array(CatalogFieldValue).max(128),
    notes: z.string().max(2000).nullable().optional(),
    tags: z.array(z.string()).max(64)
  })
  .strict()
  .superRefine((value, context) => {
    validateUniqueFieldKeys(value.fields, context);
  });

export const CatalogBatchOperation = z.discriminatedUnion("type", [
  z.object({ type: z.literal("createIndex"), index: CatalogBatchIndex }).strict(),
  z.object({ type: z.literal("updateIndex"), index: CatalogBatchIndex }).strict(),
  z.object({ type: z.literal("deleteIndex"), id: z.string().length(26) }).strict(),
  z.object({ type: z.literal("createEntry"), entry: CatalogBatchEntry }).strict(),
  z.object({ type: z.literal("updateEntry"), entry: CatalogBatchEntry }).strict(),
  z
    .object({
      type: z.literal("moveEntry"),
      id: z.string().length(26),
      toIndexID: z.string().length(26)
    })
    .strict(),
  z.object({ type: z.literal("deleteEntry"), id: z.string().length(26) }).strict(),
  z
    .object({
      type: z.literal("addField"),
      entryID: z.string().length(26),
      field: CatalogFieldValue
    })
    .strict(),
  z
    .object({
      type: z.literal("updateField"),
      entryID: z.string().length(26),
      field: CatalogFieldValue
    })
    .strict(),
  z
    .object({
      type: z.literal("removeField"),
      entryID: z.string().length(26),
      key: z.string().min(1)
    })
    .strict()
]);
export type CatalogBatchOperation = z.infer<typeof CatalogBatchOperation>;

export const CatalogBatchMutation = z.object({
  operations: z.array(CatalogBatchOperation).min(1).max(128),
  expectedRevision: z.number().int().nonnegative()
}).strict();
export type CatalogBatchMutation = z.infer<typeof CatalogBatchMutation>;

export const SecretOperationAction = z.enum([
  "vaultStatus",
  "usagePolicy",
  "inspectReference",
  "checkReferenceExists",
  "sshCommand",
  "httpRequest",
  "apiRequest",
  "databaseQuery",
  "sftpTransfer",
  "browserLogin",
  "localAppFill",
  "revealPlaintext",
  "copyPlaintext",
  "exportPlaintext",
  "deleteSecret",
  "changeSecretPolicy",
  "changeDestinationBinding",
  "changeAllowlist",
  "changeAuthorizationRules",
  "changeKeychain",
  "migrateMasterKey",
  "importRecoveryKey",
  "exportRecoveryKey",
  "restoreVault",
  "clearVault",
  "batchDelete",
  "resetVault",
  "localExecution"
]);
export type SecretOperationAction = z.infer<typeof SecretOperationAction>;

export const SecretOperationProtocol = z.enum([
  "ssh",
  "http",
  "https",
  "sftp",
  "scp",
  "postgres",
  "mysql",
  "browser",
  "localApp",
  "file"
]);
export type SecretOperationProtocol = z.infer<typeof SecretOperationProtocol>;

export const SecretFileOperation = z.enum([
  "list",
  "read",
  "download",
  "upload",
  "write",
  "overwrite",
  "move",
  "delete"
]);
export type SecretFileOperation = z.infer<typeof SecretFileOperation>;

export const SecretOperationDescriptor = z
  .object({
    actionType: SecretOperationAction,
    secretReferences: z.array(SecretReference),
    destination: z.string().nullable().optional(),
    port: z.number().int().nullable().optional(),
    protocolType: SecretOperationProtocol.nullable().optional(),
    command: z.string().nullable().optional(),
    httpMethod: z.string().nullable().optional(),
    url: z.string().nullable().optional(),
    databaseStatement: z.string().nullable().optional(),
    fileOperation: SecretFileOperation.nullable().optional(),
    fileTarget: z.string().nullable().optional(),
    localAppBundleID: z.string().nullable().optional(),
    requestedEffects: z.array(z.string()),
    parameters: z.record(z.string(), z.string()),
    agentAssessment: AgentRiskAssessment
  })
  .strict();
export type SecretOperationDescriptor = z.infer<typeof SecretOperationDescriptor>;

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("status") }).strict(),
  z.object({ type: z.literal("workbenchStatus") }).strict(),
  z
    .object({
      type: z.literal("searchCatalog"),
      query: z.string().trim().min(1).max(256),
      field: SecretCatalogField.optional(),
      limit: z.number().int().min(1).max(20).default(10)
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogSearch"),
      query: z.string().trim().min(1).max(256),
      field: SecretCatalogField.optional(),
      limit: z.number().int().min(1).max(20).default(10)
    })
    .strict(),
  z.object({ type: z.literal("catalogGet"), entryID: z.string().length(26) }).strict(),
  z.object({ type: z.literal("catalogListIndexes") }).strict(),
  z.object({ type: z.literal("catalogListEntries"), indexID: z.string().length(26) }).strict(),
  z
    .object({
      type: z.literal("catalogCreateIndex"),
      title: z.string().min(1).max(2000),
      aliases: z.array(z.string()).max(64).default([]),
      tags: z.array(z.string()).max(64).default([])
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateEntry"),
      request: CatalogDraftRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateStructure"),
      request: CatalogCreateStructureRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateDraft"),
      request: CatalogDraftRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogPatchMetadata"),
      entryID: z.string().length(26),
      patch: CatalogMetadataPatch,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCommit"),
      draft: CatalogDraft,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogAddSecretPlaceholder"),
      entryID: z.string().length(26),
      key: z.string().min(1),
      label: z.string().min(1),
      agentVisible: z.boolean().default(true),
      searchable: z.boolean().default(true),
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogBindExistingSecret"),
      entryID: z.string().length(26),
      key: z.string().min(1),
      secretRef: SecretReference,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogApplyBatch"),
      mutation: z.object({ operations: z.array(CatalogBatchOperation).min(1).max(128) }).strict(),
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z.object({ type: z.literal("catalogValidate") }).strict(),
  z.object({ type: z.literal("catalogFilePreflight") }).strict(),
  z.object({ type: z.literal("catalogRequestWriteAccess"), request: CatalogAgentWriteAccessRequest }).strict(),
  z
    .object({
      type: z.literal("inspectReference"),
      reference: SecretReference
    })
    .strict(),
  z
    .object({
      type: z.literal("reveal"),
      reference: SecretReference,
      reason: z.string().min(1)
    })
    .strict(),
  z
    .object({
      type: z.literal("encrypt"),
      label: z.string().nullable().optional(),
      policy: SecretPolicy
    })
    .strict(),
  z
    .object({
      type: z.literal("encryptBound"),
      label: z.string().nullable().optional(),
      policy: SecretPolicy,
      allowedDestinations: z.array(z.string().min(1)).max(32),
      allowedProtocols: z.array(SecretOperationProtocol).max(16)
    })
    .strict(),
  z
    .object({
      type: z.literal("revealReferences"),
      references: z.array(SecretReference).min(1),
      context: RevealContext
    })
    .strict(),
  z
    .object({
      type: z.literal("exportResolvedText"),
      references: z.array(SecretReference).min(1),
      context: RevealContext,
      destinationPath: z.string().min(1)
    })
    .strict(),
  z
    .object({
      type: z.literal("scanOrphans"),
      markdownReferences: z.array(SecretReference)
    })
    .strict(),
  z
    .object({
      type: z.literal("executeSecretOperation"),
      descriptor: SecretOperationDescriptor
    })
    .strict()
]);
export type IpcRequest = z.infer<typeof IpcRequest>;

export const AuthenticatedIpcRequest = z
  .object({
    capabilityToken: CapabilityToken,
    request: IpcRequest
  })
  .strict();
export type AuthenticatedIpcRequest = z.infer<typeof AuthenticatedIpcRequest>;

export const SecretOperationOutput = z
  .object({
    status: z.string().min(1),
    exitCode: z.number().int().optional(),
    stdout: z.string().optional(),
    stderr: z.string().optional(),
    httpStatus: z.number().int().optional(),
    contentType: z.string().nullable().optional(),
    bodyPreview: z.string().optional(),
    rowCount: z.number().int().min(0).optional(),
    rowsPreview: z.string().optional(),
    listingPreview: z.string().optional(),
    localPath: z.string().optional(),
    remotePath: z.string().optional(),
    redacted: z.boolean()
  })
  .strict();
export type SecretOperationOutput = z.infer<typeof SecretOperationOutput>;

export const RevealSessionOpened = z.object({
  type: z.literal("revealSessionOpened"),
  sessionID: z.string().min(1)
}).strict();
export type RevealSessionOpened = z.infer<typeof RevealSessionOpened>;

export const IpcResponse = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("status"),
      locked: z.boolean()
    })
    .strict(),
  z
    .object({
      type: z.literal("workbenchStatus"),
      status: WorkbenchStatus
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogSearchResult"),
      result: SecretCatalogSearchResult
    })
    .strict(),
  z.object({ type: z.literal("catalogIndexListResult"), result: CatalogIndexListResult }).strict(),
  z.object({ type: z.literal("catalogEntryListResult"), result: CatalogEntryListResult }).strict(),
  z.object({ type: z.literal("catalogDraft"), draft: CatalogDraft }).strict(),
  z.object({ type: z.literal("catalogWriteResult"), result: CatalogWriteResult }).strict(),
  z.object({ type: z.literal("catalogStructureWriteResult"), result: CatalogStructureWriteResult }).strict(),
  z
    .object({
      type: z.literal("catalogValidation"),
      catalogStatus: z.enum(["FOUND", "NOT_FOUND", "INVALID_QUERY", "CATALOG_UNAVAILABLE", "LEGACY_CATALOG_UNSUPPORTED", "INTEGRITY_MISSING", "EXTERNAL_CATALOG_MODIFICATION", "PENDING_EXTERNAL_CHANGE", "CATALOG_INVALID"]),
      revision: z.number().int().nonnegative().nullable().optional(),
      rawSHA256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
      diagnostics: z.array(CatalogValidationDiagnostic).default([]),
      filePreflight: CatalogFilePreflight.optional()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogFilePreflight"),
      filePreflight: CatalogFilePreflight
    })
    .strict(),
  z
    .object({
      type: z.literal("referenceMetadata"),
      metadata: SecretReferenceMetadata
    })
    .strict(),
  z.object({ type: z.literal("displayedToUser") }).strict(),
  z
    .object({
      type: z.literal("created"),
      reference: SecretReference
    })
    .strict(),
  RevealSessionOpened,
  z.object({ type: z.literal("exported"), path: z.string().min(1) }).strict(),
  z
    .object({
      type: z.literal("orphanScan"),
      result: OrphanScanResult
    })
    .strict(),
  z
    .object({
      type: z.literal("secretOperation"),
      output: SecretOperationOutput
    })
    .strict(),
  z.object({ type: z.literal("operationCompleted") }).strict(),
  z
    .object({
      type: z.literal("failure"),
      code: z.string().min(1)
    })
    .strict()
]);
export type IpcResponse = z.infer<typeof IpcResponse>;

export class IpcFrameCodec {
  static encode(value: unknown): Buffer {
    const payload = Buffer.from(JSON.stringify(value), "utf8");
    if (payload.byteLength > MAX_FRAME_BYTES) {
      throw new Error("IPC frame too large");
    }

    const frame = Buffer.allocUnsafe(4 + payload.byteLength);
    frame.writeUInt32BE(payload.byteLength, 0);
    payload.copy(frame, 4);
    return frame;
  }

  static decode<T>(frame: Buffer, schema: z.ZodType<T>): T {
    if (frame.byteLength < 4) {
      throw new Error("incomplete IPC frame");
    }

    const payloadLength = frame.readUInt32BE(0);
    if (payloadLength > MAX_FRAME_BYTES) {
      throw new Error("IPC frame too large");
    }

    const actualLength = frame.byteLength - 4;
    if (actualLength !== payloadLength) {
      throw new Error(`IPC frame length mismatch: expected ${payloadLength}, got ${actualLength}`);
    }

    return schema.parse(JSON.parse(frame.subarray(4).toString("utf8")));
  }
}
