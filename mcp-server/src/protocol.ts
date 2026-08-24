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
    "MIGRATION_REQUIRED",
    "EXTERNAL_CATALOG_MODIFICATION",
    "CATALOG_INVALID"
  ]),
  matches: z.array(SecretCatalogMatch)
}).strict();
export type SecretCatalogSearchResult = z.infer<typeof SecretCatalogSearchResult>;

export const CatalogWriteScope = z.enum(["metadata", "structure"]);
export type CatalogWriteScope = z.infer<typeof CatalogWriteScope>;

export const CatalogWriteLease = z.object({
  scope: CatalogWriteScope,
  issuedAt: z.union([z.string(), z.number()]),
  expiresAt: z.union([z.string(), z.number()]),
  nonce: z.string().length(26)
}).strict();
export type CatalogWriteLease = z.infer<typeof CatalogWriteLease>;

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
  fields: z.array(CatalogFieldValue).max(128).default([])
}).strict();
export type CatalogDraftRequest = z.infer<typeof CatalogDraftRequest>;

export const CatalogMetadataPatch = z.object({
  title: z.string().min(1).max(2000).optional(),
  aliases: z.array(z.string()).max(64).optional(),
  tags: z.array(z.string()).max(64).optional(),
  endpoints: z.array(CatalogEndpoint).max(64).optional(),
  notes: z.string().max(2000).optional(),
  fields: z.array(CatalogFieldValue).max(128).optional()
}).strict();
export type CatalogMetadataPatch = z.infer<typeof CatalogMetadataPatch>;

export const CatalogDraft = z.object({
  draftID: z.string().length(26),
  baseRevision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch
}).strict();
export type CatalogDraft = z.infer<typeof CatalogDraft>;

export const CatalogWriteResult = z.object({
  revision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch.nullable().optional()
}).strict();
export type CatalogWriteResult = z.infer<typeof CatalogWriteResult>;

export const CatalogValidationResult = z.object({
  status: z.enum([
    "FOUND",
    "NOT_FOUND",
    "INVALID_QUERY",
    "CATALOG_UNAVAILABLE",
    "MIGRATION_REQUIRED",
    "EXTERNAL_CATALOG_MODIFICATION",
    "CATALOG_INVALID"
  ]),
  revision: z.number().int().nonnegative().nullable().optional()
}).strict();
export type CatalogValidationResult = z.infer<typeof CatalogValidationResult>;

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
  z
    .object({
      type: z.literal("catalogCreateDraft"),
      request: CatalogDraftRequest,
      lease: CatalogWriteLease
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogPatchMetadata"),
      entryID: z.string().length(26),
      patch: CatalogMetadataPatch,
      expectedRevision: z.number().int().nonnegative(),
      lease: CatalogWriteLease
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCommit"),
      draft: CatalogDraft,
      expectedRevision: z.number().int().nonnegative(),
      lease: CatalogWriteLease
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
      expectedRevision: z.number().int().nonnegative(),
      lease: CatalogWriteLease
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogBindExistingSecret"),
      entryID: z.string().length(26),
      key: z.string().min(1),
      secretRef: SecretReference,
      expectedRevision: z.number().int().nonnegative(),
      lease: CatalogWriteLease
    })
    .strict(),
  z.object({ type: z.literal("catalogValidate") }).strict(),
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
  z.object({ type: z.literal("catalogDraft"), draft: CatalogDraft }).strict(),
  z.object({ type: z.literal("catalogWriteResult"), result: CatalogWriteResult }).strict(),
  z
    .object({
      type: z.literal("catalogValidation"),
      catalogStatus: z.enum(["FOUND", "NOT_FOUND", "INVALID_QUERY", "CATALOG_UNAVAILABLE", "MIGRATION_REQUIRED", "EXTERNAL_CATALOG_MODIFICATION", "CATALOG_INVALID"]),
      revision: z.number().int().nonnegative().nullable().optional()
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
