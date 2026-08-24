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

export const SecretCatalogMatch = z.object({
  reference: SecretReference,
  service: z.string().nullable().optional(),
  field: SecretCatalogField,
  label: z.string().nullable().optional(),
  policy: SecretPolicy,
  destinations: z.array(z.string()),
  purpose: z.string().nullable().optional(),
  groupID: z.string().nullable().optional()
}).strict();
export type SecretCatalogMatch = z.infer<typeof SecretCatalogMatch>;

export const SecretCatalogSearchResult = z.object({
  status: z.enum(["FOUND", "NOT_FOUND", "INVALID_QUERY", "CATALOG_UNAVAILABLE"]),
  matches: z.array(SecretCatalogMatch)
}).strict();
export type SecretCatalogSearchResult = z.infer<typeof SecretCatalogSearchResult>;

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
