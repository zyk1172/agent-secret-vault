import { z } from "zod";

export const CapabilityToken = z.string().min(1);
export const CatalogValidationStatus = z.enum([
  "FOUND",
  "NOT_FOUND",
  "INVALID_QUERY",
  "CATALOG_UNAVAILABLE",
  "LEGACY_CATALOG_UNSUPPORTED",
  "INTEGRITY_MISSING",
  "EXTERNAL_CATALOG_MODIFICATION",
  "PENDING_EXTERNAL_CHANGE",
  "CATALOG_INVALID"
]);

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("workbenchStatus") }).strict(),
  z.object({ type: z.literal("catalogValidate") }).strict()
]);

export const AuthenticatedIpcRequest = z.object({
  capabilityToken: CapabilityToken,
  request: IpcRequest
}).strict();

export const WorkbenchStatus = z.object({
  locked: z.boolean(),
  ipcAvailable: z.boolean(),
  activeKnowledgeBaseRoot: z.string().nullable(),
  pluginConnected: z.boolean()
}).strict();

export const CatalogDiagnosticSeverity = z.enum(["error", "warning"]);
export const CatalogDiagnosticScope = z.enum(["document", "policy", "index", "entry", "field", "unmanaged"]);
export const CatalogValidationDiagnostic = z.object({
  id: z.string().min(1),
  severity: CatalogDiagnosticSeverity,
  code: z.string().min(1),
  line: z.number().int().min(1),
  column: z.number().int().min(1).nullable().optional(),
  endLine: z.number().int().min(1).nullable().optional(),
  endColumn: z.number().int().min(1).nullable().optional(),
  scope: CatalogDiagnosticScope,
  message: z.string().min(1),
  hint: z.string().min(1).nullable().optional()
}).strict();
export type CatalogValidationDiagnostic = z.infer<typeof CatalogValidationDiagnostic>;

export const IpcResponse = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("workbenchStatus"),
    status: WorkbenchStatus
  }).strict(),
  z.object({
    type: z.literal("catalogValidation"),
    catalogStatus: CatalogValidationStatus,
    revision: z.number().int().nonnegative().nullable().optional(),
    rawSHA256: z.string().min(1).nullable().optional(),
    diagnostics: z.array(CatalogValidationDiagnostic).default([])
  }).strict(),
  z.object({ type: z.literal("failure"), code: z.string().min(1) }).strict()
]);

export type IpcRequest = z.infer<typeof IpcRequest>;
export type IpcResponse = z.infer<typeof IpcResponse>;
export type AuthenticatedIpcRequest = z.infer<typeof AuthenticatedIpcRequest>;
