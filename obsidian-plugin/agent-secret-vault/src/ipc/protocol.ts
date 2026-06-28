import { z } from "zod";

export const SecretReference = z.string().regex(/^secret:\/\/[0-9A-HJKMNP-TV-Z]{26}$/);
export const SecretPolicy = z.enum(["credential", "externalSend", "localOnly"]);
export const CapabilityToken = z.string().min(1);

export const RevealContext = z.object({
  reason: z.string().min(1),
  template: z.string().min(1),
  ranges: z.array(z.object({
    index: z.number().int().nonnegative(),
    placeholder: z.string().min(1)
  }).strict())
}).strict();

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("workbenchStatus") }).strict(),
  z.object({
    type: z.literal("encryptText"),
    plaintext: z.string().min(1),
    label: z.string().nullable(),
    policy: SecretPolicy
  }).strict(),
  z.object({
    type: z.literal("revealReferences"),
    references: z.array(SecretReference).min(1),
    context: RevealContext
  }).strict(),
  z.object({
    type: z.literal("scanOrphans"),
    markdownReferences: z.array(SecretReference)
  }).strict()
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

export const OrphanScanResult = z.object({
  missingRecords: z.array(SecretReference),
  unreferencedRecords: z.array(SecretReference)
}).strict();

export const IpcResponse = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("workbenchStatus"),
    status: WorkbenchStatus
  }).strict(),
  z.object({ type: z.literal("created"), reference: SecretReference }).strict(),
  z.object({ type: z.literal("revealSessionOpened"), sessionID: z.string().min(1) }).strict(),
  z.object({
    type: z.literal("orphanScan"),
    result: OrphanScanResult
  }).strict(),
  z.object({ type: z.literal("failure"), code: z.string().min(1) }).strict()
]);

export type IpcRequest = z.infer<typeof IpcRequest>;
export type IpcResponse = z.infer<typeof IpcResponse>;
export type AuthenticatedIpcRequest = z.infer<typeof AuthenticatedIpcRequest>;
