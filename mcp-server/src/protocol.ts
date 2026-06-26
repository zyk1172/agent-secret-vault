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

export const RiskClass = z.union([z.literal(0), z.literal(1), z.literal(2)]);
export type RiskClass = z.infer<typeof RiskClass>;

export const ExecutionRequest = z
  .object({
    templateID: z.string().min(1),
    executable: z.string().min(1),
    values: z.record(z.string(), z.string()),
    secrets: z.record(z.string(), SecretReference),
    destinationHost: z.string().nullable().optional(),
    destinationPath: z.string().nullable().optional(),
    requestedRisk: RiskClass
  })
  .strict();
export type ExecutionRequest = z.infer<typeof ExecutionRequest>;

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("status") }).strict(),
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
      type: z.literal("execute"),
      request: ExecutionRequest
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

export const OutputQuarantineReason = z.enum([
  "binaryOutput",
  "invalidUTF8",
  "emptySecretMaterial",
  "encodedSecretVariantDetected"
]);
export type OutputQuarantineReason = z.infer<typeof OutputQuarantineReason>;

export const SanitizedExecutionResult = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("completed"),
      exitCode: z.number().int(),
      stdout: z.string(),
      stderr: z.string()
    })
    .strict(),
  z
    .object({
      type: z.literal("quarantined"),
      reason: OutputQuarantineReason
    })
    .strict()
]);
export type SanitizedExecutionResult = z.infer<typeof SanitizedExecutionResult>;

export const IpcResponse = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("status"),
      locked: z.boolean()
    })
    .strict(),
  z.object({ type: z.literal("displayedToUser") }).strict(),
  z
    .object({
      type: z.literal("created"),
      reference: SecretReference
    })
    .strict(),
  z
    .object({
      type: z.literal("execution"),
      result: SanitizedExecutionResult
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
