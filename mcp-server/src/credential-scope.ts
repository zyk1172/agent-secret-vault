import { z } from "zod";

/**
 * Scope labels are provenance metadata only. They never contain credential
 * material and must not be used to compare user text with an SVLT secret.
 */
export const CredentialScope = z.enum([
  "SVLT_MANAGED_OPERATION",
  "USER_EXPLICIT_PLAINTEXT",
  "EXTERNAL_PROVIDER_OPERATION",
  "UNMANAGED_CREDENTIAL"
]);
export type CredentialScope = z.infer<typeof CredentialScope>;

export const CredentialSource = z.enum([
  "USER_CURRENT_REQUEST",
  "EXPLICIT_EXTERNAL_PROVIDER",
  "EXPLICIT_SVLT_REFERENCE",
  "AUTOMATIC_DISCOVERY"
]);
export type CredentialSource = z.infer<typeof CredentialSource>;

export const credentialSourcePriority: readonly CredentialSource[] = [
  "USER_CURRENT_REQUEST",
  "EXPLICIT_EXTERNAL_PROVIDER",
  "EXPLICIT_SVLT_REFERENCE",
  "AUTOMATIC_DISCOVERY"
];

/**
 * The selection is a discriminated union so one operation cannot carry
 * contradictory SVLT/no-SVLT/provider booleans. A new operation constructs a
 * new value; no previous selection is consulted.
 */
export type CredentialSelectionInput =
  | { selection: "userPlaintext" }
  | { selection: "userSelectedNoSVLT" }
  | { selection: "externalProvider" }
  | { selection: "svlt" }
  | { selection: "automatic" };

export type ExplicitPlaintextOverride =
  | {
      kind: "USER_SUPPLIED_FOR_CURRENT_OPERATION";
      scope: "USER_EXPLICIT_PLAINTEXT";
      source: "USER_CURRENT_REQUEST";
    }
  | {
      kind: "EXPLICITLY_SELECTED_NO_SVLT";
      scope: "USER_EXPLICIT_PLAINTEXT";
      source: "USER_CURRENT_REQUEST";
    };

export interface CredentialSelectionDecision {
  scope: CredentialScope;
  source: CredentialSource;
  shouldInvokeSVLT: boolean;
  shouldSearchSVLT: boolean;
  explicitPlaintextOverride?: ExplicitPlaintextOverride;
}

/**
 * Classifies an already explicit user/tool choice. It intentionally does not
 * parse chat text, inspect catalog values, or infer ownership from the words
 * "password", "token", or "API key".
 */
export function classifyCredentialSelection(
  input: CredentialSelectionInput
): CredentialSelectionDecision {
  switch (input.selection) {
    case "userPlaintext":
      return userPlaintextDecision({
        kind: "USER_SUPPLIED_FOR_CURRENT_OPERATION",
        scope: "USER_EXPLICIT_PLAINTEXT",
        source: "USER_CURRENT_REQUEST"
      });
    case "userSelectedNoSVLT":
      return userPlaintextDecision({
        kind: "EXPLICITLY_SELECTED_NO_SVLT",
        scope: "USER_EXPLICIT_PLAINTEXT",
        source: "USER_CURRENT_REQUEST"
      });
    case "externalProvider":
      return {
        scope: "EXTERNAL_PROVIDER_OPERATION",
        source: "EXPLICIT_EXTERNAL_PROVIDER",
        shouldInvokeSVLT: false,
        shouldSearchSVLT: false
      };
    case "svlt":
      return {
        scope: "SVLT_MANAGED_OPERATION",
        source: "EXPLICIT_SVLT_REFERENCE",
        shouldInvokeSVLT: true,
        shouldSearchSVLT: true
      };
    case "automatic":
      return {
        scope: "UNMANAGED_CREDENTIAL",
        source: "AUTOMATIC_DISCOVERY",
        shouldInvokeSVLT: false,
        shouldSearchSVLT: true
      };
  }
}

function userPlaintextDecision(
  override: ExplicitPlaintextOverride
): CredentialSelectionDecision {
  return {
    scope: "USER_EXPLICIT_PLAINTEXT",
    source: "USER_CURRENT_REQUEST",
    shouldInvokeSVLT: false,
    shouldSearchSVLT: false,
    explicitPlaintextOverride: override
  };
}
