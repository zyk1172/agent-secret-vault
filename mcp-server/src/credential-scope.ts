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

export interface CredentialSelectionInput {
  userSuppliedPlaintext: boolean;
  userExplicitlyRequestedPlaintext: boolean;
  userExplicitlySelectedNoSVLT?: boolean;
  userExplicitlySelectedSVLT?: boolean;
  explicitlySelectedExternalProvider?: boolean;
}

export interface ExplicitPlaintextOverride {
  scope: "USER_EXPLICIT_PLAINTEXT";
  source: "USER_CURRENT_REQUEST";
  userSuppliedForCurrentOperation: boolean;
  explicitlyRequestedForCurrentOperation: boolean;
  explicitlySelectedNoSVLT: boolean;
}

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
  const noSVLT = input.userExplicitlySelectedNoSVLT === true;
  const selectedSVLT = input.userExplicitlySelectedSVLT === true;
  const selectedExternal = input.explicitlySelectedExternalProvider === true;
  const explicitPlaintext = input.userExplicitlyRequestedPlaintext === true &&
    (input.userSuppliedPlaintext || noSVLT);

  if (selectedSVLT) {
    return {
      scope: "SVLT_MANAGED_OPERATION",
      source: "EXPLICIT_SVLT_REFERENCE",
      shouldInvokeSVLT: true,
      shouldSearchSVLT: true
    };
  }

  if (explicitPlaintext) {
    return {
      scope: "USER_EXPLICIT_PLAINTEXT",
      source: "USER_CURRENT_REQUEST",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false,
      explicitPlaintextOverride: {
        scope: "USER_EXPLICIT_PLAINTEXT",
        source: "USER_CURRENT_REQUEST",
        userSuppliedForCurrentOperation: input.userSuppliedPlaintext,
        explicitlyRequestedForCurrentOperation: true,
        explicitlySelectedNoSVLT: noSVLT
      }
    };
  }

  if (selectedExternal) {
    return {
      scope: "EXTERNAL_PROVIDER_OPERATION",
      source: "EXPLICIT_EXTERNAL_PROVIDER",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false
    };
  }

  return {
    scope: "UNMANAGED_CREDENTIAL",
    source: "AUTOMATIC_DISCOVERY",
    shouldInvokeSVLT: false,
    shouldSearchSVLT: true
  };
}

