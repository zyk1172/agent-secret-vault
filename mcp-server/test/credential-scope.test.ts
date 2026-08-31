import { describe, expect, it } from "vitest";

import {
  classifyCredentialSelection,
  credentialSourcePriority
} from "../src/credential-scope.js";
import {
  createVaultToolDefinitions,
  type VaultIpcClient
} from "../src/server.js";

class EmptyClient implements VaultIpcClient {
  async request() {
    return { type: "failure", code: "NOT_USED" } as const;
  }
}

describe("credential scope selection", () => {
  it("honors current user plaintext without SVLT lookup or substitution", () => {
    const decision = classifyCredentialSelection({ selection: "userPlaintext" });

    expect(decision).toMatchObject({
      scope: "USER_EXPLICIT_PLAINTEXT",
      source: "USER_CURRENT_REQUEST",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false
    });
    expect(decision.explicitPlaintextOverride).toEqual({
      kind: "USER_SUPPLIED_FOR_CURRENT_OPERATION",
      scope: "USER_EXPLICIT_PLAINTEXT",
      source: "USER_CURRENT_REQUEST"
    });
  });

  it("lets current user plaintext replace a previous SVLT selection", () => {
    const previous = classifyCredentialSelection({ selection: "svlt" });
    const current = classifyCredentialSelection({ selection: "userPlaintext" });

    expect(previous.scope).toBe("SVLT_MANAGED_OPERATION");
    expect(current).toMatchObject({
      scope: "USER_EXPLICIT_PLAINTEXT",
      source: "USER_CURRENT_REQUEST",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false
    });
  });

  it("enters SVLT only when the current operation selects SVLT", () => {
    const decision = classifyCredentialSelection({ selection: "svlt" });

    expect(decision).toMatchObject({
      scope: "SVLT_MANAGED_OPERATION",
      source: "EXPLICIT_SVLT_REFERENCE",
      shouldInvokeSVLT: true,
      shouldSearchSVLT: true
    });
    expect(decision.explicitPlaintextOverride).toBeUndefined();
  });

  it("lets current external providers replace a previous SVLT selection", () => {
    const previous = classifyCredentialSelection({ selection: "svlt" });
    const decision = classifyCredentialSelection({ selection: "externalProvider" });

    expect(previous.scope).toBe("SVLT_MANAGED_OPERATION");
    expect(decision).toMatchObject({
      scope: "EXTERNAL_PROVIDER_OPERATION",
      source: "EXPLICIT_EXTERNAL_PROVIDER",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false
    });
  });

  it("does not activate from credential words alone", () => {
    const decision = classifyCredentialSelection({ selection: "automatic" });

    expect(decision.scope).toBe("UNMANAGED_CREDENTIAL");
    expect(decision.shouldInvokeSVLT).toBe(false);
    expect(decision.shouldSearchSVLT).toBe(true);
  });

  it("supports an explicit no-SVLT operation without carrying plaintext", () => {
    const decision = classifyCredentialSelection({ selection: "userSelectedNoSVLT" });

    expect(decision).toMatchObject({
      scope: "USER_EXPLICIT_PLAINTEXT",
      source: "USER_CURRENT_REQUEST",
      shouldInvokeSVLT: false,
      shouldSearchSVLT: false,
      explicitPlaintextOverride: {
        kind: "EXPLICITLY_SELECTED_NO_SVLT",
        scope: "USER_EXPLICIT_PLAINTEXT",
        source: "USER_CURRENT_REQUEST"
      }
    });
  });

  it("publishes the source priority without any value comparison", () => {
    expect(credentialSourcePriority).toEqual([
      "USER_CURRENT_REQUEST",
      "EXPLICIT_EXTERNAL_PROVIDER",
      "EXPLICIT_SVLT_REFERENCE",
      "AUTOMATIC_DISCOVERY"
    ]);
  });
});

describe("agent policy contract", () => {
  it("exposes explicit scope and derived-plaintext boundaries", async () => {
    const tool = createVaultToolDefinitions(new EmptyClient()).find(
      (candidate) => candidate.name === "agent_secret_usage_policy"
    );
    expect(tool).toBeDefined();

    const result = await tool!.handler({});
    const policy = result.structuredContent as Record<string, unknown>;
    expect(policy.scopeRule).toMatchObject({
      managed: expect.stringContaining("SVLT_MANAGED_OPERATION"),
      explicitPlaintext: expect.stringContaining("USER_EXPLICIT_PLAINTEXT"),
      externalProvider: expect.stringContaining("EXTERNAL_PROVIDER_OPERATION")
    });
    expect(policy.userOverrideRule).toEqual(expect.stringContaining("Do not force import"));
    expect((policy.safeWorkflow as string[]).join(" ")).toContain(
      "per operation"
    );
    expect((policy.safeWorkflow as string[]).join(" ")).toContain(
      "never inherited as sticky authorization"
    );
    const workflow = (policy.safeWorkflow as string[]).join(" ");
    expect(workflow).toContain("display/audit metadata only");
    expect(workflow).toContain("single-line or multi-line scripts");
    expect(workflow).not.toContain("Never use shell chaining");
    expect(workflow).not.toContain("permanently denied");
    expect(policy.outOfScopeRule).toEqual(expect.arrayContaining([
      expect.stringContaining("device MCP"),
      expect.stringContaining("Do not compare")
    ]));
    expect((policy.forbidden as string[]).join(" ")).toContain(
      "Do not expose plaintext obtained by decrypting an SVLT-managed secret outside the approved SVLT operation."
    );
    expect((policy.forbidden as string[]).join(" ")).not.toContain("Do not use raw credentials");
  });
});
